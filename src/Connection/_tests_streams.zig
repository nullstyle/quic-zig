// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const c = boringssl.raw;
const Connection = state.Connection;
const StreamType = state.StreamType;
const Error = state.Error;
const RecvStream = state.RecvStream;
const SendStream = state.SendStream;
const Stream = state.Stream;
const StreamIdSpace = @import("../conn/StreamIdSpace.zig");
const StreamSendStats = state.StreamSendStats;
const StreamRecvState = state.StreamRecvState;
const StreamPriority = state.StreamPriority;
const application_ack_eliciting_threshold = state.application_ack_eliciting_threshold;
const default_connection_receive_window = state.default_connection_receive_window;
const default_stream_receive_window = state.default_stream_receive_window;
const frame_mod = state.frame_mod;
const long_packet_mod = state.long_packet_mod;
const max_concurrent_streams_per_kind = state.max_concurrent_streams_per_kind;
const send_stream_mod = state.send_stream_mod;
const transport_error_stream_limit = state.transport_error_stream_limit;
const util = @import("_test_util.zig");
const installTestEarlyDataReadSecret = util.installTestEarlyDataReadSecret;
const testEarlyDataPacketKeys = util.testEarlyDataPacketKeys;

test "max_buffered_send is the send buffer of every stream the connection opens" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try std.testing.expectEqual(state.default_max_buffered_send, conn.max_buffered_send);

    conn.max_buffered_send = 8;
    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 8), conn.stream(0).?.send.max_buffered);
    // The buffer is the sender's window: a write past it takes less.
    try std.testing.expectEqual(@as(usize, 8), try conn.streamWrite(0, "0123456789"));
    try std.testing.expectEqual(@as(usize, 0), try conn.streamWrite(0, "more"));
    // A stream opened before a change keeps its own.
    conn.max_buffered_send = 64;
    _ = try conn.openBidi(4);
    try std.testing.expectEqual(@as(usize, 8), conn.stream(0).?.send.max_buffered);
    try std.testing.expectEqual(@as(usize, 64), conn.stream(4).?.send.max_buffered);
}

test "the send buffer follows the peer's credit, up to its cap, unless told not to" {
    const allocator = std.testing.allocator;
    const big = try allocator.alloc(u8, 2 * 1024 * 1024);
    defer allocator.free(big);
    @memset(big, 'x');
    {
        var ctx = try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        _ = try conn.openBidi(0);
        // The peer accepts 4 MiB on the stream: a 2 MiB write fits,
        // where the 1 MiB default alone took half.
        try conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 4 * 1024 * 1024 });
        try std.testing.expectEqual(big.len, try conn.streamWrite(0, big));
    }
    {
        var ctx = try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        conn.max_buffered_send_cap = 1536 * 1024;
        _ = try conn.openBidi(0);
        try conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 4 * 1024 * 1024 });
        try std.testing.expectEqual(@as(usize, 1536 * 1024), try conn.streamWrite(0, big));
    }
    {
        var ctx = try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        conn.send_buffer_follows_credit = false;
        _ = try conn.openBidi(0);
        try conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 4 * 1024 * 1024 });
        try std.testing.expectEqual(@as(usize, 1024 * 1024), try conn.streamWrite(0, big));
    }
}

test "a write past the connection's memory budget returns short, it is not a fault" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.max_connection_memory = 1024;
    _ = try conn.openBidi(0);
    var data: [2048]u8 = undefined;
    @memset(&data, 'x');
    // The budget leaves 1024, half of it the receive side's share
    // (since 0.38.0): the write takes 512.
    try std.testing.expectEqual(@as(usize, 512), try conn.streamWrite(0, &data));
    // Nothing left for writes: the write takes nothing, the stream
    // stays open.
    try std.testing.expectEqual(@as(usize, 0), try conn.streamWrite(0, &data));
    try std.testing.expectEqual(@as(u64, 512), conn.bytes_resident);
}

/// A connection with a small memory budget and explicit windows: the
/// connection window is the receive side's share (half the budget),
/// the stream window is wide, one bidi stream open.
fn budgetConn(allocator: std.mem.Allocator, ctx: boringssl.tls.Context, budget: u64) !*Connection {
    const conn = try Connection.createClient(allocator, ctx, "x");
    errdefer conn.destroy();
    conn.max_connection_memory = budget;
    try conn.setTransportParams(.{
        .initial_max_data = budget / 2,
        .initial_max_stream_data_bidi_local = 1024 * 1024,
        .initial_max_stream_data_bidi_remote = 1024 * 1024,
        .initial_max_streams_bidi = 4,
    });
    _ = try conn.openBidi(0);
    return conn;
}

test "a write leaves the receive side its share of the memory budget: the peer's in-window bytes still land" {
    // capnp-zig's shape (2026-10-08): a 256 KiB budget, a 1 MiB reply,
    // the client's small frames every millisecond. Through v0.37.x the
    // write took the whole budget and the first peer byte closed the
    // connection with "excessive resource use", a fault the peer did
    // not cause.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try budgetConn(allocator, ctx, 256 * 1024);
    defer conn.destroy();
    const data = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 'x');
    // The writer's share: the budget less the receive side's.
    try std.testing.expectEqual(@as(usize, 128 * 1024), try conn.streamWrite(0, data));
    try std.testing.expectEqual(@as(u64, 128 * 1024), conn.bytes_resident);
    // The peer's bytes, well inside the window it was given: they land.
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = "abc", .has_length = true, .fin = false });
    try std.testing.expectEqual(Connection.CloseState.open, conn.closeState());
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try conn.streamRead(0, &buf));
    try std.testing.expectEqualStrings("abc", buf[0..3]);
    try std.testing.expectEqual(conn.residentBytesSum(), conn.bytes_resident);
}

test "a slow reader's buffers leave the writer nothing: a short write, not a fault; a read gives it back" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try budgetConn(allocator, ctx, 256 * 1024);
    defer conn.destroy();
    // The peer fills most of its window; nobody reads yet.
    const inbound = try allocator.alloc(u8, 120 * 1024);
    defer allocator.free(inbound);
    @memset(inbound, 'p');
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = inbound, .has_length = true, .fin = false });
    try std.testing.expectEqual(Connection.CloseState.open, conn.closeState());
    try std.testing.expectEqual(@as(u64, 120 * 1024), conn.bytes_resident);
    // The writer's share is 128 KiB of resident bytes in all: 8 KiB left.
    const data = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 'x');
    try std.testing.expectEqual(@as(usize, 8 * 1024), try conn.streamWrite(0, data));
    try std.testing.expectEqual(@as(usize, 0), try conn.streamWrite(0, data));
    try std.testing.expectEqual(Connection.CloseState.open, conn.closeState());
    // The application reads everything: the buffer drains and gives
    // its charge back; the writer has its share again.
    var buf: [64 * 1024]u8 = undefined;
    var read: usize = 0;
    while (read < inbound.len) read += try conn.streamRead(0, &buf);
    try std.testing.expectEqual(@as(u64, 8 * 1024), conn.bytes_resident);
    try std.testing.expectEqual(@as(usize, 120 * 1024), try conn.streamWrite(0, data));
    try std.testing.expectEqual(conn.residentBytesSum(), conn.bytes_resident);
}

test "under pressure the receive buffers compact their consumed prefix before a peer's in-window bytes are refused" {
    // The receive buffer charges the budget for its consumed prefix
    // until the prefix reaches half the buffer, while the connection
    // window slides on once half of it was read in all: with two
    // streams, one read short of its half and one drained, the peer's
    // credit grows and the first stream's prefix stays charged. With
    // the writer at its share, that slack is what stands between the
    // peer's next in-window frame and "excessive resource use". It is
    // given back first.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try budgetConn(allocator, ctx, 256 * 1024);
    defer conn.destroy();
    _ = try conn.openBidi(4);
    const data = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 'x');
    // The writer takes its whole share.
    try std.testing.expectEqual(@as(usize, 128 * 1024), try conn.streamWrite(0, data));
    // The peer fills its window: 100 KiB on stream 0, 28 KiB on stream 4.
    const a = try allocator.alloc(u8, 100 * 1024);
    defer allocator.free(a);
    @memset(a, 'p');
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = a, .has_length = true, .fin = false });
    try conn.handleStream(.application, .{ .stream_id = 4, .offset = 0, .data = a[0 .. 28 * 1024], .has_length = true, .fin = false });
    try std.testing.expectEqual(Connection.CloseState.open, conn.closeState());
    try std.testing.expectEqual(@as(u64, 256 * 1024), conn.bytes_resident);
    // The application reads 49 KiB of stream 0 (short of its half: the
    // prefix stays, charged) and all of stream 4 (drained, its charge
    // given back). 77 KiB read in all: the connection window slides,
    // the peer may send 77 KiB more.
    var buf: [49 * 1024]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 49 * 1024), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(usize, 28 * 1024), try conn.streamRead(4, &buf));
    try std.testing.expectEqual(@as(u64, 228 * 1024), conn.bytes_resident);
    try std.testing.expect(conn.local_max_data >= 200 * 1024);
    // 69 KiB more on stream 0, inside the window: 41 KiB over the budget
    // as charged, 8 KiB under it once the prefix is compacted. It lands.
    const b = try allocator.alloc(u8, 69 * 1024);
    defer allocator.free(b);
    @memset(b, 'q');
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 100 * 1024, .data = b, .has_length = true, .fin = false });
    try std.testing.expectEqual(Connection.CloseState.open, conn.closeState());
    try std.testing.expectEqual(@as(u64, (128 + 51 + 69) * 1024), conn.bytes_resident);
    const rs = conn.streamRecvState(0).?;
    try std.testing.expectEqual(@as(u64, 49 * 1024), rs.read_offset);
    // Everything the peer sent is still readable, in order.
    var tail: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 8), try conn.streamRead(0, &tail));
    try std.testing.expectEqualStrings("pppppppp", &tail);
    try std.testing.expectEqual(conn.residentBytesSum(), conn.bytes_resident);
}

test "streamWriteCapacity says what the next streamWrite takes: the buffer's room, the writer's share, the smaller" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    // The writer's share bounds it: 128 KiB of a 256 KiB budget.
    const conn = try budgetConn(allocator, ctx, 256 * 1024);
    defer conn.destroy();
    const data = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 'x');
    try std.testing.expectEqual(@as(usize, 128 * 1024), try conn.streamWriteCapacity(0));
    try std.testing.expectEqual(@as(usize, 100 * 1024), try conn.streamWrite(0, data[0 .. 100 * 1024]));
    try std.testing.expectEqual(@as(usize, 28 * 1024), try conn.streamWriteCapacity(0));
    try std.testing.expectEqual(@as(usize, 28 * 1024), try conn.streamWrite(0, data));
    try std.testing.expectEqual(@as(usize, 0), try conn.streamWriteCapacity(0));
    // A finished half takes nothing more.
    try conn.streamFinish(0);
    try std.testing.expectEqual(@as(usize, 0), try conn.streamWriteCapacity(0));
    // A receive-only stream has no send half here; a reaped one is gone.
    try std.testing.expectError(Error.StreamNotWritable, conn.streamWriteCapacity(3));
    try std.testing.expectError(Error.StreamNotFound, conn.streamWriteCapacity(8));
    try std.testing.expectEqual(conn.residentBytesSum(), conn.bytes_resident);
}

test "streamWriteCapacity: the send buffer's room bounds it when the budget does not" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    _ = try conn.openBidi(0);
    const cap = try conn.streamWriteCapacity(0);
    try std.testing.expect(cap > 0);
    const data = try allocator.alloc(u8, cap + 4096);
    defer allocator.free(data);
    @memset(data, 'x');
    // The write takes exactly the capacity.
    try std.testing.expectEqual(cap, try conn.streamWrite(0, data));
    try std.testing.expectEqual(@as(usize, 0), try conn.streamWriteCapacity(0));
    try std.testing.expectEqual(conn.residentBytesSum(), conn.bytes_resident);
}

test "streamReset publicly aborts the send half" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 5), try conn.streamWrite(0, "hello"));
    try conn.streamReset(0, 0xdead);

    const s = conn.stream(0).?;
    try std.testing.expectEqual(send_stream_mod.State.reset_sent, s.send.state);
    try std.testing.expect(s.send.reset != null);
    try std.testing.expectEqual(@as(u64, 0xdead), s.send.reset.?.error_code);
    try std.testing.expectEqual(@as(u64, 5), s.send.reset.?.final_size);
    try std.testing.expectError(send_stream_mod.Error.StreamClosed, conn.streamWrite(0, "late"));
    try std.testing.expectError(Error.StreamNotFound, conn.streamReset(4, 0));
}

test "streamSendStats snapshots the send half; null for missing streams" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Unopened stream → null (same signal a reaped stream gives).
    try std.testing.expectEqual(@as(?StreamSendStats, null), conn.streamSendStats(0));

    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 11), try conn.streamWrite(0, "hello world"));

    const stats = conn.streamSendStats(0) orelse return error.MissingStats;
    try std.testing.expectEqual(@as(u64, 11), stats.written);
    try std.testing.expectEqual(@as(u64, 0), stats.acked); // nothing acked yet
    try std.testing.expectEqual(@as(u64, 11), stats.buffered); // written - acked
    try std.testing.expect(stats.has_pending); // buffered, unsent

    // A never-opened higher id is still null, not a resurrected zero-stat stream.
    try std.testing.expectEqual(@as(?StreamSendStats, null), conn.streamSendStats(400));
}

test "send scheduler orders ready streams by RFC 9218 priority (urgency then id)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 4096,
        .initial_max_streams_bidi = max_concurrent_streams_per_kind,
    });

    // Three client bidi streams (ids 0, 4, 8), each with a pending send byte.
    _ = try conn.openBidi(0);
    _ = try conn.openBidi(4);
    _ = try conn.openBidi(8);
    _ = try conn.streamWrite(0, "a");
    _ = try conn.streamWrite(4, "b");
    _ = try conn.streamWrite(8, "c");

    var buf: [8]*Stream = undefined;

    // Default: every stream is urgency 3, so the scheduler order is stream-id
    // ascending (deterministic, independent of hash-map iteration order).
    {
        const ready = conn.collectSendableStreamsByPriority(&buf);
        try std.testing.expectEqual(@as(usize, 3), ready.len);
        try std.testing.expectEqual(@as(u64, 0), ready[0].id);
        try std.testing.expectEqual(@as(u64, 4), ready[1].id);
        try std.testing.expectEqual(@as(u64, 8), ready[2].id);
    }

    // Invert by urgency: stream 8 most urgent, stream 0 least. Urgency wins
    // over stream id, so the order becomes 8, 4, 0.
    try conn.streamSetPriority(8, .{ .urgency = 0 });
    try conn.streamSetPriority(4, .{ .urgency = 3 });
    try conn.streamSetPriority(0, .{ .urgency = 7 });
    {
        const ready = conn.collectSendableStreamsByPriority(&buf);
        try std.testing.expectEqual(@as(usize, 3), ready.len);
        try std.testing.expectEqual(@as(u64, 8), ready[0].id);
        try std.testing.expectEqual(@as(u64, 4), ready[1].id);
        try std.testing.expectEqual(@as(u64, 0), ready[2].id);
    }

    // streamPriority reflects the set value; unknown/reaped id → null, and
    // setting priority on an absent stream is a typed error.
    try std.testing.expectEqual(@as(u3, 0), conn.streamPriority(8).?.urgency);
    try std.testing.expectEqual(@as(?StreamPriority, null), conn.streamPriority(400));
    try std.testing.expectError(error.StreamNotFound, conn.streamSetPriority(400, .{}));
}

test "send scheduler: non-incremental leads its band, incremental streams round-robin" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 4096,
        .initial_max_streams_bidi = max_concurrent_streams_per_kind,
    });

    // Same urgency: three incremental streams (0, 4, 8) plus one
    // non-incremental (12), each with pending send data.
    for ([_]u64{ 0, 4, 8, 12 }) |id| {
        _ = try conn.openBidi(id);
        _ = try conn.streamWrite(id, "x");
    }
    try conn.streamSetPriority(0, .{ .urgency = 3, .incremental = true });
    try conn.streamSetPriority(4, .{ .urgency = 3, .incremental = true });
    try conn.streamSetPriority(8, .{ .urgency = 3, .incremental = true });
    try conn.streamSetPriority(12, .{ .urgency = 3, .incremental = false });

    var buf: [8]*Stream = undefined;
    var incremental_leads: [3]u64 = undefined;
    for (&incremental_leads) |*lead| {
        const ready = conn.collectSendableStreamsByPriority(&buf);
        try std.testing.expectEqual(@as(usize, 4), ready.len);
        // The non-incremental stream always leads the band (head-of-line).
        try std.testing.expectEqual(@as(u64, 12), ready[0].id);
        try std.testing.expect(!ready[0].priority.incremental);
        // The incremental streams follow; which one is first rotates.
        try std.testing.expect(ready[1].priority.incremental);
        lead.* = ready[1].id;
    }
    // Over three packets each incremental stream leads once — a fair rotation,
    // not the same stream monopolizing the band.
    try std.testing.expect(incremental_leads[0] != incremental_leads[1]);
    try std.testing.expect(incremental_leads[1] != incremental_leads[2]);
    try std.testing.expect(incremental_leads[0] != incremental_leads[2]);
}

test "streamReadFin reports FIN inline with the last read; streamRecvState tracks it" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_local = 64,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_streams_bidi = max_concurrent_streams_per_kind,
    });

    // Unknown stream → null recv-state (the same "gone" signal a reaped
    // stream gives, so a downstream needn't hold a *Stream across a reap).
    try std.testing.expectEqual(@as(?StreamRecvState, null), conn.streamRecvState(0));

    _ = try conn.openBidi(0);

    // Peer sends 3 bytes, no FIN yet.
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = "abc", .has_length = true, .fin = false });
    {
        const rs = conn.streamRecvState(0).?;
        try std.testing.expect(!rs.fin_seen and !rs.reset_seen and !rs.terminal);
    }
    var buf: [8]u8 = undefined;
    {
        const r = try conn.streamReadFin(0, &buf); // drains 3 bytes, FIN not seen yet
        try std.testing.expectEqual(@as(usize, 3), r.n);
        try std.testing.expect(!r.fin);
    }

    // Peer sends 2 more bytes WITH the FIN bit.
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 3, .data = "de", .has_length = true, .fin = true });
    {
        const r = try conn.streamReadFin(0, &buf); // the last read carries FIN inline
        try std.testing.expectEqual(@as(usize, 2), r.n);
        try std.testing.expect(r.fin);
    }
    {
        const rs = conn.streamRecvState(0).?;
        try std.testing.expect(rs.fin_seen and !rs.reset_seen and rs.terminal);
    }
}

test "streamRecvState distinguishes a peer RESET from a clean FIN" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_local = 64,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_streams_bidi = max_concurrent_streams_per_kind,
    });
    _ = try conn.openBidi(0);

    try conn.handleResetStream(.{ .stream_id = 0, .application_error_code = 7, .final_size = 0 });
    const rs = conn.streamRecvState(0).?;
    // RESET is terminal but is NOT a clean FIN — the distinction
    // `recvFullyTerminated` collapses.
    try std.testing.expect(!rs.fin_seen and rs.reset_seen and rs.terminal);
}

test "peer-created streams respect advertised stream count" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = 1,
    });

    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "a",
        .has_length = true,
    });
    try std.testing.expectEqual(@as(u64, 1), conn.peer_bidi_ids.opened);
    try std.testing.expect(conn.lifecycle.pending_close == null);

    try conn.handleStream(.application, .{
        .stream_id = 4,
        .offset = 0,
        .data = "b",
        .has_length = true,
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_stream_limit, conn.lifecycle.pending_close.?.error_code);
}

test "StreamType encodes RFC 9000 §2.1 low-two-bit stream classes" {
    try std.testing.expectEqual(StreamType.client_bidi, StreamType.fromId(0));
    try std.testing.expectEqual(StreamType.server_bidi, StreamType.fromId(1));
    try std.testing.expectEqual(StreamType.client_uni, StreamType.fromId(2));
    try std.testing.expectEqual(StreamType.server_uni, StreamType.fromId(3));
    // High-index ids classify by their low two bits only.
    try std.testing.expectEqual(StreamType.client_bidi, StreamType.fromId(400));
    try std.testing.expectEqual(StreamType.server_uni, StreamType.fromId(403));

    // id composition round-trips through fromId, and the index survives.
    inline for (.{
        StreamType.client_bidi,
        StreamType.server_bidi,
        StreamType.client_uni,
        StreamType.server_uni,
    }) |t| {
        const id = t.streamId(7);
        try std.testing.expectEqual(t, StreamType.fromId(id));
        try std.testing.expectEqual(@as(u64, 7), Connection.streamIndex(id));
    }

    try std.testing.expect(StreamType.client_bidi.isBidi() and !StreamType.client_bidi.isUni());
    try std.testing.expect(StreamType.server_uni.isUni() and StreamType.server_uni.initiatedByServer());
    try std.testing.expect(StreamType.client_uni.initiatedByClient());
}

test "openNextBidi surfaces StreamLimitExceeded without consuming the id" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.local_bidi_ids.limit = 0;

    try std.testing.expectError(Error.StreamLimitExceeded, conn.openNextBidi());
    // Not consumed: after the peer raises the limit the next open reuses index 0.
    conn.local_bidi_ids.limit = 1;
    try std.testing.expectEqual(@as(u64, 0), (try conn.openNextBidi()).id);
}

test "server handles accepted 0-RTT STREAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    installTestEarlyDataReadSecret(conn);
    try conn.setTransportParams(.{
        .initial_max_data = 1024,
        .initial_max_stream_data_bidi_remote = 1024,
        .initial_max_streams_bidi = 1,
    });
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "hello",
        .has_offset = false,
        .has_length = true,
        .fin = false,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);
    // The first ack-eliciting packet of the space is a lone one: the
    // quiet rule acknowledges it at once, whatever the threshold
    // (`Connection.ack_quick_gap_us`, since v0.35.0).
    try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.pending_ack);
    try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.delayed_ack_armed);

    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try conn.streamRead(0, &buf));
    try std.testing.expectEqualSlices(u8, "hello", buf[0..5]);
    try std.testing.expectEqual(true, conn.streamArrivedInEarlyData(0).?);
}

test "gc candidates preserve map retirement order after duplicate notices and map growth" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();
    try conn.setTransportParams(.{ .initial_max_data = 4096, .initial_max_stream_data_uni = 64, .initial_max_streams_uni = 1024 });
    // Terminal notices arrive in reverse order, before the map grows.
    var index: u64 = 80;
    while (index > 0) {
        index -= 1;
        const frame: @import("../frame/types.zig").Stream = .{ .stream_id = index * 4 + 2, .data = "", .has_length = true, .fin = true };
        try conn.handleStream(.application, frame);
        try conn.handleStream(.application, frame);
    }
    try std.testing.expectEqual(@as(usize, 80), conn.streams_gc_candidate_count);
    try std.testing.expect(!conn.streams_gc_full_scan);
    index = 80;
    while (index < 600) : (index += 1) try conn.handleStream(.application, .{ .stream_id = index * 4 + 2, .data = "", .has_length = true });
    var expected: [80]u64 = undefined;
    var n: usize = 0;
    var it = conn.streams.iterator();
    while (it.next()) |entry| if (entry.value_ptr.*.recvFullyTerminated()) {
        expected[n] = entry.key_ptr.*;
        n += 1;
    };
    try std.testing.expectEqual(expected.len, n);
    try conn.tick(1000);
    try std.testing.expectEqual(@as(usize, 0), conn.streams_gc_candidate_count);
    try std.testing.expectEqual(@as(usize, 520), conn.streamCount());
    const ring = conn.recv_end_ring.?;
    try std.testing.expectEqual(expected.len, ring.len);
    for (expected, 0..) |id, i| {
        try std.testing.expectEqual(id, ring.records[i].id);
        try std.testing.expect(conn.streamRecvWasReaped(id));
        try std.testing.expect(conn.streamRecvEnd(id).?.isClean());
        // A late frame cannot resurrect the retired stream.
        try conn.handleStream(.application, .{ .stream_id = id, .data = "", .has_length = true, .fin = true });
    }
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
}

test "gc candidates overflow keeps the exact batch and next tick end evidence" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();
    try conn.setTransportParams(.{ .initial_max_streams_uni = 400 });
    for (0..300) |i| try conn.handleResetStream(.{ .stream_id = i * 4 + 2, .application_error_code = i, .final_size = 0 });
    try std.testing.expectEqual(state.RecvEndRing.gc_batch, conn.streams_gc_candidate_count);
    try std.testing.expect(conn.streams_gc_full_scan);
    var expected: [300]u64 = undefined;
    var it = conn.streams.iterator();
    var n: usize = 0;
    while (it.next()) |entry| {
        expected[n] = entry.key_ptr.*;
        n += 1;
    }
    const batch = state.RecvEndRing.gc_batch;
    try conn.tick(1000);
    try std.testing.expectEqual(@as(usize, 300 - batch), conn.streamCount());
    for (expected[0..batch], 0..) |id, i| try std.testing.expectEqual(id, conn.recv_end_ring.?.records[i].id);
    try conn.tick(2000);
    try std.testing.expectEqual(@as(usize, 300 - 2 * batch), conn.streamCount());
    for (expected[0 .. 2 * batch]) |id| {
        try std.testing.expect(conn.streamRecvWasReaped(id));
        try std.testing.expectEqual(@as(?u64, id / 4), conn.streamRecvEnd(id).?.reset_code);
    }
    try conn.tick(3000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gc candidates drain a stopped half before FIN gaps close without premature retirement" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();
    try conn.handleStream(.application, .{ .stream_id = 2, .data = "hello", .has_length = true });
    try conn.streamStopSending(2, 7);
    // The callback may still hold this buffer until tick.
    try std.testing.expectEqual(@as(usize, 5), (try conn.streamPeek(2)).len);
    try conn.tick(1000);
    try std.testing.expect(conn.stream(2) != null);
    try std.testing.expectEqual(@as(usize, 0), (try conn.streamPeek(2)).len);
    try std.testing.expectEqual(@as(u64, 5), conn.recv_stream_bytes_read);
    try std.testing.expectEqual(@as(u64, 0), conn.bytes_resident);
    try conn.handleStream(.application, .{ .stream_id = 2, .offset = 10, .data = "!", .has_length = true, .fin = true });
    try conn.tick(2000);
    try std.testing.expect(conn.stream(2) != null);
    try conn.handleStream(.application, .{ .stream_id = 2, .offset = 5, .data = "abcde", .has_length = true });
    try conn.tick(3000);
    try std.testing.expect(conn.streamRecvWasReaped(2));
    try std.testing.expect(conn.streamRecvEnd(2).?.stopped);
    try std.testing.expect(!conn.streamRecvEnd(2).?.isClean());
    try std.testing.expectEqual(@as(u64, 11), conn.recv_stream_bytes_read);
    try std.testing.expectEqual(@as(u64, 0), conn.bytes_resident);
}

test "gc candidates require no allocation and still retire when end evidence allocation fails" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(failing.allocator(), ctx);
    defer conn.destroy();
    try conn.setTransportParams(.{ .initial_max_streams_uni = 4 });
    try conn.handleStream(.application, .{ .stream_id = 2, .data = "", .has_length = true });
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try conn.handleStream(.application, .{ .stream_id = 2, .data = "", .has_length = true, .fin = true });
    try conn.tick(1000);
    try std.testing.expect(conn.stream(2) == null);
    try std.testing.expect(conn.streamRecvWasReaped(2));
    try std.testing.expectEqual(@as(?state.StreamRecvEnd, null), conn.streamRecvEnd(2));
    try std.testing.expectEqual(@as(u64, 0), conn.bytes_resident);
}

test "gcClosedStreams reclaims bidi streams whose send + recv halves are both terminal" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const n: u64 = 100;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const id = i << 2; // client-initiated bidi
        _ = try conn.openBidi(id);
        const s = conn.stream(id).?;
        // Force both halves to terminal without driving real packets.
        // Send: data_recvd (FIN ACKed, base_offset == final_size).
        s.send.fin_marked = true;
        s.send.fin_in_flight = true;
        s.send.fin_acked = true;
        s.send.final_size = 0;
        s.send.state = .data_recvd;
        // Recv: data_recvd (peer FIN seen, all bytes drained).
        s.recv.fin_seen = true;
        s.recv.final_size = 0;
        s.recv.state = .data_recvd;
    }
    try std.testing.expectEqual(@as(usize, n), conn.streamCount());

    // These fixtures set terminal state directly, without receive/ACK handlers.
    conn.markStreamsGc();
    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gcClosedStreams reclaims bidi streams whose send is reset_recvd and recv is reset_recvd" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    const s = conn.stream(0).?;
    // Local RESET_STREAM, peer ACKed.
    s.send.reset = .{ .error_code = 0xdead, .final_size = 0, .queued = true, .acked = true };
    s.send.state = .reset_recvd;
    // Peer RESET_STREAM observed.
    s.recv.reset = .{ .error_code = 0xbeef, .final_size = 0 };
    s.recv.final_size = 0;
    s.recv.state = .reset_recvd;

    conn.markStreamsGc();
    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gcClosedStreams keeps streams where only the send half is terminal" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    const s = conn.stream(0).?;
    // Send terminal but recv still .recv (peer hasn't FIN'd).
    s.send.fin_marked = true;
    s.send.fin_in_flight = true;
    s.send.fin_acked = true;
    s.send.final_size = 0;
    s.send.state = .data_recvd;
    // s.recv stays at default `.recv`.

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 1), conn.streamCount());
    try std.testing.expect(conn.stream(0) != null);
}

test "gcClosedStreams keeps streams where only the recv half is terminal" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    const s = conn.stream(0).?;
    // Recv terminal, but local hasn't called streamFinish yet.
    s.recv.fin_seen = true;
    s.recv.final_size = 0;
    s.recv.state = .data_recvd;
    // s.send stays at default `.ready`.

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 1), conn.streamCount());
    try std.testing.expect(conn.stream(0) != null);
}

test "gcClosedStreams reclaims local-initiated uni streams once send is terminal (recv unused)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Client-initiated uni: low bits 0b10 (id 2, 6, 10, ...).
    const id: u64 = 2;
    _ = try conn.openUni(id);
    const s = conn.stream(id).?;
    s.send.fin_marked = true;
    s.send.fin_in_flight = true;
    s.send.fin_acked = true;
    s.send.final_size = 0;
    s.send.state = .data_recvd;
    // recv stays at .recv — peer can't send on a local-initiated uni
    // stream, so the recv half is structurally dead from the start.

    conn.markStreamsGc();
    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gcClosedStreams reclaims peer-initiated uni streams once recv is terminal (send unused)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Server-initiated uni from a client connection's POV: low bits 0b11.
    const id: u64 = 3;
    // Simulate the receive-side path: plant a peer-side entry straight
    // into the stream table, without `ensurePeerStream` and so without
    // the id space ever hearing of the id.
    const ptr = try allocator.create(Stream);
    errdefer allocator.destroy(ptr);
    ptr.* = .{
        .id = id,
        .send = SendStream.init(allocator),
        .recv = RecvStream.init(allocator),
        .recv_max_data = conn.initialRecvStreamLimit(id),
        .send_max_data = 0,
    };
    try conn.streams.put(allocator, id, ptr);

    const s = conn.stream(id).?;
    s.recv.fin_seen = true;
    s.recv.final_size = 0;
    s.recv.state = .data_recvd;
    // send stays at .ready — local can't send on a peer-initiated uni.

    conn.markStreamsGc();
    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
    // The id space never saw this id, so it does not count a close for
    // it (a close it did not open would be stream credit from nowhere).
    try std.testing.expectEqual(@as(u64, 0), conn.peer_uni_ids.closed);
}

test "gcClosedStreams: a reaped peer stream is not resurrected by a replayed frame (L2)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = default_connection_receive_window,
        .initial_max_stream_data_uni = default_stream_receive_window,
        .initial_max_streams_uni = 4,
    });

    // Client-initiated uni stream 0 (peer stream from the server's view).
    const sid: u64 = 2;

    // Open + finish it through the real receive path (bumps the
    // peer-opened watermark, unlike a direct streams.put).
    try conn.handleStream(.application, .{
        .stream_id = sid,
        .offset = 0,
        .data = "hi",
        .has_length = true,
        .fin = true,
    });
    try std.testing.expect(conn.streams.get(sid) != null);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_uni_ids.opened);

    // Consume all bytes so the recv half is fully terminal, then reap.
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), try conn.streamRead(sid, &buf));
    try conn.tick(1_000_000);
    try std.testing.expect(conn.streams.get(sid) == null);
    // The id space still knows uni index 0 was used, and counts the close.
    try std.testing.expectEqual(StreamIdSpace.State.used, conn.peer_uni_ids.classify(0));
    try std.testing.expectEqual(@as(u64, 1), conn.peer_uni_ids.closed);

    // Replay a STREAM frame for the reaped id — must be ignored (RFC 9000
    // §3.2), not resurrected with fresh state.
    try conn.handleStream(.application, .{
        .stream_id = sid,
        .offset = 0,
        .data = "XX",
        .has_length = true,
    });
    try std.testing.expect(conn.streams.get(sid) == null);

    // A replayed RESET_STREAM for the reaped id is likewise ignored.
    try conn.handleResetStream(.{ .stream_id = sid, .application_error_code = 0, .final_size = 2 });
    try std.testing.expect(conn.streams.get(sid) == null);

    // A higher, never-before-seen peer uni stream still opens normally —
    // the watermark only suppresses the specific reaped id.
    const sid2: u64 = 6; // client uni stream 1
    try conn.handleStream(.application, .{
        .stream_id = sid2,
        .offset = 0,
        .data = "yo",
        .has_length = true,
    });
    try std.testing.expect(conn.streams.get(sid2) != null);
}

test "gcClosedStreams: an out-of-order reaped peer stream above the watermark is not resurrected (L2 sparse)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = default_connection_receive_window,
        .initial_max_stream_data_uni = default_stream_receive_window,
        .initial_max_streams_uni = 8,
    });

    // Three client-initiated uni streams (peer streams from the server's
    // view): indices 0, 1, 2 → ids 2, 6, 10. Open each with a FIN so its
    // recv half can go terminal once its bytes are read.
    const id0: u64 = 2;
    const id1: u64 = 6;
    const id2: u64 = 10;
    for ([_]u64{ id0, id1, id2 }) |sid| {
        try conn.handleStream(.application, .{
            .stream_id = sid,
            .offset = 0,
            .data = "hi",
            .has_length = true,
            .fin = true,
        });
    }
    try std.testing.expectEqual(@as(u64, 3), conn.peer_uni_ids.opened);

    // Read + reap indices 0 and 2, but leave index 1 ALIVE — its bytes stay
    // unread, so its recv half is not terminal and gcClosedStreams keeps it.
    var buf: [8]u8 = undefined;
    _ = try conn.streamRead(id0, &buf);
    _ = try conn.streamRead(id2, &buf);
    try conn.tick(1_000_000);
    try std.testing.expect(conn.streams.get(id0) == null);
    try std.testing.expect(conn.streams.get(id2) == null);
    try std.testing.expect(conn.streams.get(id1) != null);

    // Two closed, one live between them. All three indices are `used`;
    // only the stream table tells the live one from the closed ones.
    try std.testing.expectEqual(@as(u64, 2), conn.peer_uni_ids.closed);
    for ([_]u64{ 0, 1, 2 }) |index| {
        try std.testing.expectEqual(StreamIdSpace.State.used, conn.peer_uni_ids.classify(index));
    }

    // A replayed STREAM frame for the out-of-order reaped id (index 2) MUST
    // be ignored (RFC 9000 §3.2), not resurrected — a closed stream above a
    // still-live one is as closed as one below it.
    try conn.handleStream(.application, .{
        .stream_id = id2,
        .offset = 0,
        .data = "XX",
        .has_length = true,
    });
    try std.testing.expect(conn.streams.get(id2) == null);

    // A replayed RESET_STREAM for the same reaped id is likewise ignored.
    try conn.handleResetStream(.{ .stream_id = id2, .application_error_code = 0, .final_size = 2 });
    try std.testing.expect(conn.streams.get(id2) == null);

    // The still-live in-between stream is unaffected.
    try std.testing.expect(conn.streams.get(id1) != null);
    // "Reaped" is for a stream that is gone. A live stream is not
    // reaped, though its id is used too; an id that was never used is
    // not reaped either.
    try std.testing.expect(conn.streamRecvWasReaped(id0));
    try std.testing.expect(conn.streamRecvWasReaped(id2));
    try std.testing.expect(!conn.streamRecvWasReaped(id1));
    try std.testing.expect(!conn.streamRecvWasReaped(14));
}

test "gcClosedStreams: reordered replies to reaped local bidi streams do not close the connection" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |server| {
        var ctx = if (server) try boringssl.tls.Context.initServer(.{}) else try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = if (server) try Connection.createServer(allocator, ctx) else try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        const role: u64 = if (server) 1 else 0;
        try conn.setTransportParams(.{ .initial_max_data = 4096, .initial_max_stream_data_bidi_local = 4096 });
        _ = try conn.openBidi(role); // A lower local stream remains alive.
        const sid = role + 8;
        const stream = try conn.openBidi(sid);
        // The request's empty FIN was ACKed; the real receive path consumes
        // the reply's bytes and FIN before GC. Another copy may still be on
        // the network because packet-level ACK/loss decisions raced delivery.
        try conn.streamFinish(sid);
        stream.send.fin_acked = true;
        stream.send.state = .data_recvd;
        try conn.handleStream(.application, .{ .stream_id = sid, .data = "ok", .has_length = true, .fin = true });
        var buf: [2]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 2), try conn.streamRead(sid, &buf));
        try conn.tick(1000);
        try std.testing.expect(conn.stream(sid) == null);

        try conn.handleStream(.application, .{ .stream_id = sid, .data = "ok", .has_length = true, .fin = true });
        try std.testing.expectEqual(state.CloseState.open, conn.closeState());
        try conn.handleResetStream(.{ .stream_id = sid, .application_error_code = 0, .final_size = 2 });
        try @import("recv_stream_control_handlers.zig").handleStopSending(conn, .{ .stream_id = sid, .application_error_code = 0 });
        try conn.handleMaxStreamData(.{ .stream_id = sid, .maximum_stream_data = 4096 });
        try std.testing.expectEqual(state.CloseState.open, conn.closeState());
        try std.testing.expect(conn.stream(sid) == null);
        try std.testing.expect(conn.stream(role) != null);
        try std.testing.expectError(Error.StreamAlreadyOpen, conn.openBidi(sid));
    }
}

test "gcClosedStreams: a tombstone has no index bound" {
    // The tombstone was one bit in a 4096-bit set, so a local bidi id
    // at index 4096 or above could not be forgotten and kept its
    // terminal Stream for the life of the connection. The id space has
    // no such bound: any index is reaped, and stays closed.
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(std.testing.allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{ .initial_max_data = 4096, .initial_max_stream_data_bidi_local = 4096 });
    const indices = [_]u64{ 4095, 4096, 1_000_000 };
    for (indices) |index| {
        const sid = index * 4;
        const stream = try conn.openBidi(sid);
        try conn.streamFinish(sid);
        stream.send.fin_acked = true;
        stream.send.state = .data_recvd;
        try conn.handleStream(.application, .{ .stream_id = sid, .data = "", .has_length = true, .fin = true });
    }
    try conn.tick(1000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
    try std.testing.expectEqual(@as(u64, 3), conn.local_bidi_ids.closed);
    // Skipping a block of ids costs one range, however large the block.
    try std.testing.expectEqual(@as(usize, 2), conn.local_bidi_ids.holes.items.len);
    for (indices) |index| {
        // A late reply is ignored, and the id is not free again.
        try conn.handleStream(.application, .{ .stream_id = index * 4, .data = "", .has_length = true, .fin = true });
        try conn.handleResetStream(.{ .stream_id = index * 4, .application_error_code = 0, .final_size = 0 });
        try std.testing.expect(conn.stream(index * 4) == null);
        try std.testing.expectError(Error.StreamAlreadyOpen, conn.openBidi(index * 4));
    }
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
    // An id that was only skipped is not closed: it can still be opened.
    _ = try conn.openBidi(5000 * 4);
}

test "gcClosedStreams: a reaped local uni stream id cannot be opened again" {
    // `openUni` had no tombstone check, so a reaped id opened a fresh
    // stream at offset 0. The peer drops frames for a stream it has
    // closed (RFC 9000 §3.2), so that data was lost with no error.
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(std.testing.allocator, ctx, "x");
    defer conn.destroy();
    const sid = (try conn.openNextUni()).id;
    const stream = conn.stream(sid).?;
    try conn.streamFinish(sid);
    stream.send.fin_acked = true;
    stream.send.state = .data_recvd;
    conn.markStreamsGc();
    try conn.tick(1000);
    try std.testing.expect(conn.stream(sid) == null);

    try std.testing.expectError(Error.StreamAlreadyOpen, conn.openUni(sid));
    try std.testing.expect(conn.stream(sid) == null);
    // The next id in order is not affected.
    try std.testing.expectEqual(sid + 4, (try conn.openNextUni()).id);
}

test "openBidi: skipped ids are remembered in a bounded number of ranges" {
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(std.testing.allocator, ctx, "x");
    defer conn.destroy();

    // Each open skips one id, so each leaves one more one-id range.
    var index: u64 = 1;
    var opened: usize = 0;
    while (opened < Connection.max_local_skipped_stream_ranges) : (opened += 1) {
        _ = try conn.openBidi(index * 4);
        index += 2;
    }
    try std.testing.expectEqual(Connection.max_local_skipped_stream_ranges, conn.local_bidi_ids.holes.items.len);

    // One more skip is refused, and changes nothing.
    const before = conn.local_bidi_ids.opened;
    try std.testing.expectError(Error.TooManySkippedStreamIds, conn.openBidi(index * 4));
    try std.testing.expectEqual(before, conn.local_bidi_ids.opened);
    try std.testing.expect(conn.stream(index * 4) == null);

    // In-order opens never skip, so they still work; so does filling a
    // skipped id.
    _ = try conn.openNextBidi();
    _ = try conn.openBidi(0);
    try std.testing.expectEqual(Connection.max_local_skipped_stream_ranges - 1, conn.local_bidi_ids.holes.items.len);
}

test "materializeStream: a failed allocation does not consume the id" {
    // If the id were marked used before the Stream is allocated, an
    // out-of-memory here would leave "used, with no stream": the id of
    // a closed stream. Every later frame for it would be ignored.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(failing.allocator(), ctx);
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_uni = 4096,
        .initial_max_streams_uni = 4,
    });

    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try std.testing.expectError(error.OutOfMemory, conn.handleStream(.application, .{
        .stream_id = 2,
        .data = "hi",
        .has_length = true,
    }));
    failing.fail_index = std.math.maxInt(usize);
    failing.resize_fail_index = std.math.maxInt(usize);
    try std.testing.expect(conn.stream(2) == null);
    try std.testing.expectEqual(StreamIdSpace.State.not_opened, conn.peer_uni_ids.classify(0));

    // The retransmission of that frame opens the stream.
    try conn.handleStream(.application, .{ .stream_id = 2, .data = "hi", .has_length = true });
    try std.testing.expect(conn.stream(2) != null);
    try std.testing.expectEqual(StreamIdSpace.State.used, conn.peer_uni_ids.classify(0));
}

test "gcClosedStreams: an absent local stream below the allocation watermark is not necessarily reaped" {
    for ([_]bool{ false, true }) |reset| {
        var ctx = try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = try Connection.createClient(std.testing.allocator, ctx, "x");
        defer conn.destroy();
        _ = try conn.openBidi(8); // Neither 0 nor 4 was materialized/reaped.
        if (reset) try conn.handleResetStream(.{ .stream_id = 4, .application_error_code = 0, .final_size = 0 }) else try conn.handleStream(.application, .{ .stream_id = 4, .data = "unexpected", .has_length = true });
        try std.testing.expectEqual(@as(u64, 5), conn.closeEvent().?.error_code);
        try std.testing.expect(conn.stream(4) == null);
    }
}

test "gcClosedStreams: a still-live local bidi stream keeps its final-size validation" {
    for ([_]bool{ false, true }) |reset| {
        var ctx = try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = try Connection.createClient(std.testing.allocator, ctx, "x");
        defer conn.destroy();
        try conn.setTransportParams(.{ .initial_max_data = 4096, .initial_max_stream_data_bidi_local = 4096 });
        _ = try conn.openBidi(0);
        try conn.handleStream(.application, .{ .stream_id = 0, .data = "ok", .has_length = true, .fin = true });
        // Leave the send half live: terminal-receive GC must not bypass the
        // locked final size while this stream still owns state.
        var buf: [2]u8 = undefined;
        _ = try conn.streamRead(0, &buf);
        try conn.tick(1000);
        try std.testing.expect(conn.stream(0) != null);
        if (reset) try conn.handleResetStream(.{ .stream_id = 0, .application_error_code = 0, .final_size = 3 }) else try conn.handleStream(.application, .{ .stream_id = 0, .data = "bad", .has_length = true, .fin = true });
        try std.testing.expectEqual(@as(u64, 6), conn.closeEvent().?.error_code);
    }
}

test "initialSendStreamLimit: remembered 0-RTT params bound the pre-params send window (L6)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // A plain (non-0-RTT) client with no params and no early-data keys
    // grants no pre-params send window (previously an unbounded maxInt).
    try std.testing.expectEqual(@as(u64, 0), conn.initialSendStreamLimit(0));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), conn.peer_max_data);

    // Until any parameters are there, the number of streams this end
    // may open is the wire maximum, 2^60 (nothing can be sent on them).
    try std.testing.expectEqual(@as(u64, 1 << 60), conn.local_bidi_ids.limit);
    try std.testing.expectEqual(@as(u64, 1 << 60), conn.local_uni_ids.limit);

    // Install remembered peer params (a 0-RTT resumption): pre-params
    // windows are now bounded by them, per-stream and connection-level.
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 512,
        .initial_max_streams_bidi = 3,
        .initial_max_streams_uni = 1,
    });
    // Client-initiated bidi stream 0 → remembered bidi_remote limit.
    try std.testing.expectEqual(@as(u64, 2048), conn.initialSendStreamLimit(0));
    // Client-initiated uni stream (id 2) → remembered uni limit.
    try std.testing.expectEqual(@as(u64, 512), conn.initialSendStreamLimit(2));
    // Connection-level send window tightened from maxInt to the remembered value.
    try std.testing.expectEqual(@as(u64, 4096), conn.peer_max_data);
    // The NUMBER of streams is the remembered one too (RFC 9000 §7.4.1).
    try std.testing.expectEqual(@as(u64, 3), conn.local_bidi_ids.limit);
    try std.testing.expectEqual(@as(u64, 1), conn.local_uni_ids.limit);
    _ = try conn.openBidi(0);
    _ = try conn.openBidi(4);
    _ = try conn.openBidi(8);
    try std.testing.expectError(Error.StreamLimitExceeded, conn.openBidi(12));
    _ = try conn.openUni(2);
    try std.testing.expectError(Error.StreamLimitExceeded, conn.openUni(6));
}

test "remembered 0-RTT params do not touch the limits once the real parameters are there" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // The real parameters arrived first (a late call of the embedder).
    conn.cached_peer_transport_params = .{ .initial_max_data = 1 << 20, .initial_max_streams_bidi = 50 };
    conn.peer_max_data = 1 << 20;
    conn.local_bidi_ids.limit = 50;
    conn.local_uni_ids.limit = 7;

    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_streams_bidi = 3,
        .initial_max_streams_uni = 1,
    });
    try std.testing.expectEqual(@as(u64, 1 << 20), conn.peer_max_data);
    try std.testing.expectEqual(@as(u64, 50), conn.local_bidi_ids.limit);
    try std.testing.expectEqual(@as(u64, 7), conn.local_uni_ids.limit);
}

test "send-side ops on a peer-initiated uni stream fail fast with StreamNotWritable" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // Plant a peer-initiated (client-initiated) uni stream the way inbound
    // STREAM frames leave it in the live table, then confirm every send-side
    // op rejects it instead of queueing into a send half the scheduler
    // never transmits.
    conn.local_transport_params.initial_max_streams_uni = 4;
    conn.local_transport_params.initial_max_stream_data_uni = 1024;
    const id: u64 = 2;
    const peer = try allocator.create(Stream);
    errdefer allocator.destroy(peer);
    peer.* = .{
        .id = id,
        .send = SendStream.init(allocator),
        .recv = RecvStream.init(allocator),
        .recv_max_data = conn.initialRecvStreamLimit(id),
        .send_max_data = 0,
    };
    try conn.streams.put(allocator, id, peer);

    try std.testing.expectError(Error.StreamNotWritable, conn.streamWrite(2, "black hole"));
    try std.testing.expectError(Error.StreamNotWritable, conn.streamFinish(2));
    try std.testing.expectError(Error.StreamNotWritable, conn.streamReset(2, 0));

    // Nothing landed in the stream's send half.
    const st = conn.stream(2).?;
    try std.testing.expectEqual(@as(u64, 0), st.send.writtenBytes());
    try std.testing.expect(!st.send.hasPendingChunk());

    // The guard is directional, not a blanket write ban: a local bidi
    // stream still accepts writes normally.
    const bidi = try conn.openNextBidi();
    try std.testing.expectEqual(@as(usize, 2), try conn.streamWrite(bidi.id, "ok"));
}

test "recv-side reads on a local-initiated uni stream fail fast with StreamNotReadable" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // A locally-opened uni stream has no receive half on this side.
    // Reads used to return 0 forever — indistinguishable from "nothing
    // readable right now" — the receive-side twin of the send black
    // hole above. They must fail fast instead.
    conn.local_uni_ids.limit = 4;
    const uni = try conn.openNextUni();
    var buf: [16]u8 = undefined;
    try std.testing.expectError(Error.StreamNotReadable, conn.streamRead(uni.id, &buf));
    try std.testing.expectError(Error.StreamNotReadable, conn.streamReadFin(uni.id, &buf));

    // streamRecvState on the same send-only stream returns null (not
    // a fabricated non-terminal state a completion poll would wait on
    // forever) — the receive-side twin of the StreamNotReadable guard.
    try std.testing.expectEqual(
        @as(?@import("../Connection.zig").StreamRecvState, null),
        conn.streamRecvState(uni.id),
    );

    // Directional, not a blanket read ban: a local bidi stream's
    // receive half still reads normally (empty right now) and reports
    // a real (non-terminal) recv state.
    const bidi = try conn.openNextBidi();
    try std.testing.expectEqual(@as(usize, 0), try conn.streamRead(bidi.id, &buf));
    const st = conn.streamRecvState(bidi.id) orelse return error.MissingRecvState;
    try std.testing.expect(!st.terminal);
}

// -- STOP_SENDING and MAX_STREAM_DATA: frames that name OUR sending part --

const stream_control = @import("recv_stream_control_handlers.zig");
const transport_error_stream_state = state.transport_error_stream_state;

fn stopSending(conn: *Connection, id: u64) Error!void {
    return stream_control.handleStopSending(conn, .{ .stream_id = id, .application_error_code = 9 });
}

fn maxStreamData(conn: *Connection, id: u64, maximum: u64) Error!void {
    return conn.handleMaxStreamData(.{ .stream_id = id, .maximum_stream_data = maximum });
}

/// The connection closed itself with the transport error `code`.
fn expectClosedWith(conn: *Connection, code: u64) !void {
    const ev = conn.closeEvent() orelse return error.ConnectionNotClosed;
    try std.testing.expectEqual(code, ev.error_code);
}

/// A server connection that lets the peer open four streams of each type.
fn sendPartServer(ctx: boringssl.tls.Context) !*Connection {
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    errdefer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 64,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_stream_data_uni = 64,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 4,
    });
    return conn;
}

test "STOP_SENDING for a receive-only stream is STREAM_STATE_ERROR, and makes no RESET_STREAM" {
    // RFC 9000 §19.5: "An endpoint that receives a STOP_SENDING frame
    // for a receive-only stream MUST terminate the connection with
    // error STREAM_STATE_ERROR." Stream 2 is a unidirectional stream of
    // the client: this server has no sending part on it. The handler
    // used to reset the send half of the `Stream` all the same, which
    // queued a RESET_STREAM on a stream we cannot send on.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    {
        const conn = try sendPartServer(ctx);
        defer conn.destroy();
        try conn.handleStream(.application, .{ .stream_id = 2, .offset = 0, .data = "x", .has_length = true });
        try stopSending(conn, 2);
        try expectClosedWith(conn, transport_error_stream_state);
        try std.testing.expect(conn.stream(2).?.send.reset == null);
    }
    {
        // And for one the peer has not used yet: the frame does not open it.
        const conn = try sendPartServer(ctx);
        defer conn.destroy();
        try stopSending(conn, 6);
        try expectClosedWith(conn, transport_error_stream_state);
        try std.testing.expect(conn.stream(6) == null);
        try std.testing.expectEqual(@as(u64, 0), conn.peer_uni_ids.opened);
    }
}

test "STOP_SENDING and MAX_STREAM_DATA for a stream of ours that was never opened are STREAM_STATE_ERROR" {
    // RFC 9000 §19.5 and §19.10, in the same words: a frame "for a
    // locally initiated stream that has not yet been created MUST be
    // treated as a connection error of type STREAM_STATE_ERROR". The
    // peer cannot know about a stream we have not opened. Both frames
    // used to be dropped without a word.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    // 1: a bidirectional stream of the server. 3: a unidirectional one.
    for ([_]u64{ 1, 3 }) |id| {
        for ([_]bool{ true, false }) |stop| {
            const conn = try sendPartServer(ctx);
            defer conn.destroy();
            if (stop) try stopSending(conn, id) else try maxStreamData(conn, id, 1000);
            try expectClosedWith(conn, transport_error_stream_state);
            try std.testing.expect(conn.stream(id) == null);
        }
    }
}

test "STOP_SENDING or MAX_STREAM_DATA as the first frame for a peer bidirectional stream creates it" {
    // RFC 9000 §3.2: "For bidirectional streams initiated by a peer,
    // receipt of a MAX_STREAM_DATA or STOP_SENDING frame for the
    // sending part of the stream also creates the receiving part."
    // Both used to be dropped when the stream was not there yet: the
    // STOP_SENDING was then never answered with a RESET_STREAM, and the
    // credit of the MAX_STREAM_DATA was lost.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();
    // The peer lets us send 10 bytes on a stream it opens.
    conn.cached_peer_transport_params = .{ .initial_max_stream_data_bidi_local = 10 };
    conn.validatePeerTransportLimits();

    try stopSending(conn, 0);
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
    const first = conn.stream(0) orelse return error.StreamNotCreated;
    // Our sending part is abandoned, as the peer asked (§3.5).
    try std.testing.expectEqual(SendStream.State.reset_sent, first.send.state);
    try std.testing.expectEqual(@as(u64, 9), first.send.reset.?.error_code);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_bidi_ids.opened);

    // Stream 8 arrives before stream 4: both are open now (§2.1), and
    // the one that was named has the credit.
    try maxStreamData(conn, 8, 1000);
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
    const third = conn.stream(8) orelse return error.StreamNotCreated;
    try std.testing.expectEqual(@as(u64, 1000), third.send_max_data);
    try std.testing.expectEqual(@as(u64, 3), conn.peer_bidi_ids.opened);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_bidi_ids.holeCount());

    // The embedder is told about all three, in order.
    var seen: u64 = 0;
    while (conn.pollEvent()) |ev| switch (ev) {
        .stream_opened => |info| {
            try std.testing.expectEqual(seen * 4, info.stream_id);
            seen += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(u64, 3), seen);
}

test "STOP_SENDING or MAX_STREAM_DATA for a peer stream over the limit is STREAM_LIMIT_ERROR" {
    // The frame would create the stream (§3.2), so the stream limit
    // applies to it as to any first frame (§4.6).
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    for ([_]bool{ true, false }) |stop| {
        const conn = try sendPartServer(ctx);
        defer conn.destroy();
        // Index 4 with a limit of four.
        if (stop) try stopSending(conn, 16) else try maxStreamData(conn, 16, 1000);
        try expectClosedWith(conn, transport_error_stream_limit);
        try std.testing.expect(conn.stream(16) == null);
    }
}

test "STOP_SENDING or MAX_STREAM_DATA for a peer stream that closed is ignored" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();

    // Stream 0: request read to its end, reply finished and
    // acknowledged, reaped.
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = "x", .has_length = true, .fin = true });
    var buf: [1]u8 = undefined;
    _ = try conn.streamRead(0, &buf);
    try conn.streamFinish(0);
    const s = conn.stream(0).?;
    s.send.fin_acked = true;
    s.send.state = .data_recvd;
    conn.markStreamsGc();
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(0) == null);

    try stopSending(conn, 0);
    try maxStreamData(conn, 0, 1000);
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
    try std.testing.expect(conn.stream(0) == null);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_bidi_ids.opened);
}

test "STOP_SENDING after every byte was acknowledged makes no RESET_STREAM" {
    // RFC 9000 §3.1: RESET_STREAM is sent from "Ready", "Send" or "Data
    // Sent". In "Data Recvd" the peer has acknowledged every byte and
    // the FIN, and the state is terminal. A STOP_SENDING that crossed
    // those acknowledgements on the path used to put the stream back
    // in "Reset Sent": a RESET_STREAM for a finished stream, and a
    // stream that was terminal a moment ago and now waits for one more
    // acknowledgement before it can be reaped.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();

    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = "x", .has_length = true, .fin = true });
    var buf: [1]u8 = undefined;
    _ = try conn.streamRead(0, &buf);
    try conn.streamFinish(0);
    const s = conn.stream(0).?;
    s.send.fin_acked = true;
    s.send.state = .data_recvd;

    conn.markStreamsGc();
    try stopSending(conn, 0);
    try std.testing.expectEqual(SendStream.State.data_recvd, s.send.state);
    try std.testing.expect(s.send.reset == null);
    try std.testing.expect(!s.send.hasPendingChunk());
    // Still terminal: the next tick reaps it.
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(0) == null);
}

// -- streams the application stopped reading, and streams the peer reset --

test "a peer RESET_STREAM gives the bytes nobody read back to the connection window" {
    // The connection-level window counts every byte the peer sends on
    // any stream, and MAX_DATA moves it forward as the application
    // reads. Bytes on a stream the peer resets are never read, and they
    // were never given back: each reset took its unread bytes out of
    // the window for good, and a connection that lived long enough
    // stalled at `initial_max_data`.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();

    // 40 bytes arrive and the application reads 10 of them. Then the
    // peer resets the stream at 60: it had sent 20 more, which were
    // lost on the way.
    const forty: [40]u8 = @splat('x');
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = &forty, .has_length = true });
    var buf: [10]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 10), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(u64, 10), conn.recv_stream_bytes_read);
    try conn.handleResetStream(.{ .stream_id = 0, .application_error_code = 1, .final_size = 60 });
    // All 60 count against the window, and all 60 are now done with.
    try std.testing.expectEqual(@as(u64, 60), conn.peer_sent_stream_data);
    try std.testing.expectEqual(@as(u64, 60), conn.recv_stream_bytes_read);

    // A second copy of the RESET_STREAM gives nothing back twice.
    try conn.handleResetStream(.{ .stream_id = 0, .application_error_code = 1, .final_size = 60 });
    try std.testing.expectEqual(@as(u64, 60), conn.recv_stream_bytes_read);
}

test "streamStopSending: what arrives afterwards is thrown away, and the receive half ends by itself" {
    // The application told the peer to stop. It will not read this
    // stream again, so the library reads it to its end for it. Without
    // that, a stream whose peer had already sent everything (and so
    // sends no RESET_STREAM) stayed open here for the life of the
    // connection, holding its place in the stream window and its
    // bytes in the connection window.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();

    try conn.handleStream(.application, .{ .stream_id = 2, .offset = 0, .data = "hello", .has_length = true });
    try conn.streamStopSending(2, 7);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.stop_sending.items.len);
    // Nothing is consumed during the call (the caller may be inside a
    // read callback, with a slice of this buffer in hand). The five
    // bytes that were waiting are thrown away by the next tick, and
    // count as read.
    try std.testing.expectEqual(@as(u64, 0), conn.recv_stream_bytes_read);
    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(u64, 5), conn.recv_stream_bytes_read);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try conn.streamRead(2, &buf));
    try std.testing.expect(conn.stream(2) != null);

    // The rest was already on its way, with the FIN. Nobody reads it.
    try conn.handleStream(.application, .{ .stream_id = 2, .offset = 5, .data = " world", .has_length = true, .fin = true });
    try std.testing.expectEqual(@as(u64, 11), conn.recv_stream_bytes_read);
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(2) == null);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_uni_ids.closed);
}

test "streamStopSending: only for a stream the peer can send on, and that is there" {
    // A STOP_SENDING for a stream the peer cannot send on, or has not
    // opened, is a STREAM_STATE_ERROR on the peer's side (RFC 9000
    // §19.5): the call must not put one on the wire.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();

    // Our own unidirectional stream: the peer has no sending part.
    conn.local_uni_ids.limit = 4;
    const uni = try conn.openNextUni();
    try std.testing.expectError(Error.StreamNotReadable, conn.streamStopSending(uni.id, 0));
    // A stream the peer has not opened.
    try std.testing.expectError(Error.StreamNotFound, conn.streamStopSending(0, 0));
    // A stream that finished and was reaped.
    try conn.handleStream(.application, .{ .stream_id = 2, .offset = 0, .data = "", .has_length = true, .fin = true });
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(2) == null);
    try std.testing.expectError(Error.StreamNotFound, conn.streamStopSending(2, 0));

    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.stop_sending.items.len);
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
}

test "streamStopSending on a stream the peer opened by skipping it is remembered" {
    // The peer used its second unidirectional stream first. The first
    // one (id 2) is open too (RFC 9000 §2.1) and is reported to the
    // embedder, but has no `Stream` here yet. If the embedder refuses
    // it now, the refusal has to be kept: data that arrives for it
    // later must be thrown away, not left for a reader that will never
    // come.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try sendPartServer(ctx);
    defer conn.destroy();

    try conn.handleStream(.application, .{ .stream_id = 6, .offset = 0, .data = "x", .has_length = true });
    try std.testing.expect(conn.stream(2) == null);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_uni_ids.holeCount());

    try conn.streamStopSending(2, 7);
    try std.testing.expect(conn.stream(2) != null);
    try std.testing.expectEqual(@as(u64, 0), conn.peer_uni_ids.holeCount());
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.stop_sending.items.len);

    try conn.handleStream(.application, .{ .stream_id = 2, .offset = 0, .data = "late", .has_length = true, .fin = true });
    try std.testing.expectEqual(@as(u64, 4), conn.recv_stream_bytes_read);
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(2) == null);
}
