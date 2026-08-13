//! Socket-facing UDP egress shared by the bundled loops: the
//! cross-peer `SendBatch` accumulator and the GSO super-datagram
//! drain. `runUdpServer` and `runUdpClient` run the same kernel
//! offload algorithm (fill -> one `sendmsg` carrying a `UDP_SEGMENT`
//! cmsg -> re-ship plainly if the socket rejects offload at runtime);
//! only two things differ per role, and both arrive through the
//! comptime `ctx` parameter of `drainGso`: destination resolution (a
//! server falls back to the slot's peer, a client to its configured
//! target) and the send call itself (both currently route through
//! `udp_server.sendTolerant`).

const std = @import("std");

const conn_mod = @import("../conn/root.zig");
const socket_opts = @import("socket_opts.zig");
const udp_batch = @import("udp_batch.zig");

const Net = std.Io.net;
const Connection = conn_mod.Connection;
const Address = conn_mod.path.Address;

/// Per-socket egress accumulator: outbound datagrams (for any number
/// of peers) collect here and ship via one `Socket.sendMany`.
/// `addrs` is parallel stable storage — `OutgoingMessage.address` is a
/// pointer, so the addresses must not move between fill and flush.
pub const SendBatch = struct {
    msgs: []Net.OutgoingMessage,
    addrs: []Net.IpAddress,
    buf: []u8,
    datagram_bytes: usize,
    len: usize = 0,
    used: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        capacity: usize,
        datagram_bytes: usize,
    ) !SendBatch {
        const msgs = try allocator.alloc(Net.OutgoingMessage, capacity);
        errdefer allocator.free(msgs);
        const addrs = try allocator.alloc(Net.IpAddress, capacity);
        errdefer allocator.free(addrs);
        const buf = try allocator.alloc(u8, capacity * datagram_bytes);
        errdefer allocator.free(buf);
        return .{
            .msgs = msgs,
            .addrs = addrs,
            .buf = buf,
            .datagram_bytes = datagram_bytes,
        };
    }

    pub fn deinit(self: *SendBatch, allocator: std.mem.Allocator) void {
        allocator.free(self.msgs);
        allocator.free(self.addrs);
        allocator.free(self.buf);
        self.* = undefined;
    }

    /// Scratch space for the next datagram, or null when full.
    pub fn nextSlot(self: *SendBatch) ?[]u8 {
        if (self.len >= self.msgs.len) return null;
        return self.buf[self.used..][0..self.datagram_bytes];
    }

    /// Commit `len` bytes of the slot returned by `nextSlot` for `to`.
    pub fn commit(self: *SendBatch, to: Net.IpAddress, len: usize) void {
        std.debug.assert(self.len < self.msgs.len);
        self.addrs[self.len] = to;
        self.msgs[self.len] = .{
            .address = &self.addrs[self.len],
            .data_ptr = self.buf.ptr + self.used,
            .data_len = len,
        };
        self.len += 1;
        self.used += len;
    }

    /// Ship everything accumulated (one sendMany; the std lowers to
    /// sendmmsg in 64-message chunks on Linux, a send loop elsewhere)
    /// and reset. Send failures are the caller's policy.
    pub fn flush(self: *SendBatch, io: std.Io, sock: Net.Socket) !void {
        if (self.len == 0) return;
        defer {
            self.len = 0;
            self.used = 0;
        }
        try sock.sendMany(io, self.msgs[0..self.len], .{});
    }
};

/// Drain `conn`'s outbox as GSO super-datagrams: pack equal-size
/// datagrams via `udp_batch.fillGsoBatch` and ship each batch through
/// one offloaded send (the kernel splits on the `UDP_SEGMENT` stride).
/// Bypasses the cross-slot `SendBatch` — the syscall saving already
/// happened inside the super-datagram, and immediate sends sidestep
/// buffer-lifetime coupling with other connections.
///
/// A failed offloaded send clears `gso_active` (kernel/offload
/// quirk), re-ships the already-built segments individually, finishes
/// the batch's carry datagram, and ends the drain — the caller falls
/// back to plain batched sends for whatever is left. The cleared flag
/// MUST end the loop: a `UDP_SEGMENT` cmsg must never reach a socket
/// that just rejected offload (`socket_opts.probeUdpGso` documents
/// the panic hazard).
///
/// `ctx` is comptime-duck-typed (zero-cost, no fn-pointer indirection
/// on the hot path) and supplies the role-specific policies plus the
/// socket itself — which also makes the algorithm unit-testable
/// off-Linux with a fake-socket ctx:
///
///   * `resolve(ctx, to: ?Address) ?Net.IpAddress` — pick the wire
///     destination for a batch destined to `to`. Null means "no
///     usable destination" and stops the drain (the server posture; a
///     client resolver that falls back to its configured target never
///     returns null, preserving its old behavior byte-for-byte).
///   * `send(ctx, dest: *const Net.IpAddress, data: []const u8) !void`
///     — plain single-datagram send (count-1 batches, the offload
///     fallback re-ship, and the carry).
///   * `sendMany(ctx, msgs: []Net.OutgoingMessage) !void` — the
///     offloaded send; any failure triggers the fallback above.
pub fn drainGso(
    conn: *Connection,
    gso_buf: []u8,
    max_segments: u32,
    now_us: u64,
    gso_active: *bool,
    ctx: anytype,
) !void {
    while (gso_active.*) {
        const filled = try udp_batch.fillGsoBatch(conn, gso_buf, max_segments, now_us);
        if (filled.count == 0) return;
        var dest = ctx.resolve(filled.to) orelse return;

        if (filled.count == 1) {
            try ctx.send(&dest, gso_buf[0..filled.total_len]);
        } else {
            var cmsg: [64]u8 = undefined;
            const cmsg_len = socket_opts.writeUdpSegmentCmsg(&cmsg, @intCast(filled.seg_size));
            var msgs = [_]Net.OutgoingMessage{.{
                .address = &dest,
                .data_ptr = gso_buf.ptr,
                .data_len = filled.total_len,
                .control = cmsg[0..cmsg_len],
            }};
            ctx.sendMany(&msgs) catch {
                // Offload rejected at runtime (EIO family): disable
                // for this socket and re-ship the built segments
                // plainly — they are already segment-aligned in
                // gso_buf. The cleared flag ends the drain once this
                // batch (and its carry) is out.
                gso_active.* = false;
                var off: usize = 0;
                while (off < filled.total_len) {
                    const end = @min(off + filled.seg_size, filled.total_len);
                    try ctx.send(&dest, gso_buf[off..end]);
                    off = end;
                }
            };
        }

        if (filled.hasCarry()) {
            // Trailing datagram whose destination differed from the
            // batch (migration probe, multipath switch): ships
            // separately to its own destination.
            var carry_dest = ctx.resolve(filled.carry_to) orelse return;
            try ctx.send(&carry_dest, gso_buf[filled.carry_offset..][0..filled.carry_len]);
        }
    }
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;
const boringssl = @import("boringssl");

const SendLog = struct {
    plain_lens: [80]usize = @splat(0),
    plain_count: usize = 0,
    /// Successful offloaded (`sendMany`) batches.
    gso_batches: usize = 0,
    /// Attempted offloaded sends, including rejected ones.
    gso_attempts: usize = 0,
};

/// Duck-typed `drainGso` ctx that records sends instead of touching a
/// socket — the fake socket that makes the offload algorithm testable
/// on every platform.
const RecordingCtx = struct {
    log: *SendLog,
    reject_gso: bool = false,
    unresolvable: bool = false,

    fn resolve(self: RecordingCtx, to: ?Address) ?Net.IpAddress {
        _ = to;
        if (self.unresolvable) return null;
        return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 4433 } };
    }

    fn send(self: RecordingCtx, dest: *const Net.IpAddress, data: []const u8) !void {
        _ = dest;
        if (self.log.plain_count < self.log.plain_lens.len) {
            self.log.plain_lens[self.log.plain_count] = data.len;
        }
        self.log.plain_count += 1;
    }

    fn sendMany(self: RecordingCtx, msgs: []Net.OutgoingMessage) !void {
        _ = msgs;
        self.log.gso_attempts += 1;
        if (self.reject_gso) return error.Unexpected;
        self.log.gso_batches += 1;
    }
};

fn queueStreamBytes(conn: *Connection, total: usize) !void {
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const s = try conn.openBidi(0);
    var queued: usize = 0;
    while (queued < total) {
        queued += try s.send.write(data[0..@min(data.len, total - queued)]);
    }
}

test "drainGso ships super-datagrams and leaves offload active" {
    const allocator = testing.allocator;
    var tls_ctx = try boringssl.tls.Context.initClient(.{});
    defer tls_ctx.deinit();
    const conn = try Connection.createClient(allocator, tls_ctx, "x");
    defer conn.destroy();
    try udp_batch.prepareSender(conn);
    try queueStreamBytes(conn, 7 * 1200);

    var buf: [64 * 1500]u8 = undefined;
    var log: SendLog = .{};
    var active = true;
    try drainGso(
        conn,
        &buf,
        socket_opts.default_gso_max_segments,
        1_000_000,
        &active,
        RecordingCtx{ .log = &log },
    );
    try testing.expect(active);
    try testing.expect(log.gso_attempts >= 1);
    try testing.expectEqual(log.gso_attempts, log.gso_batches);
    // Outbox fully drained: one more fill returns an empty batch.
    const rest = try udp_batch.fillGsoBatch(conn, &buf, socket_opts.default_gso_max_segments, 1_000_000);
    try testing.expectEqual(@as(u32, 0), rest.count);
}

test "drainGso offload rejection: re-ships plainly, clears the flag, and stops" {
    const allocator = testing.allocator;
    var tls_ctx = try boringssl.tls.Context.initClient(.{});
    defer tls_ctx.deinit();
    const conn = try Connection.createClient(allocator, tls_ctx, "x");
    defer conn.destroy();
    try udp_batch.prepareSender(conn);
    try queueStreamBytes(conn, 10 * 1200);

    var buf: [64 * 1500]u8 = undefined;
    var log: SendLog = .{};
    var active = true;
    try drainGso(conn, &buf, 3, 1_000_000, &active, RecordingCtx{
        .log = &log,
        .reject_gso = true,
    });
    // The rejected batch was re-shipped in per-segment strides ...
    try testing.expect(!active);
    try testing.expectEqual(@as(usize, 0), log.gso_batches);
    try testing.expect(log.plain_count >= 2);
    // ... and exactly ONE offloaded send was attempted: the drain must
    // never hand another `UDP_SEGMENT` cmsg to a socket that just
    // rejected one (regression: both loops used to keep looping on
    // the GSO branch after clearing the flag).
    try testing.expectEqual(@as(usize, 1), log.gso_attempts);
    // The rest of the outbox is left for the caller's plain-batching
    // fallback.
    const rest = try udp_batch.fillGsoBatch(conn, &buf, 3, 1_000_000);
    try testing.expect(rest.count > 0);
}

test "drainGso stops when the destination resolver returns null" {
    const allocator = testing.allocator;
    var tls_ctx = try boringssl.tls.Context.initClient(.{});
    defer tls_ctx.deinit();
    const conn = try Connection.createClient(allocator, tls_ctx, "x");
    defer conn.destroy();
    try udp_batch.prepareSender(conn);
    try queueStreamBytes(conn, 3 * 1200);

    var buf: [64 * 1500]u8 = undefined;
    var log: SendLog = .{};
    var active = true;
    try drainGso(conn, &buf, socket_opts.default_gso_max_segments, 1_000_000, &active, RecordingCtx{
        .log = &log,
        .unresolvable = true,
    });
    // Server posture: no usable destination ends the drain silently.
    try testing.expect(active);
    try testing.expectEqual(@as(usize, 0), log.plain_count);
    try testing.expectEqual(@as(usize, 0), log.gso_attempts);
}
