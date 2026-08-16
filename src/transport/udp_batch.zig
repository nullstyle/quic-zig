//! Batched-UDP offload helpers, both directions:
//!
//! * Send: GSO super-datagram assembly — pack consecutive
//!   same-destination, same-size QUIC datagrams from one connection
//!   back-to-back into a caller buffer so a single `sendmsg` with a
//!   `UDP_SEGMENT` cmsg ships them all (Linux; see
//!   `socket_opts.probeUdpGso` — the probe is load-bearing, never
//!   attach the cmsg without it).
//! * Receive: the `IngressIterator` mirror image — split batched
//!   (possibly GRO-coalesced) `IncomingMessage`s back into individual
//!   QUIC datagrams, trunc-filtered, ECN-parsed, address-converted.
//!
//! Pure transport-side logic over the public Connection API
//! (`pollDatagram` + `pmtu`) and plain message values — no Connection
//! changes, and usable by foreign-loop embedders doing their own
//! `sendmsg` / `recvmmsg`. Platform-neutral and unit-tested
//! everywhere; only the socket the bytes cross is Linux-specific.

const std = @import("std");
const conn_mod = @import("../conn/root.zig");
const socket_opts = @import("socket_opts.zig");

const Net = std.Io.net;
const Connection = conn_mod.Connection;
const Address = conn_mod.path.Address;
const EcnCodepoint = socket_opts.EcnCodepoint;

/// Result of one `fillGsoBatch` pass.
pub const GsoBatch = struct {
    /// Segment size: every segment except possibly the last is exactly
    /// this long (the kernel splits `buf[0..total_len]` on this
    /// stride).
    seg_size: usize = 0,
    /// Number of segments in `buf[0..total_len]`.
    count: u32 = 0,
    /// Bytes of `buf` occupied by the batch.
    total_len: usize = 0,
    /// Destination for the whole batch (null = the connection's
    /// current peer / caller fallback).
    to: ?Address = null,
    /// A trailing datagram whose destination differed from the batch
    /// (migration probe, multipath switch): contiguous in
    /// `buf[carry_offset..carry_offset + carry_len]`, to be sent
    /// separately to `carry_to`.
    carry_offset: usize = 0,
    carry_len: usize = 0,
    carry_to: ?Address = null,

    pub fn hasCarry(self: GsoBatch) bool {
        // Keyed on `carry_to` so a zero-length datagram with a
        // changed destination is still recognized as a carry instead
        // of being dropped as "no carry". QUIC never emits empty
        // datagrams today, but the predicate shouldn't silently
        // discard one if that ever changes.
        return self.carry_to != null;
    }
};

/// Drain up to `max_segments` datagrams from `conn` into `buf`,
/// packing equal-size segments for one GSO send. Stops on: empty
/// outbox, a short (final) segment, a destination change (returned as
/// `carry`), `max_segments`, or buffer exhaustion.
///
/// The FIRST datagram polls with the full remaining buffer — not a
/// segment-sized slice — so RFC 8899 DPLPMTUD probes (which need a
/// dst larger than the current PMTU) still emit; a first datagram
/// that isn't exactly PMTU-sized comes back as a count-1 batch and
/// ships as a plain send.
pub fn fillGsoBatch(
    conn: *Connection,
    buf: []u8,
    max_segments: u32,
    now_us: u64,
) conn_mod.Error!GsoBatch {
    var batch: GsoBatch = .{};
    if (max_segments == 0 or buf.len == 0) return batch;

    const pmtu_cap: usize = @min(conn.pmtu(), buf.len);
    if (pmtu_cap == 0) return batch;

    // First segment: full buffer so PMTUD probes can exceed the PMTU.
    const first = (try conn.pollDatagram(buf, now_us)) orelse return batch;
    batch.to = first.to;
    batch.total_len = first.len;
    batch.count = 1;
    batch.seg_size = first.len;
    if (first.len > pmtu_cap) {
        // DPLPMTUD probe — ship it alone.
        return batch;
    }
    // The FIRST datagram's length defines the GSO stride (the kernel
    // splits on this): follow-up polls are sliced to exactly it, so
    // middles are equal by construction and a shorter one is the tail.
    const seg = first.len;

    while (batch.count < max_segments) {
        const off = batch.total_len;
        if (off + seg > buf.len) break;
        const out = (try conn.pollDatagram(buf[off..][0..seg], now_us)) orelse break;
        const same_dest = destEql(batch.to, out.to);
        if (!same_dest) {
            // Different destination: hand it back as the carry; the
            // caller sends it separately. Zero copies — it is already
            // contiguous in `buf`.
            batch.carry_offset = off;
            batch.carry_len = out.len;
            batch.carry_to = out.to;
            break;
        }
        batch.total_len += out.len;
        batch.count += 1;
        if (out.len < seg) break; // short tail terminates the batch
    }
    return batch;
}

fn destEql(a: ?Address, b: ?Address) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return Address.eql(a.?, b.?);
}

/// Project a `std.Io.net.IpAddress` into quic's tagged-union
/// `path.Address`. The variants line up one-to-one, so this is a
/// straight copy. Used by `IngressIterator` and both bundled loops
/// (`udp_server.ipAddressToPathAddress` remains as a decl alias).
pub fn ipAddressToPathAddress(addr: Net.IpAddress) Address {
    return switch (addr) {
        .ip4 => |ip4| .{ .ipv4 = .{ .addr = ip4.bytes, .port = ip4.port } },
        .ip6 => |ip6| .{ .ipv6 = .{ .addr = ip6.bytes, .port = ip6.port, .flow = ip6.flow } },
    };
}

/// Which per-datagram ancillary features are active on the receiving
/// socket (see `socket_opts.negotiateUdpOffloads`): whether
/// `IngressIterator` parses ECN cmsgs, and whether it splits
/// GRO-coalesced buffers.
pub const IngressOptions = struct {
    /// Parse `IP_TOS` / `IPV6_TCLASS` cmsgs into per-datagram ECN
    /// codepoints; when inactive every datagram yields `.not_ect`.
    ecn_active: bool,
    /// Honor the kernel's `UDP_GRO` segment-size cmsg by splitting a
    /// coalesced buffer back into the original datagrams.
    gro_active: bool,
};

/// One QUIC datagram carved out of a received batch by
/// `IngressIterator` — already truncation-filtered, ECN-parsed,
/// address-converted, and GRO-split. Feed `data` / `from` / `ecn`
/// straight into `Server.feedWithEcn` / `Connection.handleWithEcn`.
pub const IngressDatagram = struct {
    /// Datagram payload (a sub-slice of the source message's buffer
    /// when GRO split it). Mutable because `Server.feed` /
    /// `Connection.handle` decrypt in place.
    data: []u8,
    /// Source address, converted to quic's `path.Address`.
    from: Address,
    /// ECN codepoint parsed once per source message (`.not_ect` when
    /// ECN is inactive or no TOS/TCLASS cmsg was present).
    ecn: EcnCodepoint,
    /// Index of the source `IncomingMessage` in the batch slice.
    msg_index: usize,
    /// True for the final datagram carved from its source message —
    /// the once-per-message hook point. `runUdpServer` stamps its
    /// listener routing here so a GRO-coalesced buffer costs ONE
    /// O(slots) scan, not one per split segment.
    last_in_message: bool,
};

/// Iterator over the QUIC datagrams contained in one batched-receive
/// result. Handles, in one place for both bundled loops (and for
/// foreign-loop embedders doing their own `recvmmsg`):
///
///   * skipping truncated messages (a truncated QUIC datagram is
///     useless);
///   * per-message ECN extraction from the cmsg control buffer;
///   * `IpAddress` -> `path.Address` conversion;
///   * GRO: splitting a kernel-coalesced buffer back into original
///     datagrams on the cmsg-reported stride (final segment may be
///     short) — QUIC coalescing rules apply per original datagram.
///
/// The caller supplies only its sink and error policy: the server
/// feeds each datagram (stamping once per message), the client
/// handles each datagram (returning early on handshake failure).
pub const IngressIterator = struct {
    msgs: []const Net.IncomingMessage,
    options: IngressOptions,
    /// Index into `msgs` of the next message to open.
    next_msg: usize = 0,
    /// GRO split in progress (`seg != 0`): per-message state carried
    /// across `next` calls while a coalesced buffer drains.
    cur: Split = .{},

    const Split = struct {
        data: []u8 = &.{},
        from: Address = .unspecified,
        ecn: EcnCodepoint = .not_ect,
        off: usize = 0,
        seg: usize = 0,
        index: usize = 0,
    };

    pub fn init(msgs: []const Net.IncomingMessage, options: IngressOptions) IngressIterator {
        return .{ .msgs = msgs, .options = options };
    }

    pub fn next(self: *IngressIterator) ?IngressDatagram {
        while (true) {
            // Drain an in-progress GRO split first.
            if (self.cur.seg != 0) {
                const end = @min(self.cur.off + self.cur.seg, self.cur.data.len);
                const last = end == self.cur.data.len;
                const out: IngressDatagram = .{
                    .data = self.cur.data[self.cur.off..end],
                    .from = self.cur.from,
                    .ecn = self.cur.ecn,
                    .msg_index = self.cur.index,
                    .last_in_message = last,
                };
                self.cur.off = end;
                if (last) self.cur.seg = 0;
                return out;
            }
            if (self.next_msg >= self.msgs.len) return null;
            const index = self.next_msg;
            self.next_msg += 1;
            const msg = &self.msgs[index];
            // A datagram that didn't fit its buffer arrives flagged
            // truncated — drop it whole.
            if (msg.flags.trunc) continue;
            const ecn: EcnCodepoint = if (self.options.ecn_active)
                socket_opts.parseEcnFromControl(msg.control)
            else
                .not_ect;
            const from = ipAddressToPathAddress(msg.from);
            // GRO: the kernel may hand us several original datagrams
            // coalesced into one buffer; the cmsg carries the split
            // stride.
            if (self.options.gro_active) {
                if (socket_opts.parseGroSegmentFromControl(msg.control)) |gro_seg| {
                    // A zero stride is a kernel/cmsg anomaly: without
                    // the guard the message would be swallowed whole
                    // (seg = 0 trips the in-progress-split drain guard
                    // below and the next() call skips past the already
                    // advanced message index). Fall through to the
                    // single-datagram return instead.
                    if (gro_seg != 0 and msg.data.len > gro_seg) {
                        self.cur = .{
                            .data = msg.data,
                            .from = from,
                            .ecn = ecn,
                            .seg = gro_seg,
                            .index = index,
                        };
                        continue;
                    }
                }
            }
            return .{
                .data = msg.data,
                .from = from,
                .ecn = ecn,
                .msg_index = index,
                .last_in_message = true,
            };
        }
    }
};

// -- tests -------------------------------------------------------------------

const testing = std.testing;
const boringssl = @import("boringssl");

// NOTE: construct Connections inline in each test — `Connection` is
// multiple megabytes by value (embedded sent-packet trackers), and an
// extra helper return hop overflows the test thread's stack.
// INTERNAL: pub for direct sibling import (egress.zig tests reuse the
// same queued-sender fixture for `drainGso`).
pub fn prepareSender(conn: *Connection) !void {
    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 21,
        .initial_max_stream_data_bidi_remote = 1 << 21,
        .initial_max_streams_bidi = 16,
    });
    try @import("../Connection/_test_util.zig").installTestApplicationWriteSecret(conn);
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_remote = 1 << 22,
    });
    // Plenty of window and no pacing: the batch fill itself is what's
    // under test.
    conn.ccForApplication().setCwndForTest(1 << 20);
    conn.pacing_enabled = false;
}

test "fillGsoBatch packs equal-size segments and stops on the short tail" {
    const allocator = testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareSender(conn);

    // Queue ~6 full packets of stream data plus a partial tail.
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const s = try conn.openBidi(0);
    var queued: usize = 0;
    while (queued < 7 * 1200) {
        queued += try s.send.write(data[0..@min(data.len, 7 * 1200 - queued)]);
    }

    var buf: [64 * 1500]u8 = undefined;
    const batch = try fillGsoBatch(conn, &buf, socket_opts.default_gso_max_segments, 1_000_000);
    try testing.expect(batch.count >= 2);
    try testing.expect(batch.seg_size > 0 and batch.seg_size <= conn.pmtu());
    // All middles are exactly seg_size; only the tail may be short:
    // total is (count-1) full segments plus a final in (0, seg].
    const full: usize = batch.seg_size * (batch.count - 1);
    try testing.expect(batch.total_len > full);
    try testing.expect(batch.total_len <= full + batch.seg_size);
    try testing.expect(!batch.hasCarry());

    // Draining the rest eventually returns an empty batch.
    var guard: u32 = 0;
    while (guard < 32) : (guard += 1) {
        const more = try fillGsoBatch(conn, &buf, socket_opts.default_gso_max_segments, 1_000_000);
        if (more.count == 0) break;
    }
    try testing.expect(guard < 32);
}

test "fillGsoBatch respects max_segments" {
    const allocator = testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareSender(conn);

    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const s = try conn.openBidi(0);
    var queued: usize = 0;
    while (queued < 10 * 1200) {
        queued += try s.send.write(data[0..@min(data.len, 10 * 1200 - queued)]);
    }

    var buf: [64 * 1500]u8 = undefined;
    const batch = try fillGsoBatch(conn, &buf, 3, 1_000_000);
    try testing.expect(batch.count <= 3);
    try testing.expect(batch.count >= 2);
}

test "fillGsoBatch on an idle connection returns an empty batch" {
    const allocator = testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareSender(conn);

    var buf: [4 * 1500]u8 = undefined;
    const batch = try fillGsoBatch(conn, &buf, 64, 1_000_000);
    try testing.expectEqual(@as(u32, 0), batch.count);
    try testing.expectEqual(@as(usize, 0), batch.total_len);
}

// -- IngressIterator ----------------------------------------------------------

const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const no_flags: Net.IncomingMessage.Flags = .{
    .eor = false,
    .trunc = false,
    .ctrunc = false,
    .oob = false,
    .errqueue = false,
};

const trunc_flags: Net.IncomingMessage.Flags = .{
    .eor = false,
    .trunc = true,
    .ctrunc = false,
    .oob = false,
    .errqueue = false,
};

const test_from: Net.IpAddress = .{ .ip4 = .{
    .bytes = .{ 127, 0, 0, 1 },
    .port = 9,
} };

test "IngressIterator skips truncated messages and converts the source address" {
    var d1 = [_]u8{ 1, 2, 3 };
    var d2 = [_]u8{ 4, 5 };
    const msgs = [_]Net.IncomingMessage{
        .{ .from = test_from, .data = &d1, .control = &.{}, .flags = trunc_flags },
        .{ .from = test_from, .data = &d2, .control = &.{}, .flags = no_flags },
    };
    var it: IngressIterator = .init(&msgs, .{ .ecn_active = false, .gro_active = false });
    const first = it.next().?;
    try testing.expectEqualSlices(u8, &d2, first.data);
    try testing.expectEqual(@as(usize, 1), first.msg_index);
    try testing.expect(first.last_in_message);
    try testing.expectEqual(EcnCodepoint.not_ect, first.ecn);
    try testing.expect(first.from == .ipv4);
    try testing.expectEqual(@as(u16, 9), first.from.ipv4.port);
    try testing.expect(it.next() == null);
}

test "IngressIterator splits a GRO-coalesced buffer on the cmsg stride" {
    if (comptime @typeInfo(std.c.cmsghdr) != .@"struct") return error.SkipZigTest;
    var control: [64]u8 = undefined;
    var seg: [4]u8 = undefined;
    std.mem.writeInt(i32, &seg, 4, native_endian);
    const n = socket_opts.writeCmsg(&control, socket_opts.sol_udp, socket_opts.udp_gro, &seg);

    // 10 bytes on a stride of 4: three original datagrams, short tail.
    var data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const msgs = [_]Net.IncomingMessage{
        .{ .from = test_from, .data = &data, .control = control[0..n], .flags = no_flags },
    };
    var it: IngressIterator = .init(&msgs, .{ .ecn_active = false, .gro_active = true });

    const a = it.next().?;
    try testing.expectEqualSlices(u8, data[0..4], a.data);
    try testing.expect(!a.last_in_message);
    const b = it.next().?;
    try testing.expectEqualSlices(u8, data[4..8], b.data);
    try testing.expect(!b.last_in_message);
    const c = it.next().?;
    try testing.expectEqualSlices(u8, data[8..10], c.data);
    try testing.expect(c.last_in_message);
    try testing.expectEqual(@as(usize, 0), c.msg_index);
    try testing.expect(it.next() == null);
}

test "IngressIterator: a buffer no longer than the stride passes through unsplit" {
    if (comptime @typeInfo(std.c.cmsghdr) != .@"struct") return error.SkipZigTest;
    var control: [64]u8 = undefined;
    var seg: [4]u8 = undefined;
    std.mem.writeInt(i32, &seg, 4, native_endian);
    const n = socket_opts.writeCmsg(&control, socket_opts.sol_udp, socket_opts.udp_gro, &seg);

    // data.len == gro_seg: exactly one original datagram, no split.
    var data = [_]u8{ 9, 8, 7, 6 };
    const msgs = [_]Net.IncomingMessage{
        .{ .from = test_from, .data = &data, .control = control[0..n], .flags = no_flags },
    };
    var it: IngressIterator = .init(&msgs, .{ .ecn_active = false, .gro_active = true });
    const only = it.next().?;
    try testing.expectEqualSlices(u8, &data, only.data);
    try testing.expect(only.last_in_message);
    try testing.expect(it.next() == null);
}

test "IngressIterator parses ECN once per message and applies it to every split segment" {
    if (comptime !(builtin.os.tag == .linux or builtin.os.tag.isDarwin())) return error.SkipZigTest;
    // Kernel-realistic control buffer for a coalesced ECN-marked
    // receive: an IP_TOS cmsg (ECT(0)) followed by the UDP_GRO
    // segment-size cmsg.
    var control: [128]u8 = undefined;
    const first = socket_opts.writeCmsg(
        &control,
        @intCast(socket_opts.ip_consts.ip_proto),
        @intCast(socket_opts.ip_consts.ip_tos),
        &.{0x02},
    );
    var seg: [4]u8 = undefined;
    std.mem.writeInt(i32, &seg, 3, native_endian);
    const second = socket_opts.writeCmsg(
        control[first..],
        socket_opts.sol_udp,
        socket_opts.udp_gro,
        &seg,
    );

    var data = [_]u8{ 0, 1, 2, 3, 4, 5 };
    const msgs = [_]Net.IncomingMessage{
        .{
            .from = test_from,
            .data = &data,
            .control = control[0 .. first + second],
            .flags = no_flags,
        },
    };
    var it: IngressIterator = .init(&msgs, .{ .ecn_active = true, .gro_active = true });
    var count: usize = 0;
    while (it.next()) |d| {
        try testing.expectEqual(EcnCodepoint.ect0, d.ecn);
        try testing.expectEqual(@as(usize, 3), d.data.len);
        count += 1;
    }
    try testing.expectEqual(@as(usize, 2), count);
}

test "IngressIterator yields an empty datagram for an empty message" {
    const msgs = [_]Net.IncomingMessage{
        .{ .from = test_from, .data = &.{}, .control = &.{}, .flags = no_flags },
    };
    var it: IngressIterator = .init(&msgs, .{ .ecn_active = false, .gro_active = false });
    const only = it.next().?;
    try testing.expectEqual(@as(usize, 0), only.data.len);
    try testing.expect(only.last_in_message);
    try testing.expect(it.next() == null);
}
