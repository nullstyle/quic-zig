//! A datagram that cannot be authenticated ends no connection.
//!
//! RFC 9000 section 12.2: a packet that cannot be processed is
//! discarded, and the packets behind it in the datagram are still
//! processed. A packet is authenticated by its AEAD tag and by nothing
//! before that: the header fields in front of the tag (the lengths of
//! the connection IDs, the token length, the Length field, the size of
//! the datagram) are what anyone wrote there.
//!
//! FOUND 2026-10-03: `Connection.handle` returned an error for a
//! header that did not parse (`error.ConnIdTooLong`,
//! `error.DeclaredLengthExceedsInput`, `error.PayloadTooShort`,
//! `error.InsufficientBytes`, `error.InsufficientCiphertext`). An
//! error out of `handle` is fatal to the connection by contract:
//! `Server.feed` closes the connection with INTERNAL_ERROR, and the
//! bundled client loop ends. So one datagram of 12 bytes with a
//! connection ID in it, from anyone who saw one packet of the
//! connection, ended the connection. So did a datagram cut short by a
//! receive buffer that was too small, and so did one flipped bit in a
//! length field.
//!
//! The interop runner's `handshakecorruption` test did not show this.
//! Its simulator changes one byte in the first 51 bytes of a datagram,
//! but (measured in the local runs of 2026-10-03) the changed datagram
//! does not reach the endpoint: neither our server's qlog nor the
//! quic-go client's log has a single packet that failed to decrypt in
//! a run with more than 300 corrupted datagrams. The UDP checksum
//! removes them first. To the endpoints that test is a loss test.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

/// The interop simulator corrupts one of the first 51 bytes.
const header_region: usize = 51;

/// A byte of a damaged copy is the byte of the datagram XORed with
/// one of these: every bit, the lowest bit, the "fixed" bit, and the
/// bit that makes a short header a long one (and the reverse).
const flips = [_]u8{ 0xff, 0x01, 0x40, 0x80 };

const Pair = struct {
    srv: quic.Server,
    cli: quic.Client,
    lb: quic.testing.Loopback,

    /// A server and a client with the handshake confirmed on both
    /// ends, in place (`lb` holds pointers to `srv` and `cli`).
    fn init(self: *Pair, allocator: std.mem.Allocator) !void {
        self.srv = try quic.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = common.test_cert_pem,
            .tls_key_pem = common.test_key_pem,
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
        });
        errdefer self.srv.deinit();
        self.cli = try quic.Client.connect(.{
            .insecure_skip_verify = true,
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
        });
        errdefer self.cli.deinit();
        self.lb = try quic.testing.Loopback.init(.{
            .allocator = allocator,
            .server = &self.srv,
            .client = &self.cli,
        });
        errdefer self.lb.deinit();

        const idle: quic.testing.NullDriver = .{};
        try self.lb.handshake(&idle);
        // Until the client has HANDSHAKE_DONE, and then until both
        // ends have nothing more to say (ACKs, new connection IDs).
        var steps: usize = 0;
        while (steps < 200 and !self.cli.conn.handshake_keys_discarded) : (steps += 1) try self.lb.step(&idle);
        try std.testing.expect(self.cli.conn.handshake_keys_discarded);
        for (0..50) |_| try self.lb.step(&idle);
    }

    fn deinit(self: *Pair) void {
        self.lb.deinit();
        self.cli.deinit();
        self.srv.deinit();
    }

    fn serverConn(self: *Pair) *quic.Connection {
        return self.srv.iterator()[0].conn;
    }

    fn expectBothOpen(self: *Pair) !void {
        try std.testing.expectEqual(@as(usize, 1), self.srv.iterator().len);
        try std.testing.expectEqual(quic.CloseState.open, self.serverConn().closeState());
        try std.testing.expectEqual(quic.CloseState.open, self.cli.conn.closeState());
    }
};

const Direction = enum { to_server, to_client };

/// Give one damaged copy of a datagram to its receiver. The receiver
/// must take it without an error and stay open.
fn deliverDamaged(pair: *Pair, direction: Direction, damaged: []u8) !void {
    switch (direction) {
        .to_server => {
            _ = try pair.srv.feed(damaged, quic.testing.loopback_addr, pair.lb.now_us);
            // A copy with a damaged connection ID is a datagram for no
            // connection; the server may answer it without state.
            while (pair.srv.drainStatelessResponse()) |_| {}
        },
        .to_client => try pair.cli.conn.handle(damaged, null, pair.lb.now_us),
    }
    try pair.expectBothOpen();
}

/// Every damaged copy of `datagram` that this file knows: each length
/// shorter than the datagram, and each byte of the header region
/// changed in each of the `flips` ways. Returns how many copies.
fn deliverEveryDamagedCopy(pair: *Pair, direction: Direction, datagram: []const u8) !usize {
    var copy: [4096]u8 = undefined;
    var copies: usize = 0;
    for (1..datagram.len) |len| {
        @memcpy(copy[0..len], datagram[0..len]);
        try deliverDamaged(pair, direction, copy[0..len]);
        copies += 1;
    }
    for (0..@min(header_region, datagram.len)) |offset| {
        for (flips) |flip| {
            @memcpy(copy[0..datagram.len], datagram);
            copy[offset] ^= flip;
            try deliverDamaged(pair, direction, copy[0..datagram.len]);
            copies += 1;
        }
    }
    return copies;
}

test "unauthenticated datagram: damaged copies of a 1-RTT packet end no open connection" {
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    try pair.init(allocator);
    defer pair.deinit();
    try pair.expectBothOpen();
    const idle: quic.testing.NullDriver = .{};

    // The client's next datagram: a 1-RTT packet with stream data.
    // The network holds it.
    const stream = try pair.cli.conn.openNextBidi();
    _ = try pair.cli.conn.streamWrite(stream.id, "hello");
    var from_client: [4096]u8 = undefined;
    const client_len = (try pair.cli.conn.poll(&from_client, pair.lb.now_us)) orelse return error.TestUnexpectedResult;
    try std.testing.expect((from_client[0] & 0x80) == 0);

    // Someone who saw that datagram sends damaged copies of it.
    const to_server = try deliverEveryDamagedCopy(&pair, .to_server, from_client[0..client_len]);
    try std.testing.expect(to_server > 100);

    // The real one arrives after them, and the connection works.
    _ = try pair.srv.feed(from_client[0..client_len], quic.testing.loopback_addr, pair.lb.now_us);
    var got: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try pair.serverConn().streamRead(stream.id, &got));
    try std.testing.expectEqualStrings("hello", got[0..5]);

    // The same from the server to the client. The server's first
    // datagram may be an ACK alone, so take the one with the answer.
    for (0..20) |_| try pair.lb.step(&idle);
    _ = try pair.serverConn().streamWrite(stream.id, "world");
    var from_server: [4096]u8 = undefined;
    const server_len = (try pair.serverConn().poll(&from_server, pair.lb.now_us)) orelse return error.TestUnexpectedResult;
    try std.testing.expect((from_server[0] & 0x80) == 0);

    const to_client = try deliverEveryDamagedCopy(&pair, .to_client, from_server[0..server_len]);
    try std.testing.expect(to_client > 100);

    try pair.cli.conn.handle(from_server[0..server_len], null, pair.lb.now_us);
    try std.testing.expectEqual(@as(usize, 5), try pair.cli.conn.streamRead(stream.id, &got));
    try std.testing.expectEqualStrings("world", got[0..5]);
    for (0..20) |_| try pair.lb.step(&idle);
    try pair.expectBothOpen();
}

test "unauthenticated datagram: a datagram too short to be a packet ends no open connection" {
    // The smallest attack: the first byte of a short header, the
    // connection ID, and not enough behind it to take the
    // header-protection sample from. `Server.feed` routes it to the
    // connection by its ID.
    const allocator = std.testing.allocator;
    var pair: Pair = undefined;
    try pair.init(allocator);
    defer pair.deinit();
    const idle: quic.testing.NullDriver = .{};

    const stream = try pair.cli.conn.openNextBidi();
    _ = try pair.cli.conn.streamWrite(stream.id, "a packet of some length");
    var real: [4096]u8 = undefined;
    const real_len = (try pair.cli.conn.poll(&real, pair.lb.now_us)) orelse return error.TestUnexpectedResult;
    try std.testing.expect((real[0] & 0x80) == 0);

    // The first byte, the connection ID, four bytes for the packet
    // number and the 16-byte sample (RFC 9001 section 5.4.2).
    const min_len: usize = 1 + @as(usize, pair.srv.local_cid_len) + 4 + 16;
    try std.testing.expect(real_len > min_len);

    var copy: [4096]u8 = undefined;
    for (1..min_len) |len| {
        @memcpy(copy[0..len], real[0..len]);
        _ = try pair.srv.feed(copy[0..len], quic.testing.loopback_addr, pair.lb.now_us);
        try pair.expectBothOpen();
    }
    // None of those reached the AEAD, so none is a forgery to count
    // against the integrity limit (RFC 9001 section 6.6). The first
    // length that does reach it is counted.
    try std.testing.expectEqual(@as(u64, 0), pair.serverConn().app_failed_auth_packets);
    @memcpy(copy[0..min_len], real[0..min_len]);
    _ = try pair.srv.feed(copy[0..min_len], quic.testing.loopback_addr, pair.lb.now_us);
    try pair.expectBothOpen();
    try std.testing.expectEqual(@as(u64, 1), pair.serverConn().app_failed_auth_packets);

    _ = try pair.srv.feed(real[0..real_len], quic.testing.loopback_addr, pair.lb.now_us);
    for (0..20) |_| try pair.lb.step(&idle);
    try pair.expectBothOpen();
}

/// A long-header packet of type `type_bits` (QUIC v1: 0 = Initial,
/// 1 = 0-RTT, 2 = Handshake) for the connection ID `dcid`, with a
/// payload that no key opens. Returns its length.
fn unopenablePacket(dst: []u8, type_bits: u8, dcid: []const u8) usize {
    var pos: usize = 0;
    dst[pos] = 0xc0 | (type_bits << 4);
    pos += 1;
    @memcpy(dst[pos..][0..4], &[_]u8{ 0, 0, 0, 1 });
    pos += 4;
    dst[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(dst[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    // No Source Connection ID.
    dst[pos] = 0;
    pos += 1;
    // An Initial packet has a token length: no token.
    if (type_bits == 0) {
        dst[pos] = 0;
        pos += 1;
    }
    // Length, as a two-byte varint: 1200 bytes of packet number and
    // payload. The server discards a datagram of less than 1200 bytes
    // that begins with an Initial packet before any connection sees
    // it (RFC 9000 section 14.1), so the packet is that large.
    const body: usize = 1200;
    dst[pos] = 0x40 | @as(u8, @intCast(body >> 8));
    dst[pos + 1] = @intCast(body & 0xff);
    pos += 2;
    @memset(dst[pos..][0..body], 0xa5);
    pos += body;
    return pos;
}

test "unauthenticated datagram: a packet that cannot be opened does not hide the packet behind it (RFC 9000 12.2)" {
    // "If decryption fails (because the keys are not available or for
    // any other reason), the receiver MAY either discard or buffer the
    // packet for subsequent processing and MUST attempt to process the
    // remaining packets."
    //
    // On an open connection the Initial and Handshake keys are gone. A
    // peer that still puts a packet of those levels in front of a
    // 1-RTT packet (a client that has not seen HANDSHAKE_DONE sends
    // its Finished that way) must not lose the 1-RTT packet.
    const allocator = std.testing.allocator;
    const idle: quic.testing.NullDriver = .{};
    for ([_]u8{ 0, 1, 2 }) |type_bits| {
        var pair: Pair = undefined;
        try pair.init(allocator);
        defer pair.deinit();

        // To the server: [a packet it cannot open][the 1-RTT packet
        // with "hello"], delivered once.
        const stream = try pair.cli.conn.openNextBidi();
        _ = try pair.cli.conn.streamWrite(stream.id, "hello");
        var real: [4096]u8 = undefined;
        const real_len = (try pair.cli.conn.poll(&real, pair.lb.now_us)) orelse return error.TestUnexpectedResult;
        try std.testing.expect((real[0] & 0x80) == 0);
        const server_cid_len: usize = pair.srv.local_cid_len;
        var both: [4096]u8 = undefined;
        var front = unopenablePacket(&both, type_bits, real[1..][0..server_cid_len]);
        @memcpy(both[front..][0..real_len], real[0..real_len]);
        _ = try pair.srv.feed(both[0 .. front + real_len], quic.testing.loopback_addr, pair.lb.now_us);
        try pair.expectBothOpen();
        var got: [16]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 5), try pair.serverConn().streamRead(stream.id, &got));
        try std.testing.expectEqualStrings("hello", got[0..5]);

        // To the client: the same, with the server's answer.
        for (0..20) |_| try pair.lb.step(&idle);
        _ = try pair.serverConn().streamWrite(stream.id, "world");
        const answer_len = (try pair.serverConn().poll(&real, pair.lb.now_us)) orelse return error.TestUnexpectedResult;
        try std.testing.expect((real[0] & 0x80) == 0);
        const client_cid_len: usize = pair.cli.conn.local_scid.len;
        front = unopenablePacket(&both, type_bits, real[1..][0..client_cid_len]);
        @memcpy(both[front..][0..answer_len], real[0..answer_len]);
        try pair.cli.conn.handle(both[0 .. front + answer_len], null, pair.lb.now_us);
        try pair.expectBothOpen();
        try std.testing.expectEqual(@as(usize, 5), try pair.cli.conn.streamRead(stream.id, &got));
        try std.testing.expectEqualStrings("world", got[0..5]);
    }
}
