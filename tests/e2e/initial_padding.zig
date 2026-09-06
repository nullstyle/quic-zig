//! RFC 9000 §14.1: a client MUST expand every UDP datagram that carries an
//! Initial packet to at least 1200 bytes, ACK-only Initials included. A
//! server MUST drop smaller ones (`Server.feed` does), so an unpadded
//! ACK-only Initial leaves the server waiting for its probe timeouts before
//! it can finish its own first flight. Against a real network peer that cost
//! about two seconds per handshake; loopback hid it because the server's
//! whole flight fit in one datagram and the client's next Initial coalesced
//! with ack-eliciting Handshake data.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

/// A certificate wide enough that the server's Initial + Handshake flight
/// needs two datagrams, so the client acknowledges the first one before it
/// has anything to send at the Handshake level: an ACK-only Initial on its
/// own, exactly the datagram the rule under test is about.
const wide_cert_pem = @embedFile("../data/test_cert_wide.pem");
const wide_key_pem = @embedFile("../data/test_key_wide_cert.pem");

/// True when the leading packet is a QUIC v1 long-header Initial
/// (form bit set, type bits 00), which is what `Server.feed` inspects.
fn leadsWithInitial(datagram: []const u8) bool {
    if (datagram.len == 0) return false;
    const first = datagram[0];
    return (first & 0x80) != 0 and (first & 0x30) == 0x00;
}

test "client pads every datagram that leads with an Initial packet to 1200 bytes" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = wide_cert_pem,
        .tls_key_pem = wide_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();

    // Loopback.handshake, unrolled so every client datagram is inspected
    // before the server sees it, and so the server's flight arrives one
    // datagram at a time with the client answering in between: a network
    // delivers it that way, and the answer to the first datagram is an
    // ACK-only Initial with nothing yet to say at the Handshake level.
    // Feeding the server keeps the rule under test honest: a short
    // Initial-leading datagram is dropped there.
    try cli.conn.advance();
    var initial_datagrams: usize = 0;
    var ack_only_initials: usize = 0;
    var steps: usize = 0;
    while (steps < 64) : (steps += 1) {
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and srv.iterator()[0].conn.handshakeDone()) break;
        try pumpClient(&cli, &srv, &lb, &initial_datagrams, &ack_only_initials);
        var flight: [8][4096]u8 = undefined;
        var lens: [8]usize = undefined;
        var count: usize = 0;
        for (srv.iterator()) |slot| {
            while (count < flight.len) {
                const len = (try slot.conn.poll(flight[count][0..], lb.now_us)) orelse break;
                lens[count] = len;
                count += 1;
            }
        }
        while (srv.drainStatelessResponse()) |_| {}
        for (0..count) |i| {
            try cli.conn.handle(flight[i][0..lens[i]], null, lb.now_us);
            try pumpClient(&cli, &srv, &lb, &initial_datagrams, &ack_only_initials);
        }
        try srv.tick(lb.now_us);
        try cli.conn.tick(lb.now_us);
        lb.now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());
    try std.testing.expect(initial_datagrams >= 2);
    try std.testing.expect(ack_only_initials >= 1);
}

/// Client → server, checking each datagram before the server sees it.
fn pumpClient(cli: *quic.Client, srv: *quic.Server, lb: *quic.testing.Loopback, initial_datagrams: *usize, ack_only_initials: *usize) !void {
    while (try cli.conn.poll(lb.rx, lb.now_us)) |len| {
        const datagram = lb.rx[0..len];
        if (leadsWithInitial(datagram)) {
            initial_datagrams.* += 1;
            // After the first flight, an Initial from the client only
            // acknowledges the server's Initial.
            if (initial_datagrams.* > 1) ack_only_initials.* += 1;
            try std.testing.expect(len >= 1200);
        }
        _ = try srv.feed(datagram, quic.testing.loopback_addr, lb.now_us);
    }
}
