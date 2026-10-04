// Loss recovery during the handshake: the early retransmission of
// unacknowledged CRYPTO data (RFC 9002 §6.2.3), the client's
// anti-deadlock probe (§6.2.2.1), and the client's backoff rule
// (§6.2.1). The end-to-end side of these rules, with a real handshake
// and a lossy network, is tests/e2e/handshake_loss.zig; the tests here
// hold each rule's edges one at a time, on a connection whose state is
// set by hand.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const conn_loss = @import("loss.zig");
const conn_keys = @import("keys.zig");
const Connection = state.Connection;
const EncryptionLevel = state.EncryptionLevel;
const SecretMaterial = state.SecretMaterial;
const TimerKind = state.TimerKind;

const start_us: u64 = 1_000_000;

/// Put one ack-eliciting packet with `text` as its CRYPTO data in
/// flight at `lvl`.
fn sendCrypto(conn: *Connection, lvl: EncryptionLevel, pn: u64, offset: u64, text: []const u8) !void {
    const bytes = try conn.allocator.dupe(u8, text);
    errdefer conn.allocator.free(bytes);
    try conn.sent_crypto[lvl.idx()].append(conn.allocator, .{
        .pn = pn,
        .offset = offset,
        .data = bytes,
    });
    try sendPing(conn, lvl, pn);
}

/// Put one ack-eliciting packet with no CRYPTO data (a PING probe) in
/// flight at `lvl`.
fn sendPing(conn: *Connection, lvl: EncryptionLevel, pn: u64) !void {
    try conn.sentForLevel(lvl).record(.{
        .pn = pn,
        .sent_time_us = start_us,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(lvl).next_pn = pn + 1;
}

/// The peer acknowledges packets 0 to `largest` at `lvl`.
fn ackThrough(conn: *Connection, lvl: EncryptionLevel, largest: u64, now_us: u64) !void {
    try conn.handleAckAtLevel(lvl, .{
        .largest_acked = largest,
        .ack_delay = 0,
        .first_range = largest,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, now_us);
}

/// Give the connection synthetic Handshake secrets, as the TLS stack
/// does when it has the ServerHello. No packet is sealed with them.
fn installHandshakeSecrets(conn: *Connection) void {
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    @memset(material.secret[0..32], 0x42);
    const idx = EncryptionLevel.handshake.idx();
    conn.levels[idx].read = material;
    conn.levels[idx].write = material;
}

fn newClient(ctx: *boringssl.tls.Context) !*Connection {
    return Connection.createClient(std.testing.allocator, ctx.*, "x");
}

// ------------------------------------------------ RFC 9002 §6.2.3

test "early retransmission: every unacknowledged CRYPTO byte of both handshake spaces goes back to the queue, and only that" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "server-hello");
    try sendCrypto(conn, .handshake, 0, 0, "certificate-part-1");
    try sendCrypto(conn, .handshake, 1, 18, "certificate-part-2");
    // A probe that carries no CRYPTO data stays where it is.
    try sendPing(conn, .handshake, 2);
    conn.pto_count = .{ 2, 1 };

    try conn_loss.retransmitHandshakeCryptoEarly(conn);

    const ini = EncryptionLevel.initial.idx();
    const hsk = EncryptionLevel.handshake.idx();
    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[ini].items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[hsk].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[ini].items.len);
    try std.testing.expectEqual(@as(usize, 2), conn.crypto_retx[hsk].items.len);
    // In the order of the stream, at the offsets they had.
    try std.testing.expectEqualStrings("server-hello", conn.crypto_retx[ini].items[0].data);
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_retx[hsk].items[0].offset);
    try std.testing.expectEqualStrings("certificate-part-1", conn.crypto_retx[hsk].items[0].data);
    try std.testing.expectEqual(@as(u64, 18), conn.crypto_retx[hsk].items[1].offset);
    try std.testing.expectEqualStrings("certificate-part-2", conn.crypto_retx[hsk].items[1].data);
    // The packets that carried the data are out of the tracker; the
    // probe is not.
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.initial).liveCount());
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.handshake).liveCount());
    // Not a probe timeout and not a loss: the backoff, the PING flags
    // and the loss counter are as they were.
    try std.testing.expectEqual([2]u32{ 2, 1 }, conn.pto_count);
    try std.testing.expectEqual([2]bool{ false, false }, conn.pending_ping);
    try std.testing.expectEqual(@as(u64, 0), conn.stats().packets_lost);
    try std.testing.expectEqual(@as(u8, 1), conn.early_handshake_retransmits);
    try std.testing.expect(conn.canSend());
}

test "early retransmission: a cue with nothing unacknowledged does nothing and uses up nothing" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();

    // The peer probes before our flight exists, or after it was
    // acknowledged. None of that counts against the limit.
    try sendPing(conn, .initial, 0);
    var i: usize = 0;
    while (i < 3 * @as(usize, conn_loss.max_early_handshake_retransmits)) : (i += 1) {
        try conn_loss.retransmitHandshakeCryptoEarly(conn);
    }
    try std.testing.expectEqual(@as(u8, 0), conn.early_handshake_retransmits);
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.initial).liveCount());

    // The limit is still whole when the flight is lost later.
    try sendCrypto(conn, .initial, 1, 0, "server-hello");
    try conn_loss.retransmitHandshakeCryptoEarly(conn);
    try std.testing.expectEqual(@as(u8, 1), conn.early_handshake_retransmits);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[EncryptionLevel.initial.idx()].items.len);
}

test "early retransmission: at most max_early_handshake_retransmits times for one connection" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();

    const ini = EncryptionLevel.initial.idx();
    var pn: u64 = 0;
    var round: usize = 0;
    while (round < conn_loss.max_early_handshake_retransmits) : (round += 1) {
        // The flight goes out (again), and the peer asks (again).
        try sendCrypto(conn, .initial, pn, 0, "server-hello");
        pn += 1;
        try conn_loss.retransmitHandshakeCryptoEarly(conn);
        try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[ini].items.len);
        // The send path would take the chunk from the queue here.
        const chunk = conn.crypto_retx[ini].orderedRemove(0);
        conn.allocator.free(chunk.data);
    }
    try std.testing.expectEqual(conn_loss.max_early_handshake_retransmits, conn.early_handshake_retransmits);

    // One more cue: the data stays with its packet, for the probe
    // timer.
    try sendCrypto(conn, .initial, pn, 0, "server-hello");
    try conn_loss.retransmitHandshakeCryptoEarly(conn);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_retx[ini].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.sent_crypto[ini].items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.initial).liveCount());
    try std.testing.expectEqual(conn_loss.max_early_handshake_retransmits, conn.early_handshake_retransmits);
}

test "early retransmission: a space whose keys are gone is left alone" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "server-hello");
    try sendCrypto(conn, .handshake, 0, 0, "certificate");
    conn.initial_keys_discarded = true;

    try conn_loss.retransmitHandshakeCryptoEarly(conn);

    try std.testing.expectEqual(@as(usize, 0), conn.crypto_retx[EncryptionLevel.initial.idx()].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[EncryptionLevel.handshake.idx()].items.len);
}

test "early retransmission: nothing on a connection that is closing" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "server-hello");
    // The only thing a closing connection sends is its
    // CONNECTION_CLOSE (RFC 9000 section 10.2.1).
    conn.close(true, 0x0a, "test");
    try conn_loss.retransmitHandshakeCryptoEarly(conn);

    const ini = EncryptionLevel.initial.idx();
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_retx[ini].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.sent_crypto[ini].items.len);
    try std.testing.expectEqual(@as(u8, 0), conn.early_handshake_retransmits);
}

test "discarding the keys of a space drops its queued and its unacknowledged CRYPTO data" {
    // CRYPTO data that waits for retransmission when its keys go can
    // never be sent. If it stayed in the queue, `canSend` would say
    // "yes" for the rest of the connection while `poll` gives nothing.
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try newClient(&ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "client-hello-part-1");
    try sendCrypto(conn, .initial, 1, 19, "client-hello-part-2");
    try sendCrypto(conn, .handshake, 0, 0, "finished");
    try sendCrypto(conn, .handshake, 1, 8, "never-acknowledged");
    try conn_loss.retransmitHandshakeCryptoEarly(conn);
    // One chunk of each space is in flight again, one still queued.
    try sendCrypto(conn, .initial, 2, 0, "client-hello-part-1");
    try sendCrypto(conn, .handshake, 2, 0, "finished");
    try std.testing.expect(conn.canSend());

    conn_keys.discardInitialKeys(conn);
    const ini = EncryptionLevel.initial.idx();
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_retx[ini].items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[ini].items.len);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.initial).liveCount());

    conn.discardHandshakeKeys();
    const hsk = EncryptionLevel.handshake.idx();
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_retx[hsk].items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[hsk].items.len);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.handshake).liveCount());

    try std.testing.expect(!conn.canSend());
}

// ---------------------------------------------- HANDSHAKE_DONE again

/// A server whose handshake is complete: HANDSHAKE_DONE was queued and
/// sent in 1-RTT packet 0, and the Handshake keys are discarded.
fn serverAfterHandshake(conn: *Connection) !void {
    conn.handshake_done_queued_once = true;
    conn.handshake_keys_discarded = true;
    var packet: state.SentPacketTracker.SentPacket = .{
        .pn = 0,
        .sent_time_us = start_us,
        .bytes = 30,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(conn.allocator, .{ .handshake_done = .{} });
    try conn.sentForLevel(.application).record(packet);
    conn.pnSpaceForLevel(.application).next_pn = 1;
}

test "HANDSHAKE_DONE again: a late Handshake packet queues it, once per cue, up to the limit" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();
    try serverAfterHandshake(conn);
    try std.testing.expect(!conn.pending_handshake_done);

    conn_loss.resendHandshakeDoneEarly(conn);
    try std.testing.expect(conn.pending_handshake_done);
    try std.testing.expectEqual(@as(u8, 1), conn.early_handshake_done_resends);

    // A second cue before the frame went out queues nothing more and
    // uses up nothing.
    conn_loss.resendHandshakeDoneEarly(conn);
    try std.testing.expectEqual(@as(u8, 1), conn.early_handshake_done_resends);

    // The send path takes the frame; the next cue queues it again,
    // until the limit.
    var round: usize = 1;
    while (round < conn_loss.max_early_handshake_retransmits) : (round += 1) {
        conn.pending_handshake_done = false;
        conn_loss.resendHandshakeDoneEarly(conn);
        try std.testing.expect(conn.pending_handshake_done);
    }
    try std.testing.expectEqual(conn_loss.max_early_handshake_retransmits, conn.early_handshake_done_resends);
    conn.pending_handshake_done = false;
    conn_loss.resendHandshakeDoneEarly(conn);
    try std.testing.expect(!conn.pending_handshake_done);
    try std.testing.expectEqual(conn_loss.max_early_handshake_retransmits, conn.early_handshake_done_resends);
}

test "HANDSHAKE_DONE again: not after the client acknowledged it" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();
    try serverAfterHandshake(conn);
    try std.testing.expect(!conn.handshake_done_acked);

    try ackThrough(conn, .application, 0, start_us + 10_000);
    try std.testing.expect(conn.handshake_done_acked);

    conn_loss.resendHandshakeDoneEarly(conn);
    try std.testing.expect(!conn.pending_handshake_done);
    try std.testing.expectEqual(@as(u8, 0), conn.early_handshake_done_resends);
}

test "HANDSHAKE_DONE again: only a server, only after its first HANDSHAKE_DONE, only with the keys gone, never when closing" {
    const Case = enum { ok, client, before_first, keys_still_there, closing };
    for ([_]Case{ .ok, .client, .before_first, .keys_still_there, .closing }) |case| {
        var server_ctx = try boringssl.tls.Context.initServer(.{});
        defer server_ctx.deinit();
        var client_ctx = try boringssl.tls.Context.initClient(.{});
        defer client_ctx.deinit();
        const conn = if (case == .client)
            try newClient(&client_ctx)
        else
            try Connection.createServer(std.testing.allocator, server_ctx);
        defer conn.destroy();

        try serverAfterHandshake(conn);
        switch (case) {
            .ok, .client => {},
            .before_first => conn.handshake_done_queued_once = false,
            .keys_still_there => conn.handshake_keys_discarded = false,
            .closing => conn.close(true, 0x0a, "test"),
        }
        conn_loss.resendHandshakeDoneEarly(conn);
        try std.testing.expectEqual(case == .ok, conn.pending_handshake_done);
        try std.testing.expectEqual(@as(u8, if (case == .ok) 1 else 0), conn.early_handshake_done_resends);
    }
}

// ------------------------------------------- RFC 9002 §6.2.2.1, §6.2.1

test "anti-deadlock: a client with nothing in flight probes at the Initial level until it has Handshake keys" {
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try newClient(&ctx);
    defer conn.destroy();

    // Before anything was acknowledged there is no probe to owe: the
    // ClientHello is in flight and the normal probe timer runs.
    try std.testing.expectEqual(@as(?EncryptionLevel, .initial), conn_loss.antiDeadlockLevel(conn));
    try std.testing.expect(conn_loss.ptoDeadlineForLevel(conn, .initial) == null);

    try sendCrypto(conn, .initial, 0, 0, "client-hello");
    try std.testing.expect(conn_loss.antiDeadlockLevel(conn) == null);
    const hello_deadline = conn_loss.ptoDeadlineForLevel(conn, .initial).?;
    try std.testing.expectEqual(start_us + conn.ptoDurationForLevel(.initial), hello_deadline);

    // The server acknowledges the ClientHello and sends nothing else
    // (it is at its anti-amplification limit, or its flight was lost).
    const ack_us = start_us + 10_000;
    try ackThrough(conn, .initial, 0, ack_us);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.initial).liveCount());
    try std.testing.expectEqual(@as(?EncryptionLevel, .initial), conn_loss.antiDeadlockLevel(conn));

    // The probe timer runs from the ACK.
    const pto_us = conn.ptoDurationForLevel(.initial);
    const deadline = conn.nextTimerDeadline(ack_us).?;
    try std.testing.expectEqual(TimerKind.pto, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.initial, deadline.level.?);
    try std.testing.expectEqual(ack_us + pto_us, deadline.at_us);

    // Not before the deadline.
    try conn.tick(deadline.at_us - 1);
    try std.testing.expect(!conn.pending_ping[0]);
    try std.testing.expectEqual(@as(u32, 0), conn.pto_count[0]);

    // At the deadline: a PING at the Initial level, and the backoff
    // doubles the next wait.
    try conn.tick(deadline.at_us);
    try std.testing.expect(conn.pending_ping[0]);
    try std.testing.expect(!conn.pending_ping[1]);
    try std.testing.expectEqual(@as(u32, 1), conn.pto_count[0]);
    try std.testing.expectEqual(deadline.at_us + 2 * pto_us, conn_loss.ptoDeadlineForLevel(conn, .initial).?);
}

test "anti-deadlock: an ACK in an Initial packet does not reset a client's backoff, and it does reset a server's" {
    var client_ctx = try boringssl.tls.Context.initClient(.{});
    defer client_ctx.deinit();
    const client = try newClient(&client_ctx);
    defer client.destroy();
    try sendPing(client, .initial, 0);
    client.pto_count[0] = 3;
    try ackThrough(client, .initial, 0, start_us + 10_000);
    try std.testing.expectEqual(@as(u32, 3), client.pto_count[0]);
    // In a Handshake packet it does: the server has validated the
    // client's address when it can send one.
    try sendPing(client, .handshake, 0);
    client.pto_count[1] = 2;
    try ackThrough(client, .handshake, 0, start_us + 20_000);
    try std.testing.expectEqual(@as(u32, 0), client.pto_count[1]);

    var server_ctx = try boringssl.tls.Context.initServer(.{});
    defer server_ctx.deinit();
    const server = try Connection.createServer(std.testing.allocator, server_ctx);
    defer server.destroy();
    try sendPing(server, .initial, 0);
    server.pto_count[0] = 3;
    try ackThrough(server, .initial, 0, start_us + 10_000);
    try std.testing.expectEqual(@as(u32, 0), server.pto_count[0]);
}

test "anti-deadlock: with Handshake keys the probe is a Handshake packet, and an ACK in a Handshake packet ends the probes" {
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try newClient(&ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "client-hello");
    const ack_us = start_us + 10_000;
    try ackThrough(conn, .initial, 0, ack_us);
    installHandshakeSecrets(conn);
    try std.testing.expectEqual(@as(?EncryptionLevel, .handshake), conn_loss.antiDeadlockLevel(conn));
    try std.testing.expect(conn_loss.ptoDeadlineForLevel(conn, .initial) == null);
    const deadline = conn_loss.ptoDeadlineForLevel(conn, .handshake).?;
    try std.testing.expectEqual(ack_us + conn.ptoDurationForLevel(.handshake), deadline);

    try conn.tick(deadline);
    try std.testing.expect(conn.pending_ping[1]);
    try std.testing.expect(!conn.pending_ping[0]);
    try std.testing.expectEqual(@as(u32, 1), conn.pto_count[1]);

    // The probe goes out and the server acknowledges it in a Handshake
    // packet: the server has validated our address. No more probes.
    conn.pending_ping[1] = false;
    try sendPing(conn, .handshake, 0);
    try std.testing.expect(conn_loss.antiDeadlockLevel(conn) == null);
    try ackThrough(conn, .handshake, 0, deadline + 10_000);
    try std.testing.expect(conn.received_handshake_ack);
    try std.testing.expect(conn_loss.antiDeadlockLevel(conn) == null);
    try std.testing.expect(conn_loss.ptoDeadlineForLevel(conn, .handshake) == null);
    try std.testing.expect(conn_loss.ptoDeadlineForLevel(conn, .initial) == null);
}

test "anti-deadlock: a packet in flight in either handshake space is the normal probe timer's business" {
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try newClient(&ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "client-hello");
    try ackThrough(conn, .initial, 0, start_us + 10_000);
    installHandshakeSecrets(conn);
    try std.testing.expectEqual(@as(?EncryptionLevel, .handshake), conn_loss.antiDeadlockLevel(conn));

    // A probe at the Initial level is still in flight: no second timer
    // at the Handshake level.
    try sendPing(conn, .initial, 1);
    try std.testing.expect(conn_loss.antiDeadlockLevel(conn) == null);
    try std.testing.expect(conn_loss.ptoDeadlineForLevel(conn, .handshake) == null);
}

test "anti-deadlock: a server never owes a probe" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "server-hello");
    const ack_us = start_us + 10_000;
    try ackThrough(conn, .initial, 0, ack_us);
    try std.testing.expect(conn_loss.antiDeadlockLevel(conn) == null);
    try std.testing.expect(conn_loss.ptoDeadlineForLevel(conn, .initial) == null);
    try std.testing.expect(conn_loss.ptoDeadlineForLevel(conn, .handshake) == null);
    try conn.tick(ack_us + 60 * 1_000_000);
    try std.testing.expectEqual([2]bool{ false, false }, conn.pending_ping);
    try std.testing.expectEqual([2]u32{ 0, 0 }, conn.pto_count);
}

test "anti-deadlock: no probe once the handshake is confirmed" {
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try newClient(&ctx);
    defer conn.destroy();

    try sendCrypto(conn, .initial, 0, 0, "client-hello");
    try ackThrough(conn, .initial, 0, start_us + 10_000);
    installHandshakeSecrets(conn);
    try std.testing.expectEqual(@as(?EncryptionLevel, .handshake), conn_loss.antiDeadlockLevel(conn));

    conn_keys.discardInitialKeys(conn);
    conn.discardHandshakeKeys();
    try std.testing.expect(conn_loss.antiDeadlockLevel(conn) == null);
}
