//! Rendezvous front end — prototype #1 of the durable-capabilities
//! resolution ladder (QUIC only, no capnp).
//!
//! The mechanic under test: a host mints a provision ticket carrying a
//! DICTATED initial DCID plus a nonce, and hands it to a third party
//! out-of-band. The third party dials the host using exactly that DCID
//! (`Client.Config.initial_dcid`). The host's front end peeks the
//! version-invariant long-header DCID (RFC 8999 §5.1) BEFORE the
//! server touches the datagram — no decryption — and routes the
//! handshake to the pending provision. The nonce then arrives in-TLS
//! on the routed connection and confirms the claim.
//!
//! The claim/confirm split carries the design's governing invariant.
//! A CLAIM happens at accept time on plaintext-observable data (the
//! DCID) and is therefore only ever ROUTING — anyone who learns the
//! DCID can trigger it, since Initial packet protection derives from
//! the DCID and hides nothing. CONFIRMATION is the authorization
//! step: the dialer must present the ticket nonce inside the
//! TLS-protected channel (1-RTT application data here), compared in
//! constant time against the claimed provision. A deployment pins
//! the host's identity (certificate/vat key) so the nonce cannot be
//! harvested by a TLS-terminating impostor; this test uses a
//! self-signed fixture and `insecure_skip_verify` instead.
//!
//! Five properties pinned here:
//!   1. A dictated-DCID dial is claimed by its pending provision,
//!      the claim binds to the accepted slot, and the nonce confirms
//!      it — routing by DCID, authorization by crypto.
//!   2. A dial with a random DCID claims nothing and is accepted
//!      through the ordinary path — the front end is a pass-through
//!      for non-provisioned traffic.
//!   3. Claims are single-use: re-dialing a spent DCID routes
//!      ordinarily and never rebinds the provision (the anti-replay
//!      answer for the front end is a single-use table).
//!   4. A wrong nonce never confirms a claim — the DCID alone
//!      authorizes nothing.
//!   5. KNOWN LIMITATION, pinned deliberately: with Retry enabled
//!      the claim silently MISSES, because the post-Retry Initial
//!      carries the server-minted Retry SCID as its DCID, not the
//!      dictated value. A production front end must either not
//!      Retry provision dials or recover the ODCID from its own
//!      Retry token; this toy does neither.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

/// One pending provision at the front end: the dictated initial DCID
/// minted into the ticket, and the nonce the dialer must present
/// in-TLS to confirm the claim. Single-use by construction.
const Provision = struct {
    dcid: [20]u8 = @splat(0),
    dcid_len: u8 = 0,
    nonce: [16]u8 = @splat(0),
    /// Latched by the first Initial that opens a connection with this
    /// DCID; never cleared. Routing state only — see `confirmed`.
    claimed: bool = false,
    /// Set only by `FrontEnd.confirmClaim` when the bound connection
    /// presents the correct nonce. This, not `claimed`, is the
    /// authorization bit.
    confirmed: bool = false,
    /// `Slot.slot_id` of the connection the claim bound to.
    bound_slot_id: ?u64 = null,

    fn dcidSlice(self: *const Provision) []const u8 {
        return self.dcid[0..self.dcid_len];
    }
};

/// The toy front end: a fixed pending-provision table plus a feed
/// wrapper. Expiry and per-source budgets layer on the same two
/// seams used here (the pre-decrypt DCID peek and the `.accepted`
/// binding). Retry does NOT layer on: a Retry rewrites the wire
/// DCID, so the peek seam misses post-Retry Initials — see property
/// 5 in the file docstring.
const FrontEnd = struct {
    provisions: [4]Provision = @splat(.{}),
    count: usize = 0,

    fn register(self: *FrontEnd, dcid: []const u8, nonce: [16]u8) *Provision {
        const slot = &self.provisions[self.count];
        self.count += 1;
        slot.* = .{ .nonce = nonce, .dcid_len = @intCast(dcid.len) };
        @memcpy(slot.dcid[0..dcid.len], dcid);
        return slot;
    }

    /// A provision matches only while unclaimed — the single-use rule.
    fn matchPending(self: *FrontEnd, dcid: []const u8) ?*Provision {
        for (self.provisions[0..self.count]) |*prov| {
            if (!prov.claimed and std.mem.eql(u8, prov.dcidSlice(), dcid)) return prov;
        }
        return null;
    }

    /// The authorization step. A claim is only routing until the
    /// bound connection presents the ticket nonce inside TLS;
    /// constant-time compare, and a wrong nonce never confirms.
    /// The provision stays spent either way — after a failed
    /// confirm the ticket minter issues a fresh ticket rather than
    /// reopening this one.
    fn confirmClaim(
        self: *FrontEnd,
        prov: *Provision,
        slot_id: u64,
        presented: [16]u8,
    ) bool {
        _ = self;
        if (!prov.claimed) return false;
        if (prov.bound_slot_id != slot_id) return false;
        if (!std.crypto.timing_safe.eql([16]u8, prov.nonce, presented)) return false;
        prov.confirmed = true;
        return true;
    }

    /// The routing seam: peek the long-header DCID pre-decrypt, feed
    /// the server, and on `.accepted` bind a matching pending
    /// provision to the new slot. Short-header traffic never carries
    /// an explicit DCID length and belongs to established
    /// connections, so it can never claim a provision.
    fn feed(
        self: *FrontEnd,
        srv: *quic.Server,
        // Mutable because `Server.feed` unmasks header protection in
        // place; the pre-decrypt peek itself only reads.
        datagram: []u8,
        addr: quic.conn.path.Address,
        now_us: u64,
    ) !quic.Server.FeedOutcome {
        var matched: ?*Provision = null;
        if (datagram.len > 0 and (datagram[0] & 0x80) != 0) {
            if (quic.wire.header.peekLongCommon(datagram)) |hdr| {
                matched = self.matchPending(hdr.dcid);
            } else |_| {}
        }
        const outcome = try srv.feed(datagram, addr, now_us);
        if (outcome == .accepted) {
            if (matched) |prov| {
                const slot = srv.iterator()[srv.iterator().len - 1];
                // The routing invariant: the slot's recorded initial
                // DCID is byte-for-byte the dictated one.
                std.debug.assert(std.mem.eql(u8, slot.initial_dcid.slice(), prov.dcidSlice()));
                prov.claimed = true;
                prov.bound_slot_id = slot.slot_id;
            }
        }
        return outcome;
    }
};

fn pumpClientToServer(
    fe: *FrontEnd,
    cli: *quic.Client,
    srv: *quic.Server,
    rx: []u8,
    addr: quic.conn.path.Address,
    now_us: u64,
) !void {
    while (try cli.conn.poll(rx, now_us)) |len| {
        _ = try fe.feed(srv, rx[0..len], addr, now_us);
    }
}

fn pumpServerToClient(
    srv: *quic.Server,
    cli: *quic.Client,
    rx: []u8,
    now_us: u64,
) !void {
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(rx, now_us)) |len| {
            try cli.conn.handle(rx[0..len], null, now_us);
        }
    }
}

fn findSlot(srv: *quic.Server, slot_id: u64) ?*quic.Server.Slot {
    for (srv.iterator()) |slot| {
        if (slot.slot_id == slot_id) return slot;
    }
    return null;
}

fn serverHandshakeDone(srv: *quic.Server) bool {
    if (srv.iterator().len == 0) return false;
    for (srv.iterator()) |slot| {
        if (!slot.conn.handshakeDone()) return false;
    }
    return true;
}

/// Drive one client/server pair to handshake completion — BOTH
/// sides, so a subsequent close/teardown starts from a settled
/// connection — through the front end. Returns the wall clock after
/// the last step.
fn handshake(
    fe: *FrontEnd,
    cli: *quic.Client,
    srv: *quic.Server,
    addr: quic.conn.path.Address,
    start_us: u64,
) !u64 {
    var rx: [4096]u8 = undefined;
    var now_us = start_us;
    var step: u32 = 0;
    while (step < 64 and
        !(cli.conn.handshakeDone() and serverHandshakeDone(srv))) : (step += 1)
    {
        try pumpClientToServer(fe, cli, srv, &rx, addr, now_us);
        // Deliver stateless responses (Retry, VN) to the client
        // instead of discarding them, so Retry-gated servers can
        // complete a handshake through this harness.
        while (srv.drainStatelessResponse()) |resp| {
            var resp_copy = resp;
            try cli.conn.handle(resp_copy.bytes[0..resp_copy.len], null, now_us);
        }
        try pumpServerToClient(srv, cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(serverHandshakeDone(srv));
    return now_us;
}

/// Close `cli` and pump until the server has reaped its slot.
fn teardown(
    fe: *FrontEnd,
    cli: *quic.Client,
    srv: *quic.Server,
    addr: quic.conn.path.Address,
    start_us: u64,
) !u64 {
    var rx: [4096]u8 = undefined;
    var now_us = start_us;
    cli.conn.close(false, 0, "done");
    var step: u32 = 0;
    while (step < 32 and srv.connectionCount() > 0) : (step += 1) {
        try pumpClientToServer(fe, cli, srv, &rx, addr, now_us);
        try pumpServerToClient(srv, cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        _ = srv.reap();
        now_us += 500_000;
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    return now_us;
}

test "rendezvous: dictated-DCID dial claims its provision and the in-TLS nonce confirms it" {
    const allocator = std.testing.allocator;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    // The host side of the provision ticket: dictated DCID + nonce.
    // 8 bytes keeps the DCID inside the Retry-token plaintext budget
    // should a deployment enable Retry in front of this.
    var fe: FrontEnd = .{};
    const ticket_dcid = [_]u8{ 0xC1, 0xD2, 0xE3, 0xF4, 0x05, 0x16, 0x27, 0x38 };
    const ticket_nonce: [16]u8 = @splat(0x5A);
    const prov = fe.register(&ticket_dcid, ticket_nonce);

    // The dialing side: connect with exactly the dictated bytes.
    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .initial_dcid = &ticket_dcid,
    });
    defer cli.deinit();
    try std.testing.expectEqualSlices(u8, &ticket_dcid, cli.conn.initial_dcid.slice());

    try cli.conn.advance();
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x11), .port = 1111 } };
    var now_us = try handshake(&fe, &cli, &srv, addr, 1_000);

    // Routing held: the provision is claimed and bound to the slot
    // that owns the dictated DCID.
    try std.testing.expect(prov.claimed);
    const slot = findSlot(&srv, prov.bound_slot_id.?) orelse return error.BoundSlotMissing;
    try std.testing.expectEqualSlices(u8, &ticket_dcid, slot.initial_dcid.slice());

    // Authorization is crypto, not the CID: the nonce arrives in-TLS
    // on the routed connection and matches the provision.
    _ = try cli.conn.openBidi(0);
    _ = try cli.conn.streamWrite(0, &ticket_nonce);
    try cli.conn.streamFinish(0);

    var rx: [4096]u8 = undefined;
    var got_nonce: [16]u8 = undefined;
    var nonce_read: usize = 0;
    var step: u32 = 0;
    while (step < 48 and nonce_read < got_nonce.len) : (step += 1) {
        try pumpClientToServer(&fe, &cli, &srv, &rx, addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        while (true) {
            const got = slot.conn.streamRead(0, got_nonce[nonce_read..]) catch break;
            if (got == 0) break;
            nonce_read += got;
        }
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
    }
    try std.testing.expectEqual(got_nonce.len, nonce_read);

    // The authorization step: the front end confirms the claim only
    // for the bound slot presenting the correct nonce.
    try std.testing.expect(fe.confirmClaim(prov, slot.slot_id, got_nonce));
    try std.testing.expect(prov.confirmed);
}

test "rendezvous: a random-DCID dial claims nothing and routes ordinarily" {
    const allocator = std.testing.allocator;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var fe: FrontEnd = .{};
    const ticket_dcid = [_]u8{ 0xC1, 0xD2, 0xE3, 0xF4, 0x05, 0x16, 0x27, 0x38 };
    const prov = fe.register(&ticket_dcid, @splat(0x5A));

    // No `initial_dcid`: the ordinary random mint. A random 8-byte
    // collision with the registered DCID is 2^-64 — ignored.
    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    try cli.conn.advance();
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2222 } };
    _ = try handshake(&fe, &cli, &srv, addr, 1_000);

    // Accepted through the ordinary path; the provision is untouched.
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(!prov.claimed);
    try std.testing.expectEqual(@as(?u64, null), prov.bound_slot_id);
}

test "rendezvous: claims are single-use — a replayed dictated DCID never rebinds" {
    const allocator = std.testing.allocator;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var fe: FrontEnd = .{};
    const ticket_dcid = [_]u8{ 0xC1, 0xD2, 0xE3, 0xF4, 0x05, 0x16, 0x27, 0x38 };
    const prov = fe.register(&ticket_dcid, @splat(0x5A));

    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x33), .port = 3333 } };
    var first_slot_id: u64 = undefined;

    // Dial 1: claims the provision, then closes cleanly.
    {
        var cli = try quic.Client.connect(.{
            .insecure_skip_verify = true, // self-signed test cert
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
            .initial_dcid = &ticket_dcid,
        });
        defer cli.deinit();

        try cli.conn.advance();
        const now_us = try handshake(&fe, &cli, &srv, addr, 1_000);
        try std.testing.expect(prov.claimed);
        first_slot_id = prov.bound_slot_id.?;
        _ = try teardown(&fe, &cli, &srv, addr, now_us);
    }

    // Dial 2: the same dictated DCID again. The spent provision must
    // not match — the connection routes through the ordinary accept
    // path and the binding stays on the dead first slot.
    var cli2 = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .initial_dcid = &ticket_dcid,
    });
    defer cli2.deinit();

    try cli2.conn.advance();
    _ = try handshake(&fe, &cli2, &srv, addr, 60_000_000);

    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expectEqual(first_slot_id, prov.bound_slot_id.?);
    try std.testing.expect(findSlot(&srv, first_slot_id) == null);
}

test "rendezvous: a wrong nonce never confirms a claim — the DCID authorizes nothing" {
    const allocator = std.testing.allocator;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var fe: FrontEnd = .{};
    const ticket_dcid = [_]u8{ 0xC1, 0xD2, 0xE3, 0xF4, 0x05, 0x16, 0x27, 0x38 };
    const ticket_nonce: [16]u8 = @splat(0x5A);
    const prov = fe.register(&ticket_dcid, ticket_nonce);

    // The threat modeled: a party who learned the DCID (it is
    // plaintext on the wire) dials with it but does not hold the
    // ticket nonce. The claim latches — that is routing, and it is
    // all a DCID can ever buy — but confirmation must fail.
    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .initial_dcid = &ticket_dcid,
    });
    defer cli.deinit();

    try cli.conn.advance();
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x44), .port = 4444 } };
    _ = try handshake(&fe, &cli, &srv, addr, 1_000);
    try std.testing.expect(prov.claimed);
    const slot = findSlot(&srv, prov.bound_slot_id.?) orelse return error.BoundSlotMissing;

    const wrong_nonce: [16]u8 = @splat(0xEE);
    try std.testing.expect(!fe.confirmClaim(prov, slot.slot_id, wrong_nonce));
    try std.testing.expect(!prov.confirmed);

    // Nor does the right nonce confirm from a slot the claim is not
    // bound to.
    try std.testing.expect(!fe.confirmClaim(prov, slot.slot_id +% 1, ticket_nonce));
    try std.testing.expect(!prov.confirmed);
}

test "rendezvous: KNOWN LIMITATION — Retry rewrites the wire DCID, so the claim misses" {
    // Deliberately pinned so the gap is loud: with
    // `Config.retry_token_key` set, the first Initial (dictated
    // DCID) draws `.retry_sent`, and the slot-creating second
    // Initial carries the server-minted Retry SCID as its DCID. The
    // peek seam never sees the dictated bytes on an accepted
    // connection, so the provision stays unclaimed while the
    // connection itself completes fine. A production front end must
    // not Retry provision dials, or must recover the ODCID from its
    // own Retry token. If this test ever FAILS on the unclaimed
    // assertions, that machinery exists and the limitation is gone —
    // update the file docstring.
    const allocator = std.testing.allocator;

    const retry_key: quic.RetryTokenKey = @splat(0x77);
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .retry_token_key = retry_key,
    });
    defer srv.deinit();

    var fe: FrontEnd = .{};
    const ticket_dcid = [_]u8{ 0xC1, 0xD2, 0xE3, 0xF4, 0x05, 0x16, 0x27, 0x38 };
    const prov = fe.register(&ticket_dcid, @splat(0x5A));

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .initial_dcid = &ticket_dcid,
    });
    defer cli.deinit();

    try cli.conn.advance();
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x55), .port = 5555 } };
    _ = try handshake(&fe, &cli, &srv, addr, 1_000);

    // The connection works; the rendezvous does not.
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    try std.testing.expect(!prov.claimed);
    try std.testing.expectEqual(@as(?u64, null), prov.bound_slot_id);
    // And the accepted slot's initial DCID is the Retry SCID, not
    // the dictated bytes — the reason the peek can never match.
    const slot = srv.iterator()[0];
    try std.testing.expect(!std.mem.eql(u8, slot.initial_dcid.slice(), &ticket_dcid));
}
