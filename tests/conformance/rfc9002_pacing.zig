//! RFC 9002 §7.7 — packet pacing.
//!
//! Pins the pacing behavior quic_zig implements in `conn.pacing` (a
//! per-path token bucket gated into the send path). Connection-level
//! liveness, deadline surfacing, and the kill switch are covered in
//! `src/conn/_state_tests_pacing.zig`; this suite carries the
//! RFC-traceable claims about the initial burst bound and what pacing
//! MUST NOT delay, exercised over real handshake-confirmed pairs.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9002 §7.7 ¶2  SHOULD    limit the initial send burst to the
//!                              initial congestion window
//!   RFC9002 §7.7 /
//!   RFC9002 §6.2.4   MUST NOT  delay PTO probes for pacing (probes
//!                              elicit the ACKs that unblock everything)
//!   RFC9002 §7.7 /
//!   RFC9000 §10.2    MUST NOT  delay CONNECTION_CLOSE for pacing
//!   RFC9002 §7.7 ¶?  MUST NOT  delay ACK-only packets for pacing (ACKs
//!                              are not congestion controlled)

const std = @import("std");
const quic_zig = @import("quic_zig");
const handshake_fixture = @import("_handshake_fixture.zig");

const HandshakePair = handshake_fixture.HandshakePair;

/// Empty the client's pacing bucket and push it into debt, so any
/// subsequent emission proves a bypass rather than leftover credit.
fn drainClientPacer(pair: *HandshakePair) void {
    const path = pair.clientConn().primaryPath();
    const cc = &path.path.cc;
    path.path.pacer.refill(
        pair.now_us,
        cc.pacingRateBps(path.path.rtt.smoothed_rtt_us),
        cc.config().max_datagram_size,
    );
    path.path.pacer.consume(10_000_000);
    std.debug.assert(!path.path.pacer.canSend(1));
}

test "SHOULD limit the initial send burst to the initial congestion window [RFC9002 §7.7 ¶2]" {
    // The bucket property itself: a fresh pacer's low-rate capacity is
    // exactly the 10-packet initial-window burst.
    const pacing = quic_zig.conn.pacing;
    var pacer: pacing.Pacer = .{};
    pacer.refill(0, pacing.rateBytesPerSecond(12_000, 333_000, true), 1_200);
    try std.testing.expect(pacer.canSend(pacing.burst_packets * 1_200));
    try std.testing.expect(!pacer.canSend(pacing.burst_packets * 1_200 + 1));
}

test "MUST NOT delay PTO probes for pacing [RFC9002 §6.2.4 / §7.7]" {
    var pair = try HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    drainClientPacer(&pair);
    // Arm the probe signal the PTO firing path uses, then poll: the
    // PING datagram must emit despite the empty (indebted) bucket.
    pair.clientConn().pendingPingForLevel(.application).* = true;
    var pkt: [2048]u8 = undefined;
    const out = try pair.clientConn().pollDatagram(&pkt, pair.now_us);
    try std.testing.expect(out != null);
}

test "MUST NOT delay CONNECTION_CLOSE for pacing [RFC9000 §10.2 / RFC9002 §7.7]" {
    var pair = try HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    drainClientPacer(&pair);
    pair.clientConn().close(false, 0x42, "paced close");
    var pkt: [2048]u8 = undefined;
    const out = try pair.clientConn().pollDatagram(&pkt, pair.now_us);
    try std.testing.expect(out != null);
}

test "MUST NOT delay ACK-only packets for pacing [RFC9002 §7.7]" {
    var pair = try HandshakePair.init(std.testing.allocator);
    defer pair.deinit();
    try pair.driveToHandshakeConfirmed();

    drainClientPacer(&pair);
    // Queue a pending ACK by recording an ack-eliciting receipt with
    // an immediate-ACK threshold of 1.
    const path = pair.clientConn().primaryPath();
    path.app_pn_space.recordReceivedPacketDelayed(1_000, pair.now_us / 1000, true, 1);
    try std.testing.expect(path.app_pn_space.received.pending_ack);
    var pkt: [2048]u8 = undefined;
    const out = try pair.clientConn().pollDatagram(&pkt, pair.now_us);
    try std.testing.expect(out != null);
}
