//! Congestion control (RFC 9002 §7 + Appendix B).
//!
//! One controller per Path: the single-path connection has one,
//! multipath connections have one per active path. The controller
//! works in `bytes_in_flight` units the connection state machine
//! maintains externally (in `SentPacketTracker`), but the controller
//! itself tracks `cwnd` and `ssthresh` as authoritative per-path
//! limits.
//!
//! `CongestionController` is the dispatch layer: a tagged union over
//! the available algorithms (NewReno today; the tag is chosen by
//! `Config.algorithm` and dispatched with zero indirection via inline
//! switches). Everything outside this file talks to the union; the
//! concrete controllers stay exported for tests and direct embedding.

const std = @import("std");

/// kPersistentCongestionThreshold from RFC 9002 §7.6.1: 3.
pub const persistent_congestion_threshold: u8 = 3;

/// kLossReductionFactor numerator from RFC 9002 §B.1.
pub const loss_reduction_factor_num: u64 = 1;
/// kLossReductionFactor denominator from RFC 9002 §B.1 (factor = 1/2).
pub const loss_reduction_factor_den: u64 = 2;

/// Selectable congestion-control algorithm.
pub const Algorithm = enum {
    /// RFC 9002 §7 / Appendix B NewReno.
    new_reno,
};

/// Tunables held by-value inside each controller so every path has
/// independent state.
pub const Config = struct {
    /// Maximum UDP datagram size we'll send. Conservatively 1200
    /// per the QUIC v1 minimum; raised by PMTU discovery later.
    max_datagram_size: u64 = 1200,
    /// Which controller `CongestionController.init` builds.
    algorithm: Algorithm = .new_reno,

    /// Minimum congestion window: 2 * max_datagram_size.
    pub fn minWindow(self: Config) u64 {
        return 2 * self.max_datagram_size;
    }

    /// Initial congestion window: min(10 * max_datagram_size,
    /// max(2 * max_datagram_size, 14720)). RFC 9002 §7.2.
    pub fn initialWindow(self: Config) u64 {
        const ten = 10 * self.max_datagram_size;
        const fourteen720 = @max(self.minWindow(), 14720);
        return @min(ten, fourteen720);
    }
};

/// Algorithm-dispatching congestion controller: by-value on each path,
/// no allocation, no vtable — every method is an inline switch on a
/// one-byte tag. Concrete controllers must expose the same event
/// surface plus `cwnd`, `ssthresh`, `recovery_start_time_us`, and
/// `cfg` fields (the inline-else accessors below reach them
/// generically).
pub const CongestionController = union(Algorithm) {
    new_reno: NewReno,

    pub fn init(cfg: Config) CongestionController {
        return switch (cfg.algorithm) {
            .new_reno => .{ .new_reno = NewReno.init(cfg) },
        };
    }

    /// The active algorithm (the union tag).
    pub fn algorithm(self: *const CongestionController) Algorithm {
        return std.meta.activeTag(self.*);
    }

    // -- event surface (forwarded) ----------------------------------------

    pub fn onPacketAcked(
        self: *CongestionController,
        bytes_acked: u64,
        largest_acked_sent_time_us: u64,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.onPacketAcked(bytes_acked, largest_acked_sent_time_us),
        }
    }

    pub fn onPacketLost(
        self: *CongestionController,
        bytes_lost: u64,
        lost_largest_sent_time_us: u64,
    ) void {
        switch (self.*) {
            inline else => |*impl| impl.onPacketLost(bytes_lost, lost_largest_sent_time_us),
        }
    }

    pub fn onPersistentCongestion(self: *CongestionController) void {
        switch (self.*) {
            inline else => |*impl| impl.onPersistentCongestion(),
        }
    }

    pub fn onCongestionEvent(self: *CongestionController, ce_packet_sent_time_us: u64) void {
        switch (self.*) {
            inline else => |*impl| impl.onCongestionEvent(ce_packet_sent_time_us),
        }
    }

    // -- read surface --------------------------------------------------------

    pub fn sendAllowance(self: *const CongestionController, bytes_in_flight: u64) u64 {
        return switch (self.*) {
            inline else => |*impl| impl.sendAllowance(bytes_in_flight),
        };
    }

    pub fn isSlowStart(self: *const CongestionController) bool {
        return switch (self.*) {
            inline else => |*impl| impl.isSlowStart(),
        };
    }

    pub fn isInRecovery(self: *const CongestionController, sent_time_us: u64) bool {
        return switch (self.*) {
            inline else => |*impl| impl.isInRecovery(sent_time_us),
        };
    }

    /// Current congestion window in bytes.
    pub fn cwndBytes(self: *const CongestionController) u64 {
        return switch (self.*) {
            inline else => |*impl| impl.cwnd,
        };
    }

    /// Slow-start threshold; null = infinity (still in initial slow start).
    pub fn ssthreshBytes(self: *const CongestionController) ?u64 {
        return switch (self.*) {
            inline else => |*impl| impl.ssthresh,
        };
    }

    /// Recovery-period anchor, if currently in recovery.
    pub fn recoveryStartTimeUs(self: *const CongestionController) ?u64 {
        return switch (self.*) {
            inline else => |*impl| impl.recovery_start_time_us,
        };
    }

    /// The controller's configured minimum window.
    pub fn minWindow(self: *const CongestionController) u64 {
        return switch (self.*) {
            inline else => |*impl| impl.cfg.minWindow(),
        };
    }

    /// The controller's configuration (algorithm tag included).
    pub fn config(self: *const CongestionController) Config {
        return switch (self.*) {
            inline else => |*impl| impl.cfg,
        };
    }

    // INTERNAL: direct cwnd override for tests and benchmark fixtures
    // that need to force a controller into a specific regime. Not part
    // of any embedder contract.
    pub fn setCwndForTest(self: *CongestionController, cwnd: u64) void {
        switch (self.*) {
            inline else => |*impl| impl.cwnd = cwnd,
        }
    }
};

/// RFC 9002 NewReno congestion controller. One instance per QUIC
/// path. Tracks congestion window, slow-start threshold, and the
/// recovery period; exposes `sendAllowance` for the packet builder.
pub const NewReno = struct {
    cfg: Config,
    /// Current congestion window in bytes.
    cwnd: u64,
    /// Slow-start threshold. `null` means infinity (slow start
    /// continues until first loss).
    ssthresh: ?u64 = null,
    /// Recovery start time in microseconds, if currently in
    /// recovery. Set on loss; cleared once an ACK arrives for a
    /// packet sent after recovery_start_time.
    recovery_start_time_us: ?u64 = null,
    /// Bytes acknowledged since the last cwnd update during
    /// congestion avoidance. We compound increments per
    /// `bytes_acked / cwnd >= max_datagram_size`.
    bytes_acked_in_ca: u64 = 0,

    /// Build a fresh controller with `cfg` and `cwnd = initialWindow()`.
    pub fn init(cfg: Config) NewReno {
        return .{ .cfg = cfg, .cwnd = cfg.initialWindow() };
    }

    /// True iff the controller is currently in recovery and the
    /// packet sent at `sent_time_us` predates the recovery boundary
    /// (so its ACK should not grow `cwnd`).
    pub fn isInRecovery(self: *const NewReno, sent_time_us: u64) bool {
        return self.recovery_start_time_us != null and
            sent_time_us <= self.recovery_start_time_us.?;
    }

    /// True while we're in slow start (no `ssthresh` yet, or
    /// `cwnd < ssthresh`).
    pub fn isSlowStart(self: *const NewReno) bool {
        return self.ssthresh == null or self.cwnd < self.ssthresh.?;
    }

    /// Process an ACK for `bytes_acked` bytes whose newest packet
    /// was sent at `largest_acked_sent_time_us`. RFC 9002 §B.5.
    pub fn onPacketAcked(
        self: *NewReno,
        bytes_acked: u64,
        largest_acked_sent_time_us: u64,
    ) void {
        // Clear recovery if we've received an ACK for a packet sent
        // after recovery began.
        if (self.recovery_start_time_us) |rec_start| {
            if (largest_acked_sent_time_us > rec_start) {
                self.recovery_start_time_us = null;
            } else {
                // Still in recovery — don't grow cwnd.
                return;
            }
        }

        if (self.isSlowStart()) {
            self.cwnd += bytes_acked;
            return;
        }

        // Congestion avoidance: cwnd grows by ~max_datagram_size per RTT.
        // The standard accounting is to accumulate bytes_acked and
        // bump cwnd by max_datagram_size once we've accumulated enough.
        self.bytes_acked_in_ca += bytes_acked;
        if (self.bytes_acked_in_ca >= self.cwnd) {
            self.bytes_acked_in_ca -= self.cwnd;
            self.cwnd += self.cfg.max_datagram_size;
        }
    }

    /// Process a packet declared lost. RFC 9002 §B.6.
    /// `lost_largest_sent_time_us` is the send time of the latest
    /// lost packet; recovery period starts at that time.
    pub fn onPacketLost(
        self: *NewReno,
        bytes_lost: u64,
        lost_largest_sent_time_us: u64,
    ) void {
        _ = bytes_lost; // tracked externally; unused here

        // Don't re-enter recovery for losses that happened during
        // an existing recovery period.
        if (self.recovery_start_time_us) |rec_start| {
            if (lost_largest_sent_time_us <= rec_start) return;
        }

        self.recovery_start_time_us = lost_largest_sent_time_us;
        // ssthresh = cwnd * 0.5
        self.ssthresh = @max(
            self.cwnd * loss_reduction_factor_num / loss_reduction_factor_den,
            self.cfg.minWindow(),
        );
        self.cwnd = self.ssthresh.?;
        self.bytes_acked_in_ca = 0;
    }

    /// Sent during a "persistent congestion" period (RFC 9002 §7.6).
    /// Reset cwnd to the minimum window.
    pub fn onPersistentCongestion(self: *NewReno) void {
        self.cwnd = self.cfg.minWindow();
        self.recovery_start_time_us = null;
        self.bytes_acked_in_ca = 0;
    }

    /// Process a peer-reported ECN-CE event for a packet whose newest
    /// in-flight peer was sent at `ce_packet_sent_time_us` (RFC 9000
    /// §13.4.2 / RFC 9002 §B.7). Mirrors `onPacketLost`'s ssthresh /
    /// cwnd halving and recovery-period start without consuming a
    /// byte budget — packets aren't actually lost from the
    /// in-flight pool by an ECN-CE report, just the controller window
    /// shrinks.
    pub fn onCongestionEvent(self: *NewReno, ce_packet_sent_time_us: u64) void {
        // Suppress re-entry into recovery for ECN events that report
        // CE on packets sent before the current recovery period.
        if (self.recovery_start_time_us) |rec_start| {
            if (ce_packet_sent_time_us <= rec_start) return;
        }
        self.recovery_start_time_us = ce_packet_sent_time_us;
        self.ssthresh = @max(
            self.cwnd * loss_reduction_factor_num / loss_reduction_factor_den,
            self.cfg.minWindow(),
        );
        self.cwnd = self.ssthresh.?;
        self.bytes_acked_in_ca = 0;
    }

    /// Are we allowed to send `bytes_in_flight` worth of data right
    /// now? Returns the cwnd headroom (bytes that can still be sent
    /// before hitting the limit). 0 means "wait."
    pub fn sendAllowance(self: *const NewReno, bytes_in_flight: u64) u64 {
        if (bytes_in_flight >= self.cwnd) return 0;
        return self.cwnd - bytes_in_flight;
    }
};

// -- tests ---------------------------------------------------------------

test "initial window honors RFC 9002 §7.2 (max 10 MSS, min(2 MSS, 14720))" {
    const cfg: Config = .{ .max_datagram_size = 1200 };
    // 10 * 1200 = 12000; max(2400, 14720) = 14720; min = 12000.
    try std.testing.expectEqual(@as(u64, 12000), cfg.initialWindow());

    const big: Config = .{ .max_datagram_size = 1500 };
    // 10 * 1500 = 15000; max(2 * 1500, 14720) = 14720; min(15000, 14720) = 14720.
    try std.testing.expectEqual(@as(u64, 14720), big.initialWindow());
}

test "slow start adds bytes_acked to cwnd" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    const initial = nr.cwnd;
    try std.testing.expect(nr.isSlowStart());
    nr.onPacketAcked(2400, 100);
    try std.testing.expectEqual(initial + 2400, nr.cwnd);
}

test "loss halves cwnd to ssthresh and enters recovery" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    nr.onPacketLost(1200, 1_000_000);
    try std.testing.expectEqual(@as(?u64, 6000), nr.ssthresh);
    try std.testing.expectEqual(@as(u64, 6000), nr.cwnd);
    try std.testing.expect(nr.recovery_start_time_us != null);
    try std.testing.expect(nr.isInRecovery(500_000));
    try std.testing.expect(!nr.isInRecovery(1_500_000));
}

test "loss can't shrink cwnd below min_window" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 2000; // already small
    nr.onPacketLost(1200, 1_000_000);
    try std.testing.expectEqual(nr.cfg.minWindow(), nr.cwnd);
}

test "recovery period prevents cwnd growth from in-recovery acks" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.onPacketLost(1200, 1_000_000);
    const cwnd_after_loss = nr.cwnd;
    // ACK for a packet sent before recovery → ignored for cwnd.
    nr.onPacketAcked(1200, 999_999);
    try std.testing.expectEqual(cwnd_after_loss, nr.cwnd);
    // ACK for a packet sent after recovery → recovery clears, but
    // cwnd is now in CA mode (cwnd == ssthresh after the loss).
    // Acking enough bytes to fill `bytes_acked_in_ca >= cwnd`
    // triggers one MSS bump.
    nr.onPacketAcked(cwnd_after_loss, 2_000_000);
    try std.testing.expectEqual(@as(?u64, null), nr.recovery_start_time_us);
    try std.testing.expectEqual(cwnd_after_loss + nr.cfg.max_datagram_size, nr.cwnd);
}

test "congestion avoidance grows cwnd by ~MSS per RTT" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    nr.ssthresh = 6000; // force CA mode
    try std.testing.expect(!nr.isSlowStart());

    // Accumulate cwnd worth of acks → one MSS bump.
    nr.onPacketAcked(12000, 100);
    try std.testing.expectEqual(@as(u64, 13200), nr.cwnd);
}

test "sendAllowance reports remaining cwnd" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    try std.testing.expectEqual(@as(u64, 12000), nr.sendAllowance(0));
    try std.testing.expectEqual(@as(u64, 4000), nr.sendAllowance(8000));
    try std.testing.expectEqual(@as(u64, 0), nr.sendAllowance(12000));
    try std.testing.expectEqual(@as(u64, 0), nr.sendAllowance(20000));
}

test "persistent congestion resets cwnd to min_window" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 30000;
    nr.onPersistentCongestion();
    try std.testing.expectEqual(nr.cfg.minWindow(), nr.cwnd);
}

test "onCongestionEvent halves cwnd to ssthresh and arms recovery" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    nr.onCongestionEvent(1_000_000);
    try std.testing.expectEqual(@as(?u64, 6000), nr.ssthresh);
    try std.testing.expectEqual(@as(u64, 6000), nr.cwnd);
    try std.testing.expectEqual(@as(?u64, 1_000_000), nr.recovery_start_time_us);
}

test "onCongestionEvent suppresses re-entry within an existing recovery period" {
    var nr = NewReno.init(.{ .max_datagram_size = 1200 });
    nr.cwnd = 12000;
    nr.onCongestionEvent(1_000_000);
    const cwnd_after_first = nr.cwnd;
    // A second CE on a packet sent before the recovery boundary is
    // a duplicate signal — shouldn't shrink cwnd further.
    nr.onCongestionEvent(999_999);
    try std.testing.expectEqual(cwnd_after_first, nr.cwnd);
}

test "CongestionController dispatch is observably identical to direct NewReno" {
    // Drive the same ack/loss/CE script through a bare NewReno and
    // through the union; every observable must match at every step —
    // the zero-delta guarantee of the dispatch layer.
    const cfg: Config = .{ .max_datagram_size = 1200 };
    var direct = NewReno.init(cfg);
    var boxed = CongestionController.init(cfg);
    try std.testing.expectEqual(Algorithm.new_reno, boxed.algorithm());

    const Step = union(enum) {
        ack: struct { bytes: u64, sent_us: u64 },
        loss: struct { bytes: u64, sent_us: u64 },
        ce: u64,
        persistent: void,
    };
    const script = [_]Step{
        .{ .ack = .{ .bytes = 2400, .sent_us = 100 } },
        .{ .ack = .{ .bytes = 4800, .sent_us = 200 } },
        .{ .loss = .{ .bytes = 1200, .sent_us = 300 } },
        .{ .ack = .{ .bytes = 1200, .sent_us = 250 } }, // in recovery
        .{ .ack = .{ .bytes = 9000, .sent_us = 400 } }, // exits recovery
        .{ .ce = 500 },
        .{ .persistent = {} },
        .{ .ack = .{ .bytes = 3000, .sent_us = 600 } },
    };
    for (script) |step| {
        switch (step) {
            .ack => |a| {
                direct.onPacketAcked(a.bytes, a.sent_us);
                boxed.onPacketAcked(a.bytes, a.sent_us);
            },
            .loss => |l| {
                direct.onPacketLost(l.bytes, l.sent_us);
                boxed.onPacketLost(l.bytes, l.sent_us);
            },
            .ce => |t| {
                direct.onCongestionEvent(t);
                boxed.onCongestionEvent(t);
            },
            .persistent => {
                direct.onPersistentCongestion();
                boxed.onPersistentCongestion();
            },
        }
        try std.testing.expectEqual(direct.cwnd, boxed.cwndBytes());
        try std.testing.expectEqual(direct.ssthresh, boxed.ssthreshBytes());
        try std.testing.expectEqual(direct.recovery_start_time_us, boxed.recoveryStartTimeUs());
        try std.testing.expectEqual(direct.isSlowStart(), boxed.isSlowStart());
        try std.testing.expectEqual(
            direct.sendAllowance(5000),
            boxed.sendAllowance(5000),
        );
    }
    try std.testing.expectEqual(cfg.minWindow(), boxed.minWindow());
    try std.testing.expectEqual(@as(u64, 1200), boxed.config().max_datagram_size);
    boxed.setCwndForTest(99_999);
    try std.testing.expectEqual(@as(u64, 99_999), boxed.cwndBytes());
}
