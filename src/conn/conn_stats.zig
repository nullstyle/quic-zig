// Connection-level statistics snapshot: the embedder-facing mirror of
// `Server.metricsSnapshot`, assembled entirely from counters and
// snapshots the connection already maintains. Free functions over
// `*Connection` in the house layout; `Connection.stats()` is the thunk.
//
// Everything here is a by-value copy — safe to hold across ticks,
// reaps, and connection teardown.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const path_mod = @import("path.zig");
const conn_paths = @import("conn_paths.zig");
const conn_streams = @import("conn_streams.zig");

const Connection = state_mod.Connection;

/// One-call observability snapshot for a connection (Unstable tier —
/// fields may be added in minors; see docs/API_STABILITY.md).
///
/// Aggregate counters are whole-connection and monotonic (they survive
/// migration and multipath rebalancing); the path section is a snapshot
/// of the CURRENT active path, so an embedder graphing cwnd/RTT follows
/// the path actually carrying traffic. Per-path detail (including the
/// DPLPMTUD state machine) stays on `Connection.pathStats(path_id)`.
pub const ConnectionStats = struct {
    /// Total UDP payload bytes sent/received across all paths.
    bytes_sent: u64,
    bytes_received: u64,
    /// QUIC packets sent, received-and-authenticated, and declared lost.
    packets_sent: u64,
    packets_received: u64,
    packets_lost: u64,

    /// The path the snapshot section below describes.
    active_path_id: u32,
    cwnd: u64,
    bytes_in_flight: u64,
    smoothed_rtt_us: u64,
    latest_rtt_us: u64,
    min_rtt_us: u64,
    rttvar_us: u64,
    congestion_state: path_mod.CongestionState,
    /// Max outbound datagram size on the active path (DPLPMTUD floor).
    pmtu: usize,

    /// Live (unreaped) streams in the connection's table.
    streams_open: usize,
    close_state: state_mod.CloseState,
};

// One-line pointer per the extraction convention: full doc on the
// `Connection.stats` thunk in state.zig.
pub fn stats(self: *const Connection) ConnectionStats {
    const active_id = conn_paths.activePathId(self);
    const ps = conn_paths.pathStats(self, active_id);
    return .{
        .bytes_sent = self.qlog_bytes_sent,
        .bytes_received = self.qlog_bytes_received,
        .packets_sent = self.qlog_packets_sent,
        .packets_received = self.qlog_packets_received,
        .packets_lost = self.qlog_packets_lost,

        .active_path_id = active_id,
        .cwnd = if (ps) |p| p.cwnd else 0,
        .bytes_in_flight = if (ps) |p| p.bytes_in_flight else 0,
        .smoothed_rtt_us = if (ps) |p| p.smoothed_rtt_us else 0,
        .latest_rtt_us = if (ps) |p| p.latest_rtt_us else 0,
        .min_rtt_us = if (ps) |p| p.min_rtt_us else 0,
        .rttvar_us = if (ps) |p| p.rttvar_us else 0,
        .congestion_state = if (ps) |p| p.congestion_window_state else .slow_start,
        .pmtu = self.pmtu(),

        .streams_open = conn_streams.streamCount(self),
        .close_state = self.closeState(),
    };
}
