//! Connection-level statistics snapshot: the embedder-facing mirror of
//! `Server.metricsSnapshot`, assembled entirely from counters and
//! snapshots the connection already maintains. Free functions over
//! `*Connection` in the house layout; `Connection.stats()` is the thunk.
//!
//! Everything here is a by-value copy — safe to hold across ticks,
//! reaps, and connection teardown.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const path_mod = @import("../conn/path.zig");
const conn_paths = @import("paths.zig");
const conn_streams = @import("streams.zig");

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
    /// Of `packets_lost`, the packets that arrived after all (an ACK
    /// covered them later): reordering on the path, not loss. The
    /// loss thresholds widen on each one (RFC 9002 §6.1), and a
    /// congestion response in which every "lost" packet arrived is
    /// taken back. A value that keeps rising with `packets_lost` means
    /// the path reorders more than the thresholds have grown to.
    packets_spuriously_lost: u64,
    /// For every Application-space packet declared lost, the time from
    /// its send to its declaration, summed over them, and how many
    /// (`loss_detection_delays`): the mean is the loss detection delay
    /// the thresholds control (RFC 9002 §6.1: about an RTT and a
    /// little at the initial thresholds, up to two RTTs at the widest).
    loss_detection_delay_sum_us: u64,
    loss_detection_delays: u64,
    /// Inbound RFC 9221 DATAGRAMs shed under queue/memory pressure
    /// instead of queued (receiver-side drop is permitted by §5.3;
    /// the connection stays up). Monotonic. A rising value means the
    /// application drains `receiveDatagram` slower than the peer
    /// sends — drain the queue to empty each service iteration.
    datagrams_dropped_recv: u64,

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
// `Connection.stats` thunk in Connection.zig.
pub fn stats(conn: *const Connection) ConnectionStats {
    const active_id = conn_paths.activePathId(conn);
    const ps = conn_paths.pathStats(conn, active_id);
    return .{
        .bytes_sent = conn.qlog_bytes_sent,
        .bytes_received = conn.qlog_bytes_received,
        .packets_sent = conn.qlog_packets_sent,
        .packets_received = conn.qlog_packets_received,
        .packets_lost = conn.qlog_packets_lost,
        .packets_spuriously_lost = conn.qlog_packets_spuriously_lost,
        .loss_detection_delay_sum_us = conn.qlog_loss_delay_sum_us,
        .loss_detection_delays = conn.qlog_loss_delays,
        .datagrams_dropped_recv = conn.datagrams_dropped_recv,

        .active_path_id = active_id,
        .cwnd = if (ps) |p| p.cwnd else 0,
        .bytes_in_flight = if (ps) |p| p.bytes_in_flight else 0,
        .smoothed_rtt_us = if (ps) |p| p.smoothed_rtt_us else 0,
        .latest_rtt_us = if (ps) |p| p.latest_rtt_us else 0,
        .min_rtt_us = if (ps) |p| p.min_rtt_us else 0,
        .rttvar_us = if (ps) |p| p.rttvar_us else 0,
        .congestion_state = if (ps) |p| p.congestion_window_state else .slow_start,
        .pmtu = conn.pmtu(),

        .streams_open = conn_streams.streamCount(conn),
        .close_state = conn.closeState(),
    };
}
