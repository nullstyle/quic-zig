//! Public API smoke coverage for the 1.0 Stable tier.
//!
//! This intentionally does not split namespaces or instantiate a live
//! connection. It makes the existing API-stability document executable by
//! compiling against the names and method shapes embedders are expected to
//! depend on.

const std = @import("std");
const quic_zig = @import("quic_zig");

fn requireDecl(comptime T: type, comptime name: []const u8) void {
    if (!@hasDecl(T, name)) @compileError("missing public API declaration: " ++ name);
}

test "stable root and namespace exports resolve" {
    comptime {
        const Root = quic_zig;
        for (.{
            "Server",
            "Client",
            "Connection",
            "transport",
            "tls",
            "Address",
            "OutgoingDatagram",
            "IncomingDatagram",
            "ConnectionEvent",
            "CloseEvent",
            "CloseState",
            "CloseSource",
            "ConnectionPhase",
            "StreamType",
            "StreamPriority",
            "StreamSendStats",
            "StreamReadResult",
            "StreamRecvState",
            "TimerDeadline",
            "TimerKind",
            "PathStats",
            "KeylogCallback",
            "Session",
            "EarlyDataStatus",
        }) |name| requireDecl(Root, name);

        const Transport = quic_zig.transport;
        for (.{
            "runUdpServer",
            "RunUdpOptions",
            "RunError",
            "runUdpClient",
            "RunUdpClientOptions",
            "RunUdpClientError",
            "EcnCodepoint",
            "ServerTuning",
        }) |name| requireDecl(Transport, name);
    }
}

test "stable wrapper config types resolve" {
    comptime {
        _ = quic_zig.Server.Config;
        _ = quic_zig.Client.Config;
        _ = quic_zig.PreferredAddressConfig;
        _ = quic_zig.transport.RunUdpOptions;
        _ = quic_zig.transport.RunUdpClientOptions;
    }
}

test "stable Connection cycle, lifecycle, stream, and datagram methods keep their callable shape" {
    const Conn = quic_zig.Connection;

    const handle: *const fn (*Conn, []u8, ?quic_zig.Address, u64) anyerror!void = Conn.handle;
    const handle_with_ecn: *const fn (*Conn, []u8, ?quic_zig.Address, quic_zig.transport.EcnCodepoint, u64) anyerror!void = Conn.handleWithEcn;
    const poll_datagram: *const fn (*Conn, []u8, u64) anyerror!?quic_zig.OutgoingDatagram = Conn.pollDatagram;
    const tick: *const fn (*Conn, u64) anyerror!void = Conn.tick;
    const poll_event: *const fn (*Conn) ?quic_zig.ConnectionEvent = Conn.pollEvent;
    const next_timer_deadline: *const fn (*const Conn, u64) ?quic_zig.TimerDeadline = Conn.nextTimerDeadline;
    const is_closed: *const fn (*const Conn) bool = Conn.isClosed;
    const close_state: *const fn (*const Conn) quic_zig.CloseState = Conn.closeState;
    const phase: *const fn (*const Conn) quic_zig.ConnectionPhase = Conn.phase;

    const open_bidi: *const fn (*Conn, u64) anyerror!*quic_zig.conn.state.Stream = Conn.openBidi;
    const open_uni: *const fn (*Conn, u64) anyerror!*quic_zig.conn.state.Stream = Conn.openUni;
    const open_next_bidi: *const fn (*Conn) anyerror!*quic_zig.conn.state.Stream = Conn.openNextBidi;
    const open_next_uni: *const fn (*Conn) anyerror!*quic_zig.conn.state.Stream = Conn.openNextUni;
    const local_stream_type: *const fn (*const Conn, bool) quic_zig.StreamType = Conn.localStreamType;
    const stream_read: *const fn (*Conn, u64, []u8) anyerror!usize = Conn.streamRead;
    const stream_read_fin: *const fn (*Conn, u64, []u8) anyerror!quic_zig.StreamReadResult = Conn.streamReadFin;
    const stream_write: *const fn (*Conn, u64, []const u8) anyerror!usize = Conn.streamWrite;
    const stream_finish: *const fn (*Conn, u64) anyerror!void = Conn.streamFinish;
    const stream_stop_sending: *const fn (*Conn, u64, u64) anyerror!void = Conn.streamStopSending;
    const stream_send_stats: *const fn (*const Conn, u64) ?quic_zig.StreamSendStats = Conn.streamSendStats;
    const stream_recv_state: *const fn (*const Conn, u64) ?quic_zig.StreamRecvState = Conn.streamRecvState;
    const stream_priority: *const fn (*const Conn, u64) ?quic_zig.StreamPriority = Conn.streamPriority;
    const stream_set_priority: *const fn (*Conn, u64, quic_zig.StreamPriority) anyerror!void = Conn.streamSetPriority;

    const begin_graceful_shutdown: *const fn (*Conn) void = Conn.beginGracefulShutdown;
    const graceful_shutdown_active: *const fn (*const Conn) bool = Conn.gracefulShutdownActive;
    const close: *const fn (*Conn, bool, u64, []const u8) void = Conn.close;

    const send_datagram: *const fn (*Conn, []const u8) anyerror!void = Conn.sendDatagram;
    const send_datagram_tracked: *const fn (*Conn, []const u8) anyerror!u64 = Conn.sendDatagramTracked;
    const receive_datagram: *const fn (*Conn, []u8) ?usize = Conn.receiveDatagram;
    const receive_datagram_info: *const fn (*Conn, []u8) ?quic_zig.IncomingDatagram = Conn.receiveDatagramInfo;
    const max_datagram_payload: *const fn (*const Conn) anyerror!usize = Conn.maxDatagramPayload;

    _ = .{
        handle,
        handle_with_ecn,
        poll_datagram,
        tick,
        poll_event,
        next_timer_deadline,
        is_closed,
        close_state,
        phase,
        open_bidi,
        open_uni,
        open_next_bidi,
        open_next_uni,
        local_stream_type,
        stream_read,
        stream_read_fin,
        stream_write,
        stream_finish,
        stream_stop_sending,
        stream_send_stats,
        stream_recv_state,
        stream_priority,
        stream_set_priority,
        begin_graceful_shutdown,
        graceful_shutdown_active,
        close,
        send_datagram,
        send_datagram_tracked,
        receive_datagram,
        receive_datagram_info,
        max_datagram_payload,
    };

    comptime requireDecl(Conn, "streamIterator");
}

test "ConnectionEvent payload aliases stay top-level and forward-compatible" {
    comptime {
        const Event = quic_zig.ConnectionEvent;
        _ = quic_zig.DatagramSendEvent;
        _ = quic_zig.FlowBlockedInfo;
        _ = quic_zig.FlowBlockedKind;
        _ = quic_zig.FlowBlockedSource;
        _ = quic_zig.ConnectionIdReplenishInfo;

        if (std.meta.fieldInfo(Event, .datagram_acked).type != quic_zig.DatagramSendEvent) {
            @compileError("ConnectionEvent.datagram_acked payload alias drifted");
        }
        if (std.meta.fieldInfo(Event, .flow_blocked).type != quic_zig.FlowBlockedInfo) {
            @compileError("ConnectionEvent.flow_blocked payload alias drifted");
        }
        if (std.meta.fieldInfo(Event, .connection_ids_needed).type != quic_zig.ConnectionIdReplenishInfo) {
            @compileError("ConnectionEvent.connection_ids_needed payload alias drifted");
        }
    }
}
