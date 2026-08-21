//! Public API smoke coverage for the 1.0 Stable tier.
//!
//! This intentionally does not split namespaces or instantiate a live
//! connection. It makes the existing API-stability document executable by
//! compiling against the names and method shapes embedders are expected to
//! depend on.

const std = @import("std");
const quic = @import("quic");

fn requireDecl(comptime T: type, comptime name: []const u8) void {
    if (!@hasDecl(T, name)) @compileError("missing public API declaration: " ++ name);
}

test "stable root and namespace exports resolve" {
    comptime {
        const Root = quic;
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

        const Transport = quic.transport;
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
        _ = quic.Server.Config;
        _ = quic.Client.Config;
        _ = quic.PreferredAddressConfig;
        _ = quic.transport.RunUdpOptions;
        _ = quic.transport.RunUdpClientOptions;
    }
}

test "stable Connection cycle, lifecycle, stream, and datagram methods keep their callable shape" {
    const Conn = quic.Connection;

    const handle: *const fn (*Conn, []u8, ?quic.Address, u64) anyerror!void = Conn.handle;
    const handle_with_ecn: *const fn (*Conn, []u8, ?quic.Address, quic.transport.EcnCodepoint, u64) anyerror!void = Conn.handleWithEcn;
    const poll_datagram: *const fn (*Conn, []u8, u64) anyerror!?quic.OutgoingDatagram = Conn.pollDatagram;
    const tick: *const fn (*Conn, u64) anyerror!void = Conn.tick;
    const poll_event: *const fn (*Conn) ?quic.ConnectionEvent = Conn.pollEvent;
    const next_timer_deadline: *const fn (*const Conn, u64) ?quic.TimerDeadline = Conn.nextTimerDeadline;
    const is_closed: *const fn (*const Conn) bool = Conn.isClosed;
    const close_state: *const fn (*const Conn) quic.CloseState = Conn.closeState;
    const phase: *const fn (*const Conn) quic.ConnectionPhase = Conn.phase;

    const open_bidi: *const fn (*Conn, u64) anyerror!*quic.conn.state.Stream = Conn.openBidi;
    const open_uni: *const fn (*Conn, u64) anyerror!*quic.conn.state.Stream = Conn.openUni;
    const open_next_bidi: *const fn (*Conn) anyerror!*quic.conn.state.Stream = Conn.openNextBidi;
    const open_next_uni: *const fn (*Conn) anyerror!*quic.conn.state.Stream = Conn.openNextUni;
    const local_stream_type: *const fn (*const Conn, bool) quic.StreamType = Conn.localStreamType;
    const stream_read: *const fn (*Conn, u64, []u8) anyerror!usize = Conn.streamRead;
    const stream_read_fin: *const fn (*Conn, u64, []u8) anyerror!quic.StreamReadResult = Conn.streamReadFin;
    const stream_write: *const fn (*Conn, u64, []const u8) anyerror!usize = Conn.streamWrite;
    const stream_finish: *const fn (*Conn, u64) anyerror!void = Conn.streamFinish;
    const stream_stop_sending: *const fn (*Conn, u64, u64) anyerror!void = Conn.streamStopSending;
    const stream_send_stats: *const fn (*const Conn, u64) ?quic.StreamSendStats = Conn.streamSendStats;
    const stream_recv_state: *const fn (*const Conn, u64) ?quic.StreamRecvState = Conn.streamRecvState;
    const stream_priority: *const fn (*const Conn, u64) ?quic.StreamPriority = Conn.streamPriority;
    const stream_set_priority: *const fn (*Conn, u64, quic.StreamPriority) anyerror!void = Conn.streamSetPriority;
    // Send-side flow-control snapshots, Stable as of 0.15.0.
    const send_window: *const fn (*const Conn) u64 = Conn.sendWindow;
    const stream_send_window: *const fn (*const Conn, u64) ?quic.SendWindow = Conn.streamSendWindow;
    // Whole-connection observability snapshot, Stable as of 0.15.0.
    const stats: *const fn (*const Conn) quic.ConnectionStats = Conn.stats;

    const begin_graceful_shutdown: *const fn (*Conn) void = Conn.beginGracefulShutdown;
    const graceful_shutdown_active: *const fn (*const Conn) bool = Conn.gracefulShutdownActive;
    const close: *const fn (*Conn, bool, u64, []const u8) void = Conn.close;

    const send_datagram: *const fn (*Conn, []const u8) anyerror!void = Conn.sendDatagram;
    const send_datagram_tracked: *const fn (*Conn, []const u8) anyerror!u64 = Conn.sendDatagramTracked;
    const receive_datagram: *const fn (*Conn, []u8) ?usize = Conn.receiveDatagram;
    const receive_datagram_info: *const fn (*Conn, []u8) ?quic.IncomingDatagram = Conn.receiveDatagramInfo;
    const next_datagram_size: *const fn (*const Conn) ?usize = Conn.nextDatagramSize;
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
        send_window,
        stream_send_window,
        stats,
        begin_graceful_shutdown,
        graceful_shutdown_active,
        close,
        send_datagram,
        send_datagram_tracked,
        receive_datagram,
        receive_datagram_info,
        next_datagram_size,
        max_datagram_payload,
    };

    comptime requireDecl(Conn, "streamIterator");
}

test "ConnectionEvent payload aliases stay top-level and forward-compatible" {
    comptime {
        // The fieldInfo walks below share one comptime branch budget;
        // the default 1000 ran out when the event union grew.
        @setEvalBranchQuota(10_000);
        const Event = quic.ConnectionEvent;
        _ = quic.DatagramSendEvent;
        _ = quic.FlowBlockedInfo;
        _ = quic.FlowBlockedKind;
        _ = quic.FlowBlockedSource;
        _ = quic.ConnectionIdReplenishInfo;
        _ = quic.StreamOpenedInfo;

        if (std.meta.fieldInfo(Event, .datagram_acked).type != quic.DatagramSendEvent) {
            @compileError("ConnectionEvent.datagram_acked payload alias drifted");
        }
        if (std.meta.fieldInfo(Event, .flow_blocked).type != quic.FlowBlockedInfo) {
            @compileError("ConnectionEvent.flow_blocked payload alias drifted");
        }
        if (std.meta.fieldInfo(Event, .connection_ids_needed).type != quic.ConnectionIdReplenishInfo) {
            @compileError("ConnectionEvent.connection_ids_needed payload alias drifted");
        }
        if (std.meta.fieldInfo(Event, .stream_opened).type != quic.StreamOpenedInfo) {
            @compileError("ConnectionEvent.stream_opened payload alias drifted");
        }
        // `handshake_established` is a void one-shot; pin its presence.
        _ = std.meta.fieldInfo(Event, .handshake_established);
        // `early_data` carries the Stable EarlyDataStatus enum.
        if (std.meta.fieldInfo(Event, .early_data).type != quic.EarlyDataStatus) {
            @compileError("ConnectionEvent.early_data payload alias drifted");
        }
    }
}

test "0-RTT, resumption-capture, migration, and ALPN surfaces keep their shape" {
    const Conn = quic.Connection;
    comptime {
        requireDecl(Conn, "negotiatedAlpn");
        requireDecl(Conn, "earlyDataStatus");
        requireDecl(Conn, "earlyDataReason");
        requireDecl(Conn, "setEarlyDataEnabled");
        requireDecl(Conn, "streamArrivedInEarlyData");
        requireDecl(Conn, "setEarlyDataContextForParams");
        // 0-RTT restore-budget query (Client convenience + the
        // Connection method it forwards to). Evolving tier.
        requireDecl(Conn, "earlyDataSendWindow");
        requireDecl(quic.Client, "earlyDataSendWindow");
        _ = quic.EarlyDataSendWindow;
        // The status enum is part of the Stable surface: embedders
        // switch on it (HTTP/3 remembered-settings replay).
        _ = quic.EarlyDataStatus;
        // Wrapper config: ticket capture (client) and 0-RTT replay
        // context + proactive CID replenish (server).
        _ = std.meta.fieldInfo(quic.Client.Config, .new_session_callback);
        _ = std.meta.fieldInfo(quic.Client.Config, .resumption_state);
        _ = std.meta.fieldInfo(quic.Server.Config, .early_data);
        _ = quic.Server.EarlyData.disabled;
        _ = std.meta.fieldInfo(quic.Server.Config, .early_data_application_context);
        _ = std.meta.fieldInfo(quic.Server.Config, .auto_replenish_connection_ids);
        _ = std.meta.fieldInfo(quic.Server.Config, .max_auto_replenish_cids);
        // Typed migration refusals stay in the public error set.
        // Named via the root alias on purpose: that is the path
        // embedders composing their own error sets should use, so
        // pinning it here keeps it from being dropped.
        const E = quic.ConnectionError;
        if (@as(E, error.MigrationPreHandshake) != error.MigrationPreHandshake or
            @as(E, error.MigrationValidationPending) != error.MigrationValidationPending or
            @as(E, error.MigrationNoFreshPeerCid) != error.MigrationNoFreshPeerCid)
        {
            @compileError("typed migration refusals drifted out of the public error set");
        }
    }
    const alpn: *const fn (*Conn) ?[]const u8 = Conn.negotiatedAlpn;
    _ = alpn;
}

test "app helper surface keeps its callable shape" {
    comptime {
        const ApiApp = struct {
            pub const StreamState = void;
            pub const ConnState = void;
        };
        const A = quic.app.Driver(ApiApp);
        _ = A.Session;
        _ = A.StreamEntry;
        _ = A.iterationHook;
        _ = A.willCloseHook;
        _ = A.init;
        _ = A.deinit;
        _ = A.service;

        // Hook signatures must keep matching the loop + Config fields
        // they are handed to.
        const iteration: *const fn (?*anyopaque, *quic.Server, u64) anyerror!void = A.iterationHook;
        const will_close: *const fn (?*anyopaque, *quic.Server.Slot) void = A.willCloseHook;
        _ = .{ iteration, will_close };

        _ = quic.app.StreamTable(void);
        _ = quic.app.Outbox;
        _ = quic.app.StreamEnd;
    }
}

test "stable observation-point fields stay reachable on Connection" {
    // API_STABILITY.md's Internal tier names these four fields as
    // *stable observation points* whose doc comments make them
    // read/write-able by embedders. Pin their types here so a future
    // rename/removal fails CI instead of silently breaking the
    // documented surface.
    comptime {
        if (std.meta.fieldInfo(quic.Connection, .last_activity_us).type != u64) {
            @compileError("Connection.last_activity_us drifted from u64");
        }
        if (std.meta.fieldInfo(quic.Connection, .ecn_enabled).type != bool) {
            @compileError("Connection.ecn_enabled drifted from bool");
        }
        if (std.meta.fieldInfo(quic.Connection, .reveal_close_reason_on_wire).type != bool) {
            @compileError("Connection.reveal_close_reason_on_wire drifted from bool");
        }
        if (std.meta.fieldInfo(quic.Connection, .delayed_ack_packet_threshold).type != u8) {
            @compileError("Connection.delayed_ack_packet_threshold drifted from u8");
        }
    }
}

test "server hostability surface keeps its callable shape" {
    const Server = quic.Server;
    comptime {
        // Embedder-owned per-connection pointer on the slot.
        if (std.meta.fieldInfo(Server.Slot, .user_data).type != ?*anyopaque) {
            @compileError("Slot.user_data drifted from ?*anyopaque");
        }
        // Pre-reap ordered-teardown hook and its Config wiring.
        _ = Server.ConnectionWillCloseCallback;
        requireDecl(Server, "nextTimerDeadline");
    }
    const next_deadline: *const fn (*const Server, u64) ?quic.TimerDeadline = Server.nextTimerDeadline;
    _ = next_deadline;

    // Per-iteration application hooks on both packaged loops.
    const server_hook_field = comptime std.meta.fieldInfo(quic.transport.RunUdpOptions, .on_iteration);
    const client_hook_field = comptime std.meta.fieldInfo(quic.transport.RunUdpClientOptions, .on_iteration);
    comptime {
        if (server_hook_field.type != ?*const fn (?*anyopaque, *quic.Server, u64) anyerror!void) {
            @compileError("RunUdpOptions.on_iteration hook signature drifted");
        }
        if (client_hook_field.type != ?*const fn (?*anyopaque, *quic.Client, u64) anyerror!void) {
            @compileError("RunUdpClientOptions.on_iteration hook signature drifted");
        }
    }
}
