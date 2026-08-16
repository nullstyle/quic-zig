// Aggregator for the per-area Connection test files (split from the
// former 8.4k-line monolith). Connection.zig's test hook imports this file;
// each area file below is reached through this comptime block.

const std = @import("std");
const state = @import("../Connection.zig");

// The method-syntax alias block at the bottom of Connection.zig is a
// hand-maintained ~229-line list of `pub const handleX =
// conn_spoke.handleX;` pairs. A typo there silently re-binds a public
// method to the wrong free function (the SendBatch case in commit
// 652c7bd was exactly this). Sample every spoke with a
// pointer-equality check so a wrong or stale alias becomes a compile
// error.
test "method-syntax aliases point at their spoke free-functions" {
    comptime {
        if (state.handleOnePacket != @import("recv_dispatch.zig").handleOnePacket) {
            @compileError("Connection.handleOnePacket is not recv_dispatch.handleOnePacket");
        }
        if (state.handleCrypto != @import("recv_data_handlers.zig").handleCrypto) {
            @compileError("Connection.handleCrypto is not recv_data_handlers.handleCrypto");
        }
        if (state.handleStream != @import("recv_data_handlers.zig").handleStream) {
            @compileError("Connection.handleStream is not recv_data_handlers.handleStream");
        }
        if (state.handleNewConnectionId != @import("recv_cid_token_handlers.zig").handleNewConnectionId) {
            @compileError("Connection.handleNewConnectionId is not recv_cid_token_handlers.handleNewConnectionId");
        }
        if (state.registerPeerCidForTesting != @import("cids.zig").registerPeerCidForTesting) {
            @compileError("Connection.registerPeerCidForTesting is not cids.registerPeerCidForTesting");
        }
        if (state.handleAckAtLevel != @import("recv_ack_handlers.zig").handleAckAtLevel) {
            @compileError("Connection.handleAckAtLevel is not recv_ack_handlers.handleAckAtLevel");
        }
        if (state.pollDatagram != @import("send.zig").pollDatagram) {
            @compileError("Connection.pollDatagram is not send.pollDatagram");
        }
        if (state.dispatchFrames != @import("recv_dispatch.zig").dispatchFrames) {
            @compileError("Connection.dispatchFrames is not recv_dispatch.dispatchFrames");
        }
    }
}

test {
    _ = @import("_tests_cids.zig");
    _ = @import("_tests_datagram.zig");
    _ = @import("_tests_delivery.zig");
    _ = @import("_tests_flow.zig");
    _ = @import("_tests_fuzz.zig");
    _ = @import("_tests_keys.zig");
    _ = @import("_tests_lifecycle.zig");
    _ = @import("_tests_loss.zig");
    _ = @import("_tests_migration.zig");
    _ = @import("_tests_misc.zig");
    _ = @import("_tests_pacing.zig");
    _ = @import("_tests_paths.zig");
    _ = @import("_tests_qlog.zig");
    _ = @import("_tests_recv.zig");
    _ = @import("_tests_send.zig");
    _ = @import("_tests_streams.zig");
    _ = @import("_tests_version.zig");
}
