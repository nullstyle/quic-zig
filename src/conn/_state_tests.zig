// Aggregator for the per-area Connection test files (split from the
// former 8.4k-line monolith). state.zig's test hook imports this file;
// each area file below is reached through this comptime block.

comptime {
    _ = @import("_state_tests_cids.zig");
    _ = @import("_state_tests_datagram.zig");
    _ = @import("_state_tests_flow.zig");
    _ = @import("_state_tests_fuzz.zig");
    _ = @import("_state_tests_keys.zig");
    _ = @import("_state_tests_lifecycle.zig");
    _ = @import("_state_tests_loss.zig");
    _ = @import("_state_tests_migration.zig");
    _ = @import("_state_tests_misc.zig");
    _ = @import("_state_tests_pacing.zig");
    _ = @import("_state_tests_paths.zig");
    _ = @import("_state_tests_qlog.zig");
    _ = @import("_state_tests_recv.zig");
    _ = @import("_state_tests_send.zig");
    _ = @import("_state_tests_streams.zig");
    _ = @import("_state_tests_version.zig");
}
