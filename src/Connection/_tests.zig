// Aggregator for the per-area Connection test files (split from the
// former 8.4k-line monolith). state.zig's test hook imports this file;
// each area file below is reached through this comptime block.

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
