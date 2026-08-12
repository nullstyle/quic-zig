// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const EncryptionLevel = state.EncryptionLevel;
const level_mod = state.level_mod;

test "EncryptionLevel idx round-trip" {
    inline for (level_mod.all) |lvl| {
        try std.testing.expectEqual(lvl.idx(), @intFromEnum(lvl));
    }
}
