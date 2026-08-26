//! Comment-anchor lint: every security rationale must cite something a
//! reader can open — an RFC section or a self-contained mechanism name.
//!
//! History: the repo's comments used to cite section numbers of an
//! internal security guide that was never written, so every rationale
//! pointed at a document nobody could open. Commit 4a3ecdd repointed
//! all 27 of them; later work reintroduced ~40 more, cleaned up again
//! alongside the v0.17.0 release. This lint keeps the third wave out:
//! it walks the repo's Zig sources and fails on any comment that cites
//! the ghost document by name or by section style.

const std = @import("std");

// Built by concatenation so this file never contains the banned byte
// sequences itself.
const banned = [_][]const u8{
    "hardening" ++ " guide",
    "hardening" ++ " §",
    "guide" ++ " §",
};

const roots = [_][]const u8{ "src", "tests", "examples", "bench", "tools" };

test "no comment cites the ghost security guide" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // `zig build test` runs from the package root; if the tree is not
    // visible from cwd (foreign harness), skip rather than false-fail.
    std.Io.Dir.cwd().access(io, "build.zig", .{}) catch return error.SkipZigTest;

    var offenders: usize = 0;
    for (roots) |root| {
        var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch continue;
        defer dir.close(io);
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
            // Skip caches and hidden trees (e.g. vendored .zig-cache).
            if (entry.path[0] == '.' or
                std.mem.indexOf(u8, entry.path, "zig-cache") != null or
                std.mem.indexOf(u8, entry.path, "/.") != null) continue;
            const bytes = entry.dir.readFileAlloc(io, entry.basename, allocator, .limited(8 * 1024 * 1024)) catch continue;
            defer allocator.free(bytes);
            offenders += scanFile(root, entry.path, bytes);
        }
    }
    if (offenders != 0) {
        std.debug.print(
            "{d} comment(s) cite the ghost security guide — repoint each " ++
                "to the governing RFC section or a self-contained mechanism " ++
                "name (see this lint's header and commit 4a3ecdd)\n",
            .{offenders},
        );
        return error.GhostGuideCitation;
    }
}

fn scanFile(root: []const u8, sub_path: []const u8, bytes: []const u8) usize {
    var hits: usize = 0;
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        line_no += 1;
        for (banned) |needle| {
            if (containsIgnoreCase(line, needle)) {
                std.debug.print("{s}/{s}:{d}: {s}\n", .{
                    root, sub_path, line_no, std.mem.trim(u8, line, " \t"),
                });
                hits += 1;
                break;
            }
        }
    }
    return hits;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |i| {
        if (std.ascii.startsWithIgnoreCase(haystack[i..], needle)) return true;
    }
    return false;
}
