//! Shared helpers for the e2e/ test suite.
//!
//! Several smoke tests need the same on-disk PEM fixtures and the
//! same "reasonable defaults" `TransportParams` block. Centralizing
//! them here keeps the per-file boilerplate small and ensures
//! everyone agrees on what "default" means.
//!
//! Tests that need a *different* shape (e.g. raising
//! `initial_max_data` for a 512 KiB upload regression) keep their
//! own inline literal — `defaultParams` is only the baseline, not
//! a constraint.

const std = @import("std");
const quic = @import("quic");

/// Self-signed test certificate. Loaded via `@embedFile` so it ships
/// with the test binary instead of being read at runtime.
pub const test_cert_pem = @embedFile("../data/test_cert.pem");

/// Matching private key for `test_cert_pem`.
pub const test_key_pem = @embedFile("../data/test_key.pem");

/// Second self-signed certificate with the same profile (EC P-256,
/// CA:TRUE, SAN localhost/127.0.0.1) but a distinct key, so mTLS
/// tests can present an identity that does NOT chain to
/// `test_cert_pem`. Regenerate with tools/gen-test-certs.sh.
pub const test_untrusted_cert_pem = @embedFile("../data/test_untrusted_cert.pem");

/// Matching private key for `test_untrusted_cert_pem`. Also serves
/// as the "well-formed but wrong key" fixture for KeyMismatch tests
/// against `test_cert_pem`.
pub const test_untrusted_key_pem = @embedFile("../data/test_untrusted_key.pem");

/// Reasonable defaults for smoke tests that don't care about
/// specific transport-parameter shapes. Mirrors the values the
/// QNS endpoint advertises by default.
pub fn defaultParams() quic.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
}

/// A leak check with no stack traces, for tests that make tens of
/// thousands of streams.
///
/// `std.testing.allocator` records a stack trace for every allocation.
/// In a Debug build that costs far more than everything else such a
/// test does. MEASURED 2026-10-03 (macOS arm64, Zig 0.17.0): with the
/// stream-window tests on it, the Debug end-to-end suite took 24 s, and
/// a profile of it was DWARF unwinder frames from top to bottom. On
/// this allocator the suite takes 8.4 s (it took 4 s before those
/// tests were written), so they have one size in every build mode.
///
/// It counts live allocations and live bytes, and that is all it does:
/// it does not find a double free or a free with the wrong length, as
/// `std.testing.allocator` does. So a file that uses it keeps a short
/// run of the same paths on `std.testing.allocator`. Call
/// `expectNoLeaks` after everything that used it is deinitialized. A
/// leak it reports has no trace: to find it, run that test once on
/// `std.testing.allocator`.
pub const LeakCounter = struct {
    parent: std.mem.Allocator = std.heap.smp_allocator,
    live_allocations: u64 = 0,
    live_bytes: u64 = 0,
    /// Do not print the counts when the check fails (this type's own
    /// test makes it fail on purpose).
    quiet: bool = false,

    pub fn allocator(self: *LeakCounter) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn expectNoLeaks(self: *const LeakCounter) !void {
        if (self.live_allocations == 0 and self.live_bytes == 0) return;
        if (!self.quiet) std.debug.print("leak: {d} allocation(s), {d} byte(s) still live\n", .{ self.live_allocations, self.live_bytes });
        return error.MemoryLeakDetected;
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = allocImpl,
        .resize = resizeImpl,
        .remap = remapImpl,
        .free = freeImpl,
    };

    fn allocImpl(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *LeakCounter = @ptrCast(@alignCast(ctx));
        const result = self.parent.vtable.alloc(self.parent.ptr, len, alignment, ret_addr);
        if (result != null) {
            self.live_allocations += 1;
            self.live_bytes += len;
        }
        return result;
    }

    fn resizeImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *LeakCounter = @ptrCast(@alignCast(ctx));
        const ok = self.parent.vtable.resize(self.parent.ptr, memory, alignment, new_len, ret_addr);
        if (ok) self.live_bytes = self.live_bytes - memory.len + new_len;
        return ok;
    }

    fn remapImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *LeakCounter = @ptrCast(@alignCast(ctx));
        const result = self.parent.vtable.remap(self.parent.ptr, memory, alignment, new_len, ret_addr);
        if (result != null) self.live_bytes = self.live_bytes - memory.len + new_len;
        return result;
    }

    fn freeImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *LeakCounter = @ptrCast(@alignCast(ctx));
        self.parent.vtable.free(self.parent.ptr, memory, alignment, ret_addr);
        self.live_allocations -= 1;
        self.live_bytes -= memory.len;
    }
};

test "LeakCounter: a live allocation fails the check, and a freed one does not" {
    // The stream tests trust this allocator to find a stream that was
    // never freed, so its own check is pinned here.
    var leaks: LeakCounter = .{ .quiet = true };
    const a = leaks.allocator();
    try leaks.expectNoLeaks();

    const one = try a.alloc(u8, 100);
    try std.testing.expectError(error.MemoryLeakDetected, leaks.expectNoLeaks());
    try std.testing.expectEqual(@as(u64, 1), leaks.live_allocations);
    try std.testing.expectEqual(@as(u64, 100), leaks.live_bytes);

    // Growth is counted in, and counted back out.
    var list: std.ArrayList(u64) = .empty;
    for (0..1000) |i| try list.append(a, i);
    try std.testing.expect(leaks.live_bytes >= 100 + 1000 * @sizeOf(u64));
    list.deinit(a);
    try std.testing.expectEqual(@as(u64, 1), leaks.live_allocations);
    try std.testing.expectEqual(@as(u64, 100), leaks.live_bytes);
    try std.testing.expectError(error.MemoryLeakDetected, leaks.expectNoLeaks());

    a.free(one);
    try leaks.expectNoLeaks();
}
