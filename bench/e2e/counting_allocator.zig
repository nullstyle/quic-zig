//! Allocator wrapper that counts calls and bytes, for allocation
//! accounting in the e2e benchmarks ("does the steady-state transfer
//! allocate?" is a headline claim and needs a number behind it).

const std = @import("std");

pub const CountingAllocator = struct {
    parent: std.mem.Allocator,
    allocs: u64 = 0,
    frees: u64 = 0,
    resizes: u64 = 0,
    remaps: u64 = 0,
    bytes_allocated: u64 = 0,
    live_bytes: u64 = 0,
    peak_live_bytes: u64 = 0,

    pub fn init(parent: std.mem.Allocator) CountingAllocator {
        return .{ .parent = parent };
    }

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub const Snapshot = struct {
        allocs: u64,
        frees: u64,
        resizes: u64,
        remaps: u64,
        bytes_allocated: u64,
        live_bytes: u64,
        peak_live_bytes: u64,

        /// Counter movement from `before` to `after` (live/peak are
        /// carried from `after` as-is).
        pub fn since(after: Snapshot, before: Snapshot) Snapshot {
            return .{
                .allocs = after.allocs - before.allocs,
                .frees = after.frees - before.frees,
                .resizes = after.resizes - before.resizes,
                .remaps = after.remaps - before.remaps,
                .bytes_allocated = after.bytes_allocated - before.bytes_allocated,
                .live_bytes = after.live_bytes,
                .peak_live_bytes = after.peak_live_bytes,
            };
        }
    };

    pub fn snapshot(self: *const CountingAllocator) Snapshot {
        return .{
            .allocs = self.allocs,
            .frees = self.frees,
            .resizes = self.resizes,
            .remaps = self.remaps,
            .bytes_allocated = self.bytes_allocated,
            .live_bytes = self.live_bytes,
            .peak_live_bytes = self.peak_live_bytes,
        };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = allocImpl,
        .resize = resizeImpl,
        .remap = remapImpl,
        .free = freeImpl,
    };

    fn allocImpl(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.parent.vtable.alloc(self.parent.ptr, len, alignment, ret_addr);
        if (result != null) {
            self.allocs += 1;
            self.bytes_allocated += len;
            self.live_bytes += len;
            if (self.live_bytes > self.peak_live_bytes) self.peak_live_bytes = self.live_bytes;
        }
        return result;
    }

    fn resizeImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ok = self.parent.vtable.resize(self.parent.ptr, memory, alignment, new_len, ret_addr);
        if (ok) {
            self.resizes += 1;
            self.adjustLive(memory.len, new_len);
        }
        return ok;
    }

    fn remapImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.parent.vtable.remap(self.parent.ptr, memory, alignment, new_len, ret_addr);
        if (result != null) {
            self.remaps += 1;
            self.adjustLive(memory.len, new_len);
        }
        return result;
    }

    fn freeImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.parent.vtable.free(self.parent.ptr, memory, alignment, ret_addr);
        self.frees += 1;
        self.live_bytes -= memory.len;
    }

    fn adjustLive(self: *CountingAllocator, old_len: usize, new_len: usize) void {
        if (new_len >= old_len) {
            const grow = new_len - old_len;
            self.bytes_allocated += grow;
            self.live_bytes += grow;
            if (self.live_bytes > self.peak_live_bytes) self.peak_live_bytes = self.live_bytes;
        } else {
            self.live_bytes -= old_len - new_len;
        }
    }
};

test "counts allocations, frees, and live bytes back to zero" {
    var counting = CountingAllocator.init(std.testing.allocator);
    const a = counting.allocator();

    const one = try a.alloc(u8, 100);
    try std.testing.expectEqual(@as(u64, 1), counting.allocs);
    try std.testing.expectEqual(@as(u64, 100), counting.live_bytes);

    var list: std.ArrayList(u32) = .empty;
    for (0..1000) |i| try list.append(a, @intCast(i));
    try std.testing.expect(counting.allocs > 1);
    try std.testing.expect(counting.peak_live_bytes >= 100 + 1000 * @sizeOf(u32));

    list.deinit(a);
    a.free(one);
    try std.testing.expectEqual(@as(u64, 0), counting.live_bytes);
    try std.testing.expectEqual(counting.allocs + counting.remaps, counting.frees + counting.remaps);
}

test "snapshot delta isolates a phase" {
    var counting = CountingAllocator.init(std.testing.allocator);
    const a = counting.allocator();

    const setup = try a.alloc(u8, 64);
    defer a.free(setup);

    const before = counting.snapshot();
    const phase = try a.alloc(u8, 32);
    a.free(phase);
    const delta = counting.snapshot().since(before);
    try std.testing.expectEqual(@as(u64, 1), delta.allocs);
    try std.testing.expectEqual(@as(u64, 1), delta.frees);
    try std.testing.expectEqual(@as(u64, 32), delta.bytes_allocated);
}
