//! quic.app - opt-in application-layer helpers for connection embedders.
//!
//! Everything here sits strictly *above* the transport: it wires the
//! raw `Connection` event/stream API into typed callbacks and the
//! three state machines every custom server otherwise hand-rolls —
//! per-stream tracking, short-write staging, and sound end-of-stream
//! detection. Nothing in this module changes wire behavior; it composes
//! the stable `Server` / `Connection` surface only.
//!
//! The pieces, usable together or apart:
//!
//!   - `ConnectionDriver(App)` — a borrowing per-connection dispatcher,
//!     for accepted or dialed connections, with explicit consumption and
//!     pause support. It leaves transport ownership and timers to the caller.
//!   - `Driver(App)` — the compatible server convenience dispatcher you hand to
//!     `transport.runUdpServer` (or service yourself from a
//!     hand-rolled loop). It walks slots, drains `pollEvent`, tracks
//!     peer streams, pumps reads, and calls *typed* application
//!     callbacks: no `?*anyopaque` context, no `@ptrCast` dance, no
//!     iterator-diffing to discover connections.
//!   - `StreamTable(State)` — a fixed-capacity, typed per-stream
//!     registry with one typed `state` per stream, sized at init.
//!   - `Outbox` — iteration-resumable stream writes: `push` accepts
//!     what the connection will take and stages the refused tail for
//!     retry, making `streamWrite`'s deliberate short-write behavior
//!     invisible to application code.
//!
//! Boundary: quic-zig stays transport-only. These are stream/slot
//! utilities, not application protocol policy — request routing,
//! framing, and HTTP/3 semantics still belong to the embedder.

const std = @import("std");
const quic = @import("../root.zig");

const Connection = quic.Connection;
const ConnectionEvent = quic.ConnectionEvent;
const CloseEvent = quic.CloseEvent;

/// Why a tracked stream's service loop ended — payload of
/// `Driver`'s `onStreamEnd` callback.
///
/// LIFETIME: the table entry (and with it `entry.state`) is released
/// the moment `on_stream_end` returns, on every variant. Anything the
/// app still needs from the entry — accumulated per-stream state, the
/// final buffered bytes — must be consumed or moved INSIDE the hook;
/// a pointer kept past it dangles into a recycled slot. (The send
/// side is independent: a staged Outbox tail for the same stream id
/// keeps draining after release.)
pub const StreamEnd = union(enum) {
    /// Clean EOF: the peer FINed, every byte was delivered through
    /// `onStreamData`, and the recv half is terminal.
    fin,
    /// The peer aborted the stream with RESET_STREAM. Bytes already
    /// delivered stay delivered; no more are coming.
    reset,
    /// The stream left the connection's live table before its end was
    /// observed (the GC reaped a fully-terminal stream, or the
    /// connection is closing). Treat as done: there is nothing left
    /// to read.
    reaped,
};

/// Fixed-capacity registry of the peer streams a connection is
/// servicing, with one typed application state per stream.
///
/// `track` returns null when the table is full — never let that pass
/// silently: a stream you track-but-never-service is a wire-visible
/// hang. `Driver` responds to a full table by sending STOP_SENDING
/// (a loud, on-wire refusal) rather than accepting the stream into a
/// black hole. Size the table to the `initial_max_streams_bidi` +
/// `initial_max_streams_uni` the server advertises and a conforming
/// peer can never overflow it.
pub fn StreamTable(comptime State: type) type {
    return struct {
        const Self = @This();

        /// One tracked stream. `state` is application-owned; it lives
        /// from `track` to the matching `release` (for `Driver` users:
        /// from `onStreamOpen` to `onStreamEnd`). `track` does NOT
        /// initialize `state` — a standalone table user sets it right
        /// after tracking; the `Driver` default-constructs it when a
        /// stream is first tracked.
        pub const Entry = struct {
            id: u64 = 0,
            active: bool = false,
            /// Direction of the tracked stream (RFC 9000 §2.1: the id
            /// encodes it). The `Driver` fills this when a stream is
            /// first tracked so data/end callbacks can guard send-side
            /// calls (`outbox.push`/`finish` on a peer uni stream fail
            /// with `StreamNotWritable`). Standalone table users set
            /// it themselves or ignore it.
            bidi: bool = false,
            state: State = undefined,

            fn reset(self: *Entry) void {
                self.* = .{};
            }
        };

        allocator: std.mem.Allocator,
        entries: []Entry = &.{},

        /// Allocate a table holding `capacity` concurrently-tracked
        /// streams.
        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            const entries = try allocator.alloc(Entry, capacity);
            for (entries) |*e| e.reset();
            return .{ .allocator = allocator, .entries = entries };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.entries);
            self.entries = &.{};
        }

        /// Register `id`, reusing the first free slot. Returns null
        /// when the table is full (see the module doc for the loud
        /// refusal that should follow). Already-tracked ids are
        /// idempotent — the existing entry comes back.
        pub fn track(self: *Self, id: u64) ?*Entry {
            if (self.get(id)) |e| return e;
            for (self.entries) |*e| {
                if (e.active) continue;
                e.* = .{ .id = id, .active = true };
                return e;
            }
            return null;
        }

        /// The tracked entry for `id`, or null.
        pub fn get(self: *Self, id: u64) ?*Entry {
            for (self.entries) |*e| {
                if (e.active and e.id == id) return e;
            }
            return null;
        }

        /// Mark the entry for `id` free. No-op for untracked ids.
        pub fn release(self: *Self, id: u64) void {
            for (self.entries) |*e| {
                if (e.active and e.id == id) {
                    e.reset();
                    return;
                }
            }
        }

        /// Number of currently-tracked streams.
        pub fn count(self: *const Self) usize {
            var n: usize = 0;
            for (self.entries) |*e| {
                if (e.active) n += 1;
            }
            return n;
        }

        /// Walk the active entries. Invalidation rule: `release` on an
        /// entry invalidates that pointer only (slots are a fixed
        /// array); `track` may reuse a released slot mid-walk.
        pub const Iterator = struct {
            table: *Self,
            i: usize = 0,

            pub fn next(self: *Iterator) ?*Entry {
                while (self.i < self.table.entries.len) {
                    const e = &self.table.entries[self.i];
                    self.i += 1;
                    if (e.active) return e;
                }
                return null;
            }
        };

        pub fn iterator(self: *Self) Iterator {
            return .{ .table = self };
        }
    };
}

/// Iteration-resumable stream writes: whatever `Connection.streamWrite`
/// refuses (its short-write backpressure) is staged here and retried
/// on later passes. Admission is bounded; QueueFull accepts no bytes.
///
/// One `Outbox` per connection. Data order per stream is preserved —
/// a later `push` never jumps a staged tail. Memory is proportional
/// to staged bytes only: a stream with an empty tail costs nothing.
pub const Outbox = struct {
    allocator: std.mem.Allocator,
    tails: std.AutoHashMapUnmanaged(u64, Tail) = .empty,
    limits: Limits = .{},
    pending_bytes: usize = 0,
    reserved_bytes: usize = 0,

    /// Admission reserves room for the complete push before touching the
    /// connection. QueueFull therefore always means zero bytes accepted.
    pub const Limits = struct {
        max_streams: usize = 128,
        max_bytes: usize = 16 * 1024 * 1024,
    };

    /// One stream's staged bytes, plus whether a `finish` arrived
    /// while they were staged (delivered by `flush` after the last
    /// staged byte lands).
    const Tail = struct {
        data: std.ArrayListUnmanaged(u8) = .empty,
        fin: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator) Outbox {
        return initWithLimits(allocator, .{});
    }

    pub fn initWithLimits(allocator: std.mem.Allocator, limits: Limits) Outbox {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn pendingBytes(self: *const Outbox) usize {
        return self.pending_bytes;
    }

    pub fn pendingStreams(self: *const Outbox) usize {
        return self.tails.count();
    }

    pub fn deinit(self: *Outbox) void {
        var it = self.tails.valueIterator();
        while (it.next()) |tail| tail.data.deinit(self.allocator);
        self.tails.deinit(self.allocator);
        self.* = undefined;
    }

    /// Write `data` to stream `id`, staging whatever the connection
    /// refuses for a later `flush`. Propagates `streamWrite` errors —
    /// including `StreamNotWritable` for peer-initiated uni streams
    /// and `StreamNotFound` once the stream is reaped — and returns
    /// `error.StreamClosed` for a push after `finish`, mirroring the
    /// connection's own write-after-FIN rule.
    pub fn push(self: *Outbox, conn: *Connection, id: u64, data: []const u8) !void {
        if (self.tails.getPtr(id)) |tail| {
            if (tail.fin) return error.StreamClosed;
            if (data.len > self.limits.max_bytes -| self.reserved_bytes) return error.QueueFull;
            // Charge backing capacity as well as live bytes: if the
            // allocator cannot shrink a drained prefix, its retained memory
            // must not become unaccounted queue headroom.
            const before = tail.data.capacity;
            try tail.data.ensureTotalCapacityPrecise(self.allocator, tail.data.items.len + data.len);
            self.reserved_bytes += tail.data.capacity - before;
            tail.data.appendSliceAssumeCapacity(data);
            self.pending_bytes += data.len;
            return;
        }
        if (data.len == 0) {
            _ = try conn.streamWrite(id, data);
            return;
        }
        if (self.tails.count() >= self.limits.max_streams or
            data.len > self.limits.max_bytes -| self.reserved_bytes) return error.QueueFull;
        // Reserve the complete write before streamWrite: an allocation
        // failure after a short write must never make a retry duplicate its
        // already-accepted prefix.
        var tail: Tail = .{};
        errdefer tail.data.deinit(self.allocator);
        try tail.data.ensureTotalCapacityPrecise(self.allocator, data.len);
        tail.data.appendSliceAssumeCapacity(data);
        try self.tails.ensureUnusedCapacity(self.allocator, 1);
        const n = try conn.streamWrite(id, data);
        if (n == data.len) {
            tail.data.deinit(self.allocator);
            return;
        }
        const remaining = data.len - n;
        std.mem.copyForwards(u8, tail.data.items[0..remaining], tail.data.items[n..]);
        tail.data.shrinkAndFree(self.allocator, remaining);
        self.tails.putAssumeCapacity(id, tail);
        self.pending_bytes += remaining;
        self.reserved_bytes += tail.data.capacity;
    }

    /// Queue the FIN for stream `id`. With nothing staged this is
    /// `streamFinish` directly. With a staged tail the FIN is
    /// DEFERRED: `streamFinish` now would fix the stream's final size
    /// below the staged bytes — truncating the stream on the wire and
    /// making the next `flush` fail with `StreamClosed` — so `flush`
    /// places it after the last staged byte drains instead.
    pub fn finish(self: *Outbox, conn: *Connection, id: u64) !void {
        if (self.tails.getPtr(id)) |tail| {
            tail.fin = true;
            return;
        }
        try conn.streamFinish(id);
    }

    /// Abort stream `id` with RESET_STREAM and drop any staged tail.
    pub fn reset(self: *Outbox, conn: *Connection, id: u64, error_code: u64) !void {
        self.forget(id);
        conn.streamReset(id, error_code) catch |err| switch (err) {
            // Already reaped: nothing to abort.
            error.StreamNotFound => {},
            else => return err,
        };
    }

    /// Try to hand one stream's staged tail to the connection.
    /// Returns true when nothing remains staged for `id` (including
    /// when there never was a tail); a `finish` deferred behind the
    /// tail lands as part of that final drain. False means bytes are
    /// still staged — the connection is backpressured; retry on a
    /// later pass.
    pub fn flush(self: *Outbox, conn: *Connection, id: u64) !bool {
        const tail = self.tails.getPtr(id) orelse return true;
        const n = conn.streamWrite(id, tail.data.items) catch |err| switch (err) {
            // The stream was reaped (fully closed + GC'd); staged
            // bytes can never ship. Drop the tail.
            error.StreamNotFound, error.StreamClosed => {
                self.forget(id);
                return true;
            },
            else => return err,
        };
        const remaining = tail.data.items.len - n;
        std.mem.copyForwards(u8, tail.data.items[0..remaining], tail.data.items[n..]);
        self.pending_bytes -= n;
        const capacity_before = tail.data.capacity;
        tail.data.shrinkAndFree(self.allocator, remaining);
        self.reserved_bytes -= capacity_before - tail.data.capacity;
        if (remaining != 0) return false;
        const fin = tail.fin;
        self.forget(id);
        if (fin) {
            conn.streamFinish(id) catch |err| switch (err) {
                // Reaped between the write and the FIN: nothing to do.
                error.StreamNotFound => {},
                else => return err,
            };
        }
        return true;
    }

    /// Flush every staged tail once. Called by `Driver` at the end of
    /// each service pass; call it yourself from hand-rolled loops.
    pub fn flushAll(self: *Outbox, conn: *Connection) !void {
        // Snapshot ALL keys before removals. A fixed first-128 snapshot
        // starves later streams when those first entries stay blocked.
        const ids = try self.allocator.alloc(u64, self.tails.count());
        defer self.allocator.free(ids);
        var it = self.tails.keyIterator();
        var n: usize = 0;
        while (it.next()) |id| : (n += 1) ids[n] = id.*;
        for (ids) |id| _ = try self.flush(conn, id);
    }

    /// Bytes staged for `id` (0 when none).
    pub fn staged(self: *const Outbox, id: u64) usize {
        const tail = self.tails.get(id) orelse return 0;
        return tail.data.items.len;
    }

    /// Drop the staged tail (and any deferred FIN) for `id` without
    /// touching the stream.
    pub fn forget(self: *Outbox, id: u64) void {
        if (self.tails.fetchRemove(id)) |removed| {
            var tail = removed.value;
            self.pending_bytes -= tail.data.items.len;
            self.reserved_bytes -= tail.data.capacity;
            tail.data.deinit(self.allocator);
        }
    }
};

/// A stream/event pump borrowing one Connection, independent of its role,
/// socket, or owner. It never advances, ticks, reaps, or destroys the
/// connection. Call service before the owner's transport tick, and deinit
/// before destroying the connection. The driver and App must remain at
/// stable addresses while callbacks run; init itself stores no self pointer.
///
/// App declares ConnState and StreamState (void, optional, or a struct with
/// default fields). `state` belongs to the caller. All hooks are optional and
/// registered explicitly. A successful data hook returns the number of bytes
/// consumed; zero pauses that stream until the next service pass. Partial
/// consumption also yields, preserving QUIC receive credit for unread bytes.
/// Borrowed bytes expire when the hook returns. Hooks must not read/consume,
/// reset, or tick this same receive stream, or recursively call service.
///
/// Peer streams are discovered from connection events. Register a locally
/// opened bidirectional stream with trackStream to receive its response.
/// One driver owns event consumption for a connection; callers compose their
/// protocol dispatch in the hooks, rather than installing competing pumps.
pub fn ConnectionDriver(comptime App: type) type {
    return struct {
        const Self = @This();
        pub const Table = StreamTable(App.StreamState);
        pub const StreamEntry = Table.Entry;
        pub const Datagram = struct { bytes: []const u8, arrived_in_early_data: bool };
        pub const Hooks = struct {
            on_connect: ?*const fn (*App, *Self) anyerror!void = null,
            on_handshake: ?*const fn (*App, *Self) anyerror!void = null,
            on_stream_open: ?*const fn (*App, *Self, *StreamEntry, bool) anyerror!void = null,
            on_stream_data: ?*const fn (*App, *Self, *StreamEntry, []const u8) anyerror!usize = null,
            on_stream_end: ?*const fn (*App, *Self, *StreamEntry, StreamEnd) anyerror!void = null,
            on_datagram: ?*const fn (*App, *Self, Datagram) anyerror!void = null,
            on_close: ?*const fn (*App, *Self, CloseEvent) anyerror!void = null,
            on_event: ?*const fn (*App, *Self, ConnectionEvent) anyerror!void = null,
            on_disconnect: ?*const fn (*App, *Self) void = null,
        };
        pub const Options = struct {
            allocator: std.mem.Allocator,
            app: *App,
            conn: *Connection,
            max_tracked_streams: usize = 128,
            datagram_buf_bytes: usize = 1200,
            stream_refusal_code: u64 = 0,
            outbox_limits: Outbox.Limits = .{},
            hooks: Hooks = .{},
        };

        allocator: std.mem.Allocator,
        app: *App,
        conn: *Connection,
        state: App.ConnState = initialState(App.ConnState),
        table: Table,
        outbox: Outbox,
        datagram_buf: []u8,
        stream_refusal_code: u64,
        hooks: Hooks,
        started: bool = false,
        handshake_notified: bool = false,
        servicing: bool = false,
        active: bool = true,
        streams_refused: u64 = 0,

        pub fn streamsServiced(self: *const Self) bool {
            return self.hooks.on_stream_data != null;
        }

        pub fn refusedStreams(self: *const Self) u64 {
            return self.streams_refused;
        }

        fn consumeChunk(self: *Self, session: *Self, entry: *StreamEntry, bytes: []const u8) anyerror!usize {
            return self.hooks.on_stream_data.?(self.app, session, entry, bytes);
        }

        pub fn init(options: Options) !Self {
            var table = try Table.init(options.allocator, options.max_tracked_streams);
            errdefer table.deinit();
            const buf = try options.allocator.alloc(u8, @max(options.datagram_buf_bytes, 1));
            return .{
                .allocator = options.allocator,
                .app = options.app,
                .conn = options.conn,
                .table = table,
                .outbox = Outbox.initWithLimits(options.allocator, options.outbox_limits),
                .datagram_buf = buf,
                .stream_refusal_code = options.stream_refusal_code,
                .hooks = options.hooks,
            };
        }

        /// Exactly-once teardown for tracked streams, then connection state.
        /// The owner still owns conn and may continue its graceful close.
        pub fn deinit(self: *Self) void {
            if (!self.active) return;
            std.debug.assert(!self.servicing);
            self.active = false;
            endTrackedStreams(self, self);
            if (self.hooks.on_disconnect) |f| f(self.app, self);
            self.table.deinit();
            self.outbox.deinit();
            self.allocator.free(self.datagram_buf);
        }

        pub fn trackStream(self: *Self, id: u64) !void {
            if (!self.active) return error.DriverClosed;
            if (self.conn.streamRecvState(id) == null) return error.StreamNotReadable;
            if (!self.streamsServiced()) return error.StreamConsumerMissing;
            if (self.table.get(id) == null and self.table.count() == self.table.entries.len) return error.StreamTableFull;
            try trackConnectionStream(self, self, .{ .stream_id = id, .bidi = (id & 2) == 0 });
        }

        pub fn service(self: *Self) !void {
            if (!self.active) return error.DriverClosed;
            if (self.servicing) return error.ReentrantService;
            self.servicing = true;
            defer self.servicing = false;
            self.serviceInner() catch |err| switch (err) {
                error.ExcessiveLoad => self.conn.close(true, Connection.transport_error_excessive_load, "excessive resource use"),
                else => return err,
            };
        }

        fn serviceInner(self: *Self) !void {
            if (!self.started) {
                if (self.hooks.on_connect) |f| try f(self.app, self);
                self.started = true;
            }
            // An owner may hand us an already-authenticated connection after
            // observing its handshake event. Synthesize the notification once.
            if (self.conn.handshakeDone()) try self.dispatchHandshake(self);
            try pumpConnection(self, self);
        }

        fn dispatchHandshake(self: *Self, session: *Self) !void {
            if (self.handshake_notified) return;
            if (self.hooks.on_handshake) |f| try f(self.app, session);
            self.handshake_notified = true;
        }
    };
}

fn initialState(comptime T: type) T {
    return switch (@typeInfo(T)) {
        .void => {},
        .optional => null,
        .@"struct" => .{},
        else => @compileError("application state must be void, optional, or a default-constructible struct"),
    };
}

// Shared by the borrowed ConnectionDriver and the Server convenience Driver.
// The server adapter also bridges its historical void hook to full
// consumption. All transport ordering lives in this one pump.
fn pumpConnection(owner: anytype, session: anytype) anyerror!void {
    while (session.conn.pollEvent()) |ev| switch (ev) {
        .handshake_established => try owner.dispatchHandshake(session),
        .stream_opened => |info| try trackConnectionStream(owner, session, info),
        .close => |ev_close| if (owner.hooks.on_close) |f| try f(owner.app, session, ev_close),
        else => if (owner.hooks.on_event) |f| try f(owner.app, session, ev),
    };
    if (owner.streamsServiced()) {
        // This table has fixed storage: callbacks may open send streams
        // without invalidating our iterator over the receive registry.
        var it = session.table.iterator();
        while (it.next()) |entry| try pumpStream(owner, session, entry);
    }
    while (session.conn.receiveDatagramInfo(owner.datagram_buf)) |info| {
        if (owner.hooks.on_datagram) |f| {
            if (info.payload_len > info.len) return error.DatagramBufferTooSmall;
            try f(owner.app, session, .{
                .bytes = owner.datagram_buf[0..info.len],
                .arrived_in_early_data = info.arrived_in_early_data,
            });
        }
    }
    try session.outbox.flushAll(session.conn);
}

fn trackConnectionStream(owner: anytype, session: anytype, info: quic.StreamOpenedInfo) !void {
    if (session.table.get(info.stream_id) != null) return;
    if (!owner.streamsServiced()) {
        owner.streams_refused +|= 1;
        session.conn.streamStopSending(info.stream_id, owner.stream_refusal_code) catch {};
        return;
    }
    const entry = session.table.track(info.stream_id) orelse {
        owner.streams_refused +|= 1;
        session.conn.streamStopSending(info.stream_id, owner.stream_refusal_code) catch {};
        return;
    };
    entry.state = initialState(@TypeOf(entry.state));
    entry.bidi = info.bidi;
    if (owner.hooks.on_stream_open) |f| try f(owner.app, session, entry, info.bidi);
}

fn pumpStream(owner: anytype, session: anytype, entry: anytype) anyerror!void {
    var ended: ?StreamEnd = null;
    while (true) {
        const chunk = session.conn.streamPeek(entry.id) catch |err| switch (err) {
            error.StreamNotFound => {
                // A higher stream implicitly opens lower IDs before their
                // first frame materializes receive state. Only the connection
                // can distinguish that absence from actual terminal GC.
                if (!session.conn.streamRecvWasReaped(entry.id)) return;
                ended = .reaped;
                break;
            },
            else => return err,
        };
        if (chunk.len == 0) break;
        const n = try owner.consumeChunk(session, entry, chunk);
        if (n > chunk.len) return error.InvalidConsumedCount;
        if (n != 0) try session.conn.streamConsume(entry.id, n);
        if (n < chunk.len) return;
    }
    if (ended == null) {
        if (session.conn.streamRecvState(entry.id)) |st| {
            if (st.terminal) ended = if (st.reset_seen) .reset else .fin;
        } else ended = .reaped;
    }
    const end = ended orelse return;
    defer session.table.release(entry.id);
    if (owner.hooks.on_stream_end) |f| try f(owner.app, session, entry, end);
}

fn endTrackedStreams(owner: anytype, session: anytype) void {
    var it = session.table.iterator();
    while (it.next()) |entry| {
        if (owner.hooks.on_stream_end) |f| f(owner.app, session, entry, .reaped) catch {};
        session.table.release(entry.id);
    }
}

/// Comptime-generic application dispatcher: walks the server's slots,
/// drains each connection's event queue, tracks and services peer
/// streams, delivers inbound DATAGRAMs, and flushes staged writes —
/// then hands every occurrence to a *typed* callback on `App`.
/// (`session` / `entry` callback params are `anytype` — see the App
/// contract below for why.)
///
/// Declare `Driver(MyApp)` once; wire its hooks:
///
/// ```zig
/// const D = quic.app.Driver(MyApp);
/// var app: MyApp = .{ ... };
/// var driver = try D.init(.{
///     .allocator = allocator,
///     .app = &app,
///     .hooks = .{ .on_stream_data = MyApp.onStreamData },
/// });
/// defer driver.deinit();
///
/// var server = try quic.Server.init(.{
///     ...
///     .on_connection_will_close = D.willCloseHook,
///     .on_connection_will_close_user_data = &driver,
/// });
/// try quic.transport.runUdpServer(&server, .{
///     ...
///     .on_iteration = D.iterationHook,
///     .on_iteration_ctx = &driver,
/// });
/// ```
///
/// The `?*anyopaque` → typed cast happens exactly once, inside the
/// hooks. Application code never sees it.
///
/// ## The App contract
///
/// Registered hooks fire with typed parameters; error returns
/// propagate out of the loop verbatim — an error is the supported way
/// to stop the server. (One exception: `error.ExcessiveLoad` is
/// connection-scoped by the transport's contract and closes only the
/// over-budget connection — see `service`.) The App MUST declare `StreamState` and
/// `ConnState` (use `void` when it has no per-stream / per-connection
/// state) — the Driver allocates and frees that storage per
/// connection / stream on the App's behalf.
///
/// Callback signatures name the driver's types directly —
/// `*D.Session`, `*D.StreamEntry`, `quic.app.StreamEnd` for a
/// file-level `const D = quic.app.Driver(MyApp);` — exactly like the
/// examples. Declare `const D = quic.app.Driver(MyApp);` next to the
/// app so both sides can name each other.
///
/// ```zig
/// const D = quic.app.Driver(EchoApp);
/// const EchoApp = struct {
///     pub const StreamState = struct { chunks: u32 = 0 };
///     pub const ConnState = void;
///
///     fn onStreamData(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
///         e.state.chunks += 1;
///         try s.outbox.push(s.conn, e.id, chunk);
///     }
///
///     fn onStreamEnd(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
///         if (end == .fin) try s.outbox.finish(s.conn, e.id);
///     }
/// };
/// ```
///
/// ## Hook registration (read this if callbacks silently don't fire)
///
/// Hooks are registered in `init`, explicitly — there is no method
/// detection, on purpose (comptime `@hasDecl` against App types from
/// dependent modules proved unreliable on 0.17-dev, and a callback
/// that silently fails to register is exactly the class of bug this
/// module exists to prevent):
///
/// ```zig
/// var driver = try D.init(.{
///     .allocator = allocator,
///     .app = &app,
///     .hooks = .{
///         .on_stream_data = EchoApp.onStreamData,
///         .on_stream_end = EchoApp.onStreamEnd,
///         .on_datagram = EchoApp.onDatagram,
///     },
/// });
/// ```
///
/// Unregistered hooks do not fire. The registration site doubles as
/// the wiring checklist; when in doubt, assert:
/// `try std.testing.expect(driver.streamsServiced());`.
///
/// ## Ordering guarantees (the traps this removes)
///
/// Per service pass, in order: events drained first (so `onStreamOpen`
/// precedes any data from that stream), then stream reads (`onStreamData`
/// chunks in order; `onStreamEnd` exactly once, on `.terminal` / reset /
/// reaped — never on "empty read + FIN seen", which truncates under
/// reordering), then DATAGRAM delivery, then a staged-write flush.
/// Under `runUdpServer` this all runs before `Connection.tick`, which
/// is what keeps the stream GC from reaping a stream with unread
/// bytes. A hand-rolled loop must preserve the same order: service
/// the Driver before `conn.tick`.
///
/// Timing consequence of that order: `onStreamOpen` fires during the
/// event drain, before the same pass's stream reads — so a freshly
/// opened stream has no driver-delivered bytes at open time even when
/// the connection already buffers data; the read pump delivers it later in
/// the same pass, or in a later pass when the first bytes have not
/// arrived yet. Per-stream state armed in `onStreamOpen` must mean
/// "open, nothing observed yet" — never "data is available" or "the
/// stream's shape is decided". Observation begins at the first
/// `onStreamData` / `onStreamEnd`, not at open.
///
/// On teardown the contract stays airtight: `willCloseHook` fires
/// `onStreamEnd` (`.reaped`) for every stream the table still tracks
/// before `onDisconnect` — so per-stream state freed in `onStreamEnd`
/// is freed on abrupt disconnects too, with no app-side sweep. This
/// holds on both paths: the normal close → tick → reap cycle, and
/// `Server.deinit` with connections still live (it fires the same
/// hook per slot). No pre-`deinit` drain loop is needed to avoid
/// leaking sessions — see `willCloseHook`'s doc.
pub fn Driver(comptime App: type) type {
    // State types are REQUIRED decls (no @hasDecl probing — see the
    // hook-table note for why probes are banned in this module): an
    // App without per-stream or per-connection state declares
    // `const StreamState = void;` / `const ConnState = void;`.
    // A missing decl is a loud compile error, never a silent `void`.
    const AppConnState = App.ConnState;
    const AppStreamState = App.StreamState;

    return struct {
        const Self = @This();
        const Table = StreamTable(AppStreamState);

        /// Zero value for an app state type: `void` gets the void
        /// literal, optionals (incl. `?*T` session pointers) default
        /// to null, structs must be default-constructible (`.{}` —
        /// all fields defaulted). Anything else is a loud compile
        /// error naming the offending type.
        fn zeroState(comptime T: type) T {
            return switch (@typeInfo(T)) {
                .void => {},
                .optional => null,
                .@"struct" => .{},
                else => @compileError("App ConnState/StreamState must be void, an optional " ++
                    "(defaults to null), or a struct with every field defaulted; got " ++
                    @typeName(T)),
            };
        }

        /// Zero value for the app's per-connection state.
        const default_app_state: AppConnState = zeroState(AppConnState);

        /// Zero value for the app's per-stream state, written into the
        /// table entry when a stream is first tracked. Without this
        /// write the entry would hold whatever the slot held before —
        /// including the deinit-poisoned state of a previous stream
        /// that released the slot.
        const default_stream_state: AppStreamState = zeroState(AppStreamState);

        /// One accepted connection's driver state — allocated on first
        /// sight of the slot, freed in the will-close hook. Callbacks
        /// receive a pointer to this as their context.
        pub const Session = struct {
            /// The slot this session rides on. Its user_data remains
            /// available to the embedding application's other hooks.
            slot: *quic.Server.Slot,
            /// The QUIC connection — same object as `slot.conn`.
            conn: *Connection,
            /// Peer-stream registry (`StreamEntry.state` is
            /// `App.StreamState`).
            table: Table,
            /// Staged stream writes; flushed at the end of every pass.
            outbox: Outbox,
            /// Typed application per-connection state (`void` when
            /// the App declares `ConnState = void`).
            app: AppConnState = default_app_state,
        };

        /// One tracked peer stream — `Session.table`'s entry type.
        /// `state` is `App.StreamState` (or `void`).
        pub const StreamEntry = Table.Entry;

        pub const Options = struct {
            allocator: std.mem.Allocator,
            /// The application — whose (optional) methods become the
            /// callbacks. Must outlive the Driver.
            app: *App,
            /// Peer streams tracked per connection. Size to the
            /// stream limits the server advertises; overflow is
            /// answered with STOP_SENDING, never a silent hang.
            max_tracked_streams: usize = 128,
            /// DATAGRAM delivery buffer. Must be at least the
            /// `max_datagram_frame_size` the server advertises; a
            /// larger inbound datagram then surfaces
            /// `error.DatagramBufferTooSmall` instead of silent tail
            /// loss. Sized for the 1200 RFC floor by default.
            datagram_buf_bytes: usize = 1200,
            /// The callbacks to dispatch on, listed explicitly.
            /// Empty by default — unregistered hooks do not fire.
            hooks: Hooks = .{},
            /// Application error code sent as STOP_SENDING when the
            /// stream table is full and a peer stream must be refused.
            stream_refusal_code: u64 = 0,
            outbox_limits: Outbox.Limits = .{},
        };

        allocator: std.mem.Allocator,
        app: *App,
        /// Application error code sent as STOP_SENDING when the stream
        /// table is full (from `Options`).
        stream_refusal_code: u64,
        /// Per-connection stream-table capacity, from `Options`.
        tracked_streams: usize,
        outbox_limits: Outbox.Limits,
        datagram_buf: []u8,
        /// Callbacks registered at `init` (see the module docs'
        /// "Hook registration" section).
        hooks: Hooks,
        sessions: std.AutoHashMapUnmanaged(*quic.Server.Slot, *Session) = .empty,
        previous_close_hook: ?quic.Server.ConnectionWillCloseCallback = null,
        previous_close_context: ?*anyopaque = null,
        attached_server: ?*quic.Server = null,
        servicing: bool = false,
        streams_refused: u64 = 0,

        // ---- runtime hook table --------------------------------------
        //
        // Callbacks are typed function pointers the EMBEDDER lists in
        // `init`, and the service path dispatches on them at runtime.
        // There is no `@hasDecl`-based detection anywhere in this
        // module: evaluating it against App types from dependent
        // modules was observed (0.17-dev) to answer false regardless
        // of where it ran — struct consts, `init`, `service`, or even
        // a user-called helper — while the identical expression in the
        // embedder's own module answered true. A missed callback must
        // be a compile error or a loud registration list, never a
        // silently-false probe; explicit hooks are that list.
        //
        pub const ConnectFn = *const fn (*App, *Session) anyerror!void;
        pub const HandshakeFn = *const fn (*App, *Session) anyerror!void;
        pub const StreamOpenFn = *const fn (*App, *Session, *StreamEntry, bool) anyerror!void;
        pub const StreamDataFn = *const fn (*App, *Session, *StreamEntry, []const u8) anyerror!void;
        pub const StreamDataConsumedFn = *const fn (*App, *Session, *StreamEntry, []const u8) anyerror!usize;
        pub const StreamEndFn = *const fn (*App, *Session, *StreamEntry, StreamEnd) anyerror!void;
        pub const DatagramFn = *const fn (*App, *Session, Datagram) anyerror!void;
        pub const CloseFn = *const fn (*App, *Session, CloseEvent) anyerror!void;
        pub const EventFn = *const fn (*App, *Session, ConnectionEvent) anyerror!void;
        pub const DisconnectFn = *const fn (*App, *Session) void;

        /// One delivered DATAGRAM (RFC 9221) — `on_datagram`'s
        /// payload. Carrying the metadata alongside the bytes keeps
        /// 0-RTT-aware apps (idempotency gates keyed on
        /// `arrived_in_early_data`) from reaching into the transport
        /// mid-hook.
        pub const Datagram = struct {
            bytes: []const u8,
            /// The DATAGRAM arrived in 0-RTT (before the handshake
            /// completed) — replayable; gate side effects accordingly.
            arrived_in_early_data: bool,
        };

        /// The callback set the driver dispatches on. Construct
        /// explicitly (`.{ .on_stream_data = MyApp.onStreamData, ... }`).
        /// Hooks you do not register do not fire — assert with
        /// `driver.streamsServiced()` if unsure.
        pub const Hooks = struct {
            on_connect: ?ConnectFn = null,
            on_handshake: ?HandshakeFn = null,
            /// Fires from the event drain, BEFORE the same pass's
            /// stream reads: a freshly opened entry has no delivered
            /// bytes, even when the connection already buffers data —
            /// `onStreamData` delivers it later in the
            /// same pass (or a later one). Arm per-stream state as
            /// "open, nothing observed yet", not "data available";
            /// treat an empty peek/read at open as expected, not
            /// EOF. See the module docs' "Ordering guarantees".
            on_stream_open: ?StreamOpenFn = null,
            on_stream_data: ?StreamDataFn = null,
            /// Optional partial-consumption hook. Takes precedence over the
            /// legacy void hook; zero or partial progress yields this stream.
            on_stream_data_consumed: ?StreamDataConsumedFn = null,
            on_stream_end: ?StreamEndFn = null,
            on_datagram: ?DatagramFn = null,
            on_close: ?CloseFn = null,
            on_event: ?EventFn = null,
            on_disconnect: ?DisconnectFn = null,
        };

        pub fn init(options: Options) !Self {
            const datagram_buf = try options.allocator.alloc(u8, @max(options.datagram_buf_bytes, 1));

            return .{
                .allocator = options.allocator,
                .app = options.app,
                .stream_refusal_code = options.stream_refusal_code,
                .tracked_streams = options.max_tracked_streams,
                .outbox_limits = options.outbox_limits,
                .datagram_buf = datagram_buf,
                .hooks = options.hooks,
            };
        }

        /// The server must be destroyed before the driver. service attaches
        /// teardown automatically; no manual session sweep is required.
        pub fn deinit(self: *Self) void {
            std.debug.assert(self.sessions.count() == 0);
            self.sessions.deinit(self.allocator);
            self.allocator.free(self.datagram_buf);
            self.* = undefined;
        }

        /// Install teardown without replacing the embedder's existing hook.
        /// The prior hook runs after driver cleanup with slot.user_data
        /// unchanged. A driver may attach to one server, and must outlive it.
        pub fn attach(self: *Self, server: *quic.Server) void {
            if (self.attached_server) |attached| {
                std.debug.assert(attached == server);
                return;
            }
            self.attached_server = server;
            if (server.on_connection_will_close == willCloseHook and
                server.on_connection_will_close_user_data == @as(?*anyopaque, self)) return;
            self.previous_close_hook = server.on_connection_will_close;
            self.previous_close_context = server.on_connection_will_close_user_data;
            server.setConnectionWillCloseHook(willCloseHook, self);
        }

        /// Whether an `on_stream_data` hook was registered at `init`
        /// and streams are serviced. Instance-based: exactly what the
        /// service path dispatches on. Assert it in tests —
        /// `try std.testing.expect(driver.streamsServiced());` — so a
        /// callback that was never registered fails loudly.
        pub fn streamsServiced(self: *const Self) bool {
            return self.hooks.on_stream_data != null or self.hooks.on_stream_data_consumed != null;
        }

        pub fn refusedStreams(self: *const Self) u64 {
            return self.streams_refused;
        }

        fn consumeChunk(self: *Self, session: *Session, entry: *StreamEntry, bytes: []const u8) anyerror!usize {
            if (self.hooks.on_stream_data_consumed) |f| return f(self.app, session, entry, bytes);
            try self.hooks.on_stream_data.?(self.app, session, entry, bytes);
            return bytes.len;
        }

        /// Whether an `on_datagram` hook was registered at `init` and
        /// DATAGRAMs are delivered to the app.
        pub fn datagramsDelivered(self: *const Self) bool {
            return self.hooks.on_datagram != null;
        }

        /// The `RunUdpOptions.on_iteration` hook. Also callable
        /// directly from a hand-rolled loop, once per iteration,
        /// before any `conn.tick`.
        pub fn iterationHook(ctx: ?*anyopaque, server: *quic.Server, now_us: u64) anyerror!void {
            _ = now_us;
            const self: *Self = @ptrCast(@alignCast(ctx.?));
            try self.service(server);
        }

        /// The `Server.Config.on_connection_will_close` hook: delivers
        /// the `on_stream_end` (`.reaped`) still owed to every stream
        /// the table still tracks, fires `on_disconnect` while the
        /// session is still valid, then frees the session. This is the
        /// only place the session is destroyed, and it runs inside
        /// `reap` — the same thread as `iterationHook`, so the two
        /// never race.
        ///
        /// The synthesized ends keep the per-stream state contract
        /// airtight on abrupt disconnects: `StreamEntry.state` lives
        /// from `on_stream_open` to `on_stream_end` on EVERY path, so
        /// an app that frees its state in `on_stream_end` never leaks
        /// a mid-request stream. Errors from the callback are swallowed
        /// here — the connection is tearing down regardless and this
        /// hook cannot propagate them.
        ///
        /// Both teardown paths run this hook: the normal reap cycle
        /// (close → `tick` past draining → `reap`) AND `Server.deinit`
        /// called with connections still live (it fires the hook per
        /// slot before destroying it). So sessions and their app state
        /// free on either path — no pre-`deinit` drain loop is required
        /// just to avoid leaking them. (Draining still matters for
        /// graceful close on the wire; it is no longer a leak-safety
        /// obligation.)
        pub fn willCloseHook(ctx: ?*anyopaque, slot: *quic.Server.Slot) void {
            const self: *Self = @ptrCast(@alignCast(ctx.?));
            if (self.sessions.fetchRemove(slot)) |removed| {
                const session = removed.value;
                endTrackedStreams(self, session);
                if (self.hooks.on_disconnect) |f| f(self.app, session);
                session.table.deinit();
                session.outbox.deinit();
                self.allocator.destroy(session);
            }
            if (self.previous_close_hook) |f| f(self.previous_close_context, slot);
        }

        /// One full service pass over every live slot.
        ///
        /// Errors propagate verbatim — an app error is the supported
        /// way to stop the loop — with ONE exception:
        /// `error.ExcessiveLoad` is connection-scoped by contract
        /// (`tryReserveResidentBytes`: the over-budget connection
        /// closes with `excessive_load`), so it closes THAT
        /// connection and the pass continues. One overloaded peer
        /// must not tear down the whole server.
        pub fn service(self: *Self, server: *quic.Server) anyerror!void {
            if (self.servicing) return error.ReentrantService;
            self.servicing = true;
            defer self.servicing = false;
            self.attach(server);
            for (server.iterator()) |slot| {
                self.serviceSlot(slot) catch |err| switch (err) {
                    error.ExcessiveLoad => slot.conn.close(
                        true,
                        Connection.transport_error_excessive_load,
                        "excessive resource use",
                    ),
                    else => return err,
                };
            }
        }

        fn serviceSlot(self: *Self, slot: *quic.Server.Slot) anyerror!void {
            const session = try self.ensureSession(slot);
            try pumpConnection(self, session);
        }

        fn ensureSession(self: *Self, slot: *quic.Server.Slot) !*Session {
            if (self.sessions.get(slot)) |session| return session;
            const session = try self.allocator.create(Session);
            errdefer self.allocator.destroy(session);
            session.* = .{
                .slot = slot,
                .conn = slot.conn,
                .table = try Table.init(self.allocator, self.tracked_streams),
                .outbox = Outbox.initWithLimits(self.allocator, self.outbox_limits),
            };
            errdefer {
                session.table.deinit();
                session.outbox.deinit();
            }
            try self.sessions.put(self.allocator, slot, session);
            errdefer _ = self.sessions.remove(slot);
            if (self.hooks.on_connect) |f| try f(self.app, session);
            return session;
        }

        fn dispatchHandshake(self: *Self, session: *Session) !void {
            if (self.hooks.on_handshake) |f| try f(self.app, session);
        }

        /// The session riding on `slot`, for applications that keep
        /// their own slot references. Null before the first service
        /// pass reaches the slot.
        pub fn sessionOn(self: *const Self, slot: *quic.Server.Slot) ?*Session {
            return self.sessions.get(slot);
        }
    };
}

test "StreamTable: track, idempotence, release, full-table refusal" {
    var table = try StreamTable(u32).init(std.testing.allocator, 2);
    defer table.deinit();

    const a = table.track(0).?;
    a.state = 1;
    try std.testing.expect(table.track(0).? == a); // idempotent
    _ = table.track(4).?;
    try std.testing.expectEqual(@as(?*StreamTable(u32).Entry, null), table.track(8)); // full
    try std.testing.expectEqual(@as(usize, 2), table.count());

    table.release(0);
    try std.testing.expectEqual(@as(usize, 1), table.count());
    const c = table.track(8).?; // slot reused
    c.state = 3;
    try std.testing.expectEqual(@as(u64, 8), c.id);

    var seen: usize = 0;
    var it = table.iterator();
    while (it.next()) |e| {
        seen += 1;
        try std.testing.expect(e.active);
    }
    try std.testing.expectEqual(@as(usize, 2), seen);
}

test "StreamTable: void state type works" {
    var table = try StreamTable(void).init(std.testing.allocator, 4);
    defer table.deinit();
    const e = table.track(2).?;
    e.state = {};
    table.release(2);
}

test "Driver: optional state types (incl. ?*T session pointers) default to null" {
    // The qmsg port's friction #1: `?*T` per-connection state needed a
    // wrapper struct because the zero value only handled void/struct.
    const OptApp = struct {
        pub const StreamState = ?*u32;
        pub const ConnState = ?*u64;
    };
    const OD = Driver(OptApp);
    var app: OptApp = .{};
    var driver = try OD.init(.{ .allocator = std.testing.allocator, .app = &app });
    defer driver.deinit();
    try std.testing.expectEqual(@as(?*u64, null), OD.default_app_state);
    try std.testing.expectEqual(@as(?*u32, null), OD.default_stream_state);
}

const HookedApp = struct {
    pub const StreamState = struct { received: usize = 0 };
    pub const ConnState = struct { opens: u32 = 0 };

    fn onStreamData(_: *HookedApp, _: *HookedDriver.Session, _: *HookedDriver.StreamEntry, _: []const u8) anyerror!void {}
    fn onDatagram(_: *HookedApp, _: *HookedDriver.Session, _: HookedDriver.Datagram) anyerror!void {}
};

const HookedDriver = Driver(HookedApp);

test "Driver: explicitly registered hooks drive streamsServiced/datagramsDelivered" {
    var app: HookedApp = .{};
    var driver = try HookedDriver.init(.{
        .allocator = std.testing.allocator,
        .app = &app,
        .hooks = .{
            .on_stream_data = HookedApp.onStreamData,
            .on_datagram = HookedApp.onDatagram,
        },
    });
    defer driver.deinit();
    try std.testing.expect(driver.streamsServiced());
    try std.testing.expect(driver.datagramsDelivered());

    const BareApp = struct {
        pub const StreamState = void;
        pub const ConnState = void;
    };
    var bare: BareApp = .{};
    var bare_driver = try Driver(BareApp).init(.{
        .allocator = std.testing.allocator,
        .app = &bare,
    });
    defer bare_driver.deinit();
    try std.testing.expect(!bare_driver.streamsServiced());
    try std.testing.expect(!bare_driver.datagramsDelivered());
}

const TestConnCtx = struct {
    allocator: std.mem.Allocator,
    tls: @import("boringssl").tls.Context,

    conn: *Connection,

    fn deinit(self: *TestConnCtx) void {
        self.conn.destroy();
        self.tls.deinit();
    }
};

fn testConn(allocator: std.mem.Allocator) !TestConnCtx {
    const boringssl = @import("boringssl");
    var tls = try boringssl.tls.Context.initClient(.{});
    errdefer tls.deinit();
    const conn = try Connection.createClient(allocator, tls, "x");
    return .{ .allocator = allocator, .tls = tls, .conn = conn };
}

test "Outbox: full acceptance stages nothing; short writes stage, retry, and preserve order" {
    const allocator = std.testing.allocator;
    var ctx = try testConn(allocator);
    defer ctx.deinit();

    var outbox = Outbox.init(allocator);
    defer outbox.deinit();

    const s = try ctx.conn.openNextBidi();
    const stream = ctx.conn.stream(s.id).?;

    // Full acceptance: nothing staged.
    try outbox.push(ctx.conn, s.id, "hello");
    try std.testing.expectEqual(@as(usize, 0), outbox.staged(s.id));
    try std.testing.expectEqual(@as(u64, 5), stream.send.writtenBytes());

    // Cap the send buffer so the next push short-writes: the refused
    // tail is staged, and a subsequent push queues BEHIND it (a direct
    // write would jump the staged bytes on the wire).
    stream.send.max_buffered = 8;
    try outbox.push(ctx.conn, s.id, "0123456789"); // 3 fit, 7 staged
    try std.testing.expectEqual(@as(usize, 7), outbox.staged(s.id));
    try outbox.push(ctx.conn, s.id, "XYZ"); // queued behind the tail
    try std.testing.expectEqual(@as(usize, 10), outbox.staged(s.id));
    try std.testing.expectEqual(@as(u64, 8), stream.send.writtenBytes());

    // Room opens up: flush drains everything, in order.
    stream.send.max_buffered = 64;
    try std.testing.expect(try outbox.flush(ctx.conn, s.id));
    try std.testing.expectEqual(@as(usize, 0), outbox.staged(s.id));
    try std.testing.expectEqual(@as(u64, 18), stream.send.writtenBytes());

    const chunk = stream.send.peekChunk(64).?;
    try std.testing.expectEqualStrings("hello0123456789XYZ", stream.send.chunkBytes(chunk));

    // finish queues the FIN without disturbing anything.
    try outbox.finish(ctx.conn, s.id);
    try std.testing.expect(stream.send.hasPendingChunk());
}

test "Outbox: forget drops the staged tail only; reset also aborts the send half" {
    const allocator = std.testing.allocator;
    var ctx = try testConn(allocator);
    defer ctx.deinit();

    var outbox = Outbox.init(allocator);
    defer outbox.deinit();

    const s = try ctx.conn.openNextBidi();
    const stream = ctx.conn.stream(s.id).?;
    stream.send.max_buffered = 4;

    // Stage a tail, then forget it: staged bytes vanish, but the
    // stream itself is untouched — no reset, accepted bytes intact.
    try outbox.push(ctx.conn, s.id, "0123456789"); // 4 fit, 6 staged
    try std.testing.expectEqual(@as(usize, 6), outbox.staged(s.id));
    outbox.forget(s.id);
    try std.testing.expectEqual(@as(usize, 0), outbox.staged(s.id));
    try std.testing.expectEqual(@as(u64, 4), stream.send.writtenBytes());
    try std.testing.expect(stream.send.reset == null);

    // Re-stage (buffer is still full, so everything queues), then
    // reset: the tail drops AND the send half aborts with the code.
    try outbox.push(ctx.conn, s.id, "abcdef");
    try std.testing.expectEqual(@as(usize, 6), outbox.staged(s.id));
    try outbox.reset(ctx.conn, s.id, 7);
    try std.testing.expectEqual(@as(usize, 0), outbox.staged(s.id));
    try std.testing.expect(stream.send.reset != null);

    // Reset of an unknown (reaped) stream is a no-op, not an error.
    try outbox.reset(ctx.conn, 40, 0);
}

test "Outbox: finish with a staged tail defers the FIN until the tail drains" {
    const allocator = std.testing.allocator;
    var ctx = try testConn(allocator);
    defer ctx.deinit();

    var outbox = Outbox.init(allocator);
    defer outbox.deinit();

    const s = try ctx.conn.openNextBidi();
    const stream = ctx.conn.stream(s.id).?;
    stream.send.max_buffered = 8;

    // 8 accepted, 8 staged; finish must NOT land yet — an immediate
    // streamFinish would fix final_size at 8, truncating the staged
    // tail on the wire and poisoning the flush with StreamClosed.
    try outbox.push(ctx.conn, s.id, "0123456789ABCDEF");
    try std.testing.expectEqual(@as(usize, 8), outbox.staged(s.id));
    try outbox.finish(ctx.conn, s.id);
    try std.testing.expect(!stream.send.fin_marked);

    // Write-after-finish through the Outbox mirrors the stream rule.
    try std.testing.expectError(error.StreamClosed, outbox.push(ctx.conn, s.id, "x"));

    // Partial drain: room for 4 of the 8 staged bytes. flush reports
    // "still staged", and the FIN stays deferred.
    stream.send.max_buffered = 12;
    try std.testing.expect(!try outbox.flush(ctx.conn, s.id));
    try std.testing.expectEqual(@as(usize, 4), outbox.staged(s.id));
    try std.testing.expect(!stream.send.fin_marked);

    // Full drain: the tail lands, and the FIN lands AFTER it — at
    // final size 16, the true end of the stream.
    stream.send.max_buffered = 64;
    try std.testing.expect(try outbox.flush(ctx.conn, s.id));
    try std.testing.expectEqual(@as(usize, 0), outbox.staged(s.id));
    try std.testing.expectEqual(@as(u64, 16), stream.send.writtenBytes());
    try std.testing.expect(stream.send.fin_marked);
    try std.testing.expectEqual(@as(?u64, 16), stream.send.final_size);

    const chunk = stream.send.peekChunk(64).?;
    try std.testing.expectEqualStrings("0123456789ABCDEF", stream.send.chunkBytes(chunk));
}

const ProgressApp = struct {
    pub const ConnState = ?*u8;
    pub const StreamState = struct { received: usize = 0 };
    const C = ConnectionDriver(@This());
    limit: usize = 0,
    received: usize = 0,
    opens: usize = 0,
    ends: usize = 0,
    disconnects: usize = 0,
    last_end: ?StreamEnd = null,

    fn data(app: *ProgressApp, driver: *C, entry: *C.StreamEntry, bytes: []const u8) anyerror!usize {
        try std.testing.expectError(error.ReentrantService, driver.service());
        const n = @min(bytes.len, app.limit);
        entry.state.received += n;
        app.received += n;
        return n;
    }
    fn opened(app: *ProgressApp, _: *C, _: *C.StreamEntry, _: bool) anyerror!void {
        app.opens += 1;
    }
    fn ended(app: *ProgressApp, _: *C, _: *C.StreamEntry, end: StreamEnd) anyerror!void {
        app.ends += 1;
        app.last_end = end;
    }
    fn disconnected(app: *ProgressApp, _: *C) void {
        app.disconnects += 1;
    }
    fn hooks() C.Hooks {
        return .{ .on_stream_open = opened, .on_stream_data = data, .on_stream_end = ended, .on_disconnect = disconnected };
    }
};

fn receivingTestConn(allocator: std.mem.Allocator) !TestConnCtx {
    const ctx = try testConn(allocator);
    try ctx.conn.setTransportParams(quic.Server.Config.defaultTransportParams());
    return ctx;
}

test "ConnectionDriver: paused and partial reads retain receive credit and FIN until consumed" {
    var ctx = try receivingTestConn(std.testing.allocator);
    defer ctx.deinit();
    var app: ProgressApp = .{};
    var driver = try ProgressApp.C.init(.{ .allocator = std.testing.allocator, .app = &app, .conn = ctx.conn, .hooks = ProgressApp.hooks() });
    defer driver.deinit();
    try ctx.conn.handleStream(.application, .{ .stream_id = 3, .offset = 0, .data = "abcdef", .fin = true });
    try driver.service();
    try std.testing.expectEqual(@as(u64, 0), ctx.conn.streamRecvState(3).?.read_offset);
    try std.testing.expectEqual(@as(u64, 0), ctx.conn.recv_stream_bytes_read);
    try std.testing.expectEqual(@as(usize, 0), app.ends);
    try std.testing.expectEqual(@as(usize, 1), driver.table.count());
    app.limit = 2;
    try driver.service();
    try std.testing.expectEqual(@as(u64, 2), ctx.conn.streamRecvState(3).?.read_offset);
    try std.testing.expectEqual(@as(usize, 0), app.ends);
    try driver.service();
    try driver.service();
    try std.testing.expectEqual(@as(usize, 6), app.received);
    try std.testing.expectEqual(@as(usize, 1), app.ends);
    try std.testing.expectEqual(StreamEnd.fin, app.last_end.?);
    try std.testing.expectEqual(@as(usize, 0), driver.table.count());
    try driver.service();
    try std.testing.expectEqual(@as(usize, 1), app.ends);
}

test "ConnectionDriver: local bidi receive tracking, reset and teardown each end once" {
    var ctx = try receivingTestConn(std.testing.allocator);
    defer ctx.deinit();
    var app: ProgressApp = .{};
    var driver = try ProgressApp.C.init(.{ .allocator = std.testing.allocator, .app = &app, .conn = ctx.conn, .hooks = ProgressApp.hooks() });
    const local = try ctx.conn.openNextBidi();
    try driver.trackStream(local.id);
    try driver.trackStream(local.id);
    try std.testing.expectEqual(@as(usize, 1), app.opens);
    try ctx.conn.handleStream(.application, .{ .stream_id = local.id, .offset = 0, .data = "reply", .fin = false });
    try driver.service();
    try ctx.conn.handleResetStream(.{ .stream_id = local.id, .application_error_code = 4, .final_size = 5 });
    try driver.service();
    try std.testing.expectEqual(StreamEnd.reset, app.last_end.?);
    try std.testing.expectEqual(@as(usize, 1), app.ends);
    try ctx.conn.handleStream(.application, .{ .stream_id = 3, .offset = 0, .data = "pending", .fin = false });
    try driver.service();
    driver.deinit();
    driver.deinit();
    try std.testing.expectEqual(@as(usize, 2), app.ends);
    try std.testing.expectEqual(StreamEnd.reaped, app.last_end.?);
    try std.testing.expectEqual(@as(usize, 1), app.disconnects);
    try std.testing.expectError(error.DriverClosed, driver.service());
    // Borrowing the connection never transfers its ownership.
    try std.testing.expect(ctx.conn.stream(3) != null);
}

test "ConnectionDriver: implicit lower streams wait for reordered first data" {
    for ([_]u64{ 1, 3 }) |first_id| {
        var ctx = try receivingTestConn(std.testing.allocator);
        defer ctx.deinit();
        var app: ProgressApp = .{ .limit = 100 };
        var driver = try ProgressApp.C.init(.{ .allocator = std.testing.allocator, .app = &app, .conn = ctx.conn, .hooks = ProgressApp.hooks() });
        defer driver.deinit();
        // A higher peer stream implicitly opens every lower stream of its
        // type, but their Stream allocations need not exist before data lands.
        try ctx.conn.handleStream(.application, .{ .stream_id = first_id + 4, .data = "later", .fin = true });
        try driver.service();
        try std.testing.expectEqual(@as(usize, 2), app.opens);
        try std.testing.expectEqual(@as(usize, 1), app.ends);
        try std.testing.expectEqual(@as(usize, 1), driver.table.count());
        try ctx.conn.tick(1000);
        try driver.service();
        try std.testing.expectEqual(@as(usize, 1), app.ends);
        try ctx.conn.handleStream(.application, .{ .stream_id = first_id, .data = "first", .fin = true });
        try driver.service();
        try std.testing.expectEqual(@as(usize, 10), app.received);
        try std.testing.expectEqual(@as(usize, 2), app.ends);
        try std.testing.expectEqual(StreamEnd.fin, app.last_end.?);
        try std.testing.expectEqual(@as(usize, 0), driver.table.count());
    }
}

test "ConnectionDriver: an observed receive stream still ends once when its owner reaps it" {
    var ctx = try receivingTestConn(std.testing.allocator);
    defer ctx.deinit();
    var app: ProgressApp = .{ .limit = 100 };
    var driver = try ProgressApp.C.init(.{ .allocator = std.testing.allocator, .app = &app, .conn = ctx.conn, .hooks = ProgressApp.hooks() });
    defer driver.deinit();
    const stream = try ctx.conn.openNextBidi();
    const sid = stream.id;
    try driver.trackStream(sid);
    try ctx.conn.streamFinish(sid);
    stream.send.fin_acked = true;
    stream.send.state = .data_recvd;
    try ctx.conn.handleResetStream(.{ .stream_id = sid, .application_error_code = 0, .final_size = 0 });
    try ctx.conn.tick(1000);
    try std.testing.expect(ctx.conn.stream(sid) == null);
    try driver.service();
    try std.testing.expectEqual(@as(usize, 1), app.ends);
    try std.testing.expectEqual(StreamEnd.reaped, app.last_end.?);
    try std.testing.expectEqual(@as(usize, 0), driver.table.count());
    try driver.service();
    try std.testing.expectEqual(@as(usize, 1), app.ends);
}

test "ConnectionDriver: an implicit unobserved stream ends if terminal input is reaped before service" {
    for ([_]bool{ false, true }) |reset| {
        var ctx = try receivingTestConn(std.testing.allocator);
        defer ctx.deinit();
        var app: ProgressApp = .{ .limit = 100 };
        var driver = try ProgressApp.C.init(.{ .allocator = std.testing.allocator, .app = &app, .conn = ctx.conn, .hooks = ProgressApp.hooks() });
        defer driver.deinit();
        try ctx.conn.handleStream(.application, .{ .stream_id = 7, .data = "later", .fin = true });
        try driver.service();
        try std.testing.expectEqual(@as(usize, 1), app.ends);
        if (reset) try ctx.conn.handleResetStream(.{ .stream_id = 3, .application_error_code = 0, .final_size = 0 }) else try ctx.conn.handleStream(.application, .{ .stream_id = 3, .data = "", .fin = true });
        try ctx.conn.tick(1000);
        try std.testing.expect(ctx.conn.stream(3) == null);
        try driver.service();
        try std.testing.expectEqual(@as(usize, 2), app.ends);
        try std.testing.expectEqual(StreamEnd.reaped, app.last_end.?);
        try std.testing.expectEqual(@as(usize, 0), driver.table.count());
    }
}

test "Outbox: admission is bounded and rejected writes never accept a prefix" {
    var ctx = try testConn(std.testing.allocator);
    defer ctx.deinit();
    var outbox = Outbox.initWithLimits(std.testing.allocator, .{ .max_streams = 1, .max_bytes = 8 });
    defer outbox.deinit();
    const first = try ctx.conn.openNextBidi();
    first.send.max_buffered = 2;
    try outbox.push(ctx.conn, first.id, "abcd");
    try std.testing.expectEqual(@as(usize, 2), outbox.pendingBytes());
    try std.testing.expectError(error.QueueFull, outbox.push(ctx.conn, first.id, "1234567"));
    try std.testing.expectEqual(@as(u64, 2), first.send.writtenBytes());
    const second = try ctx.conn.openNextBidi();
    try std.testing.expectError(error.QueueFull, outbox.push(ctx.conn, second.id, "x"));
    try std.testing.expectEqual(@as(u64, 0), second.send.writtenBytes());
    try std.testing.expectEqual(@as(usize, 1), outbox.pendingStreams());
    first.send.max_buffered = 32;
    try outbox.flushAll(ctx.conn);
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingBytes());
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingStreams());
    try outbox.push(ctx.conn, second.id, "x");
    try std.testing.expectEqual(@as(u64, 1), second.send.writtenBytes());
}

test "Outbox: blocked early entries never starve later streams beyond 128" {
    var ctx = try testConn(std.testing.allocator);
    defer ctx.deinit();
    var outbox = Outbox.initWithLimits(std.testing.allocator, .{ .max_streams = 256, .max_bytes = 256 });
    defer outbox.deinit();
    for (0..160) |_| {
        const stream = try ctx.conn.openNextBidi();
        stream.send.max_buffered = 0;
        try outbox.push(ctx.conn, stream.id, "x");
    }
    var last: u64 = undefined;
    var it = outbox.tails.keyIterator();
    while (it.next()) |id| last = id.*;
    ctx.conn.stream(last).?.send.max_buffered = 1;
    try outbox.flushAll(ctx.conn);
    try std.testing.expectEqual(@as(usize, 0), outbox.staged(last));
    try std.testing.expectEqual(@as(usize, 159), outbox.pendingBytes());
}

test "ConnectionDriver: capacity refusal is visible and isolated to the incoming stream" {
    var ctx = try receivingTestConn(std.testing.allocator);
    defer ctx.deinit();
    var app: ProgressApp = .{};
    var driver = try ProgressApp.C.init(.{ .allocator = std.testing.allocator, .app = &app, .conn = ctx.conn, .max_tracked_streams = 1, .stream_refusal_code = 42, .hooks = ProgressApp.hooks() });
    defer driver.deinit();
    try ctx.conn.handleStream(.application, .{ .stream_id = 3, .offset = 0, .data = "first", .fin = false });
    try ctx.conn.handleStream(.application, .{ .stream_id = 7, .offset = 0, .data = "second", .fin = false });
    try driver.service();
    try std.testing.expectEqual(@as(usize, 1), driver.table.count());
    try std.testing.expectEqual(@as(u64, 1), driver.refusedStreams());
    try std.testing.expectEqual(@as(usize, 1), ctx.conn.pending_frames.stop_sending.items.len);
    try std.testing.expectEqual(@as(u64, 7), ctx.conn.pending_frames.stop_sending.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 42), ctx.conn.pending_frames.stop_sending.items[0].application_error_code);
    try std.testing.expect(!ctx.conn.isClosed());
}

test "Outbox: allocation failure before a short write leaves the stream unchanged" {
    var ctx = try testConn(std.testing.allocator);
    defer ctx.deinit();
    const stream = try ctx.conn.openNextBidi();
    stream.send.max_buffered = 2;
    // The old write-first implementation accepted two bytes before this
    // allocation failed, so blindly retrying the same push duplicated them.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var outbox = Outbox.init(failing.allocator());
    defer outbox.deinit();
    try std.testing.expectError(error.OutOfMemory, outbox.push(ctx.conn, stream.id, "abcd"));
    try std.testing.expectEqual(@as(u64, 0), stream.send.writtenBytes());
    try std.testing.expectEqual(@as(usize, 0), outbox.pendingBytes());
}

test "ConnectionDriver: invalid consumption never advances the receive cursor" {
    const InvalidApp = struct {
        pub const ConnState = void;
        pub const StreamState = void;
        const C = ConnectionDriver(@This());
        fn data(_: *@This(), _: *C, _: *C.StreamEntry, bytes: []const u8) anyerror!usize {
            return bytes.len + 1;
        }
    };
    var ctx = try receivingTestConn(std.testing.allocator);
    defer ctx.deinit();
    var app: InvalidApp = .{};
    var driver = try InvalidApp.C.init(.{ .allocator = std.testing.allocator, .app = &app, .conn = ctx.conn, .hooks = .{ .on_stream_data = InvalidApp.data } });
    defer driver.deinit();
    try ctx.conn.handleStream(.application, .{ .stream_id = 3, .offset = 0, .data = "abc", .fin = true });
    try std.testing.expectError(error.InvalidConsumedCount, driver.service());
    try std.testing.expectEqual(@as(u64, 0), ctx.conn.streamRecvState(3).?.read_offset);
}
