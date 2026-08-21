//! quic.app - opt-in application-layer helpers for server embedders.
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
//!   - `Driver(App)` — a comptime-generic dispatcher you hand to
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
/// on later passes, so application writes are fire-and-forget.
///
/// One `Outbox` per connection. Data order per stream is preserved —
/// a later `push` never jumps a staged tail. Memory is proportional
/// to staged bytes only: a stream with an empty tail costs nothing.
pub const Outbox = struct {
    allocator: std.mem.Allocator,
    tails: std.AutoHashMapUnmanaged(u64, Tail) = .empty,

    /// One stream's staged bytes, plus whether a `finish` arrived
    /// while they were staged (delivered by `flush` after the last
    /// staged byte lands).
    const Tail = struct {
        data: std.ArrayListUnmanaged(u8) = .empty,
        fin: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator) Outbox {
        return .{ .allocator = allocator };
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
            // Order: a live tail means the connection is already
            // backpressured — a direct write would jump the queue.
            try tail.data.appendSlice(self.allocator, data);
            return;
        }
        const n = try conn.streamWrite(id, data);
        if (n == data.len) return;
        var tail: Tail = .{};
        errdefer tail.data.deinit(self.allocator);
        try tail.data.appendSlice(self.allocator, data[n..]);
        try self.tails.put(self.allocator, id, tail);
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
            error.StreamNotFound => {
                self.forget(id);
                return true;
            },
            else => return err,
        };
        const remaining = tail.data.items.len - n;
        std.mem.copyForwards(u8, tail.data.items[0..remaining], tail.data.items[n..]);
        tail.data.items.len = remaining;
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
        // Key snapshot first: a successful flush removes entries,
        // which would invalidate an in-place map iterator.
        var ids: [128]u64 = undefined;
        while (true) {
            var n: usize = 0;
            var it = self.tails.keyIterator();
            while (it.next()) |id| {
                if (n == ids.len) break;
                ids[n] = id.*;
                n += 1;
            }
            if (n == 0) return;
            var progress = false;
            for (ids[0..n]) |id| {
                if (!try self.flush(conn, id)) continue;
                progress = true;
            }
            // Everything still staged refused to move: backpressured
            // across the board — retry on the next pass.
            if (!progress) return;
        }
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
            tail.data.deinit(self.allocator);
        }
    }
};

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

        /// Zero value for the app's per-connection state. `void` needs
        /// the void literal; every other `ConnState` must be
        /// default-constructible (`.{}` — all fields defaulted).
        const default_app_state: AppConnState = if (AppConnState == void) {} else .{};

        /// Zero value for the app's per-stream state, written into the
        /// table entry when a stream is first tracked. Same rule as
        /// `ConnState`: `void` or default-constructible. Without this
        /// write the entry would hold whatever the slot held before —
        /// including the deinit-poisoned state of a previous stream
        /// that released the slot.
        const default_stream_state: AppStreamState = if (AppStreamState == void) {} else .{};

        /// One accepted connection's driver state — allocated on first
        /// sight of the slot, freed in the will-close hook. Callbacks
        /// receive a pointer to this as their context.
        pub const Session = struct {
            /// The slot this session rides on (`slot_id`, `peer_addr`,
            /// `user_data` = this session's allocation).
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
            /// Read-chunk scratch, shared across streams. 4 KiB
            /// mirrors the canonical examples.
            read_chunk_bytes: usize = 4096,
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
        };

        allocator: std.mem.Allocator,
        app: *App,
        /// Application error code sent as STOP_SENDING when the stream
        /// table is full (from `Options`).
        stream_refusal_code: u64,
        /// Per-connection stream-table capacity, from `Options`.
        tracked_streams: usize,
        read_chunk: []u8,
        datagram_buf: []u8,
        /// Callbacks registered at `init` (see the module docs'
        /// "Hook registration" section).
        hooks: Hooks,

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
        pub const StreamEndFn = *const fn (*App, *Session, *StreamEntry, StreamEnd) anyerror!void;
        pub const DatagramFn = *const fn (*App, *Session, []const u8) anyerror!void;
        pub const CloseFn = *const fn (*App, *Session, CloseEvent) anyerror!void;
        pub const EventFn = *const fn (*App, *Session, ConnectionEvent) anyerror!void;
        pub const DisconnectFn = *const fn (*App, *Session) void;

        /// The callback set the driver dispatches on. Construct
        /// explicitly (`.{ .on_stream_data = MyApp.onStreamData, ... }`).
        /// Hooks you do not register do not fire — assert with
        /// `driver.streamsServiced()` if unsure.
        pub const Hooks = struct {
            on_connect: ?ConnectFn = null,
            on_handshake: ?HandshakeFn = null,
            on_stream_open: ?StreamOpenFn = null,
            on_stream_data: ?StreamDataFn = null,
            on_stream_end: ?StreamEndFn = null,
            on_datagram: ?DatagramFn = null,
            on_close: ?CloseFn = null,
            on_event: ?EventFn = null,
            on_disconnect: ?DisconnectFn = null,
        };

        pub fn init(options: Options) !Self {
            const read_chunk = try options.allocator.alloc(u8, @max(options.read_chunk_bytes, 1));
            errdefer options.allocator.free(read_chunk);
            const datagram_buf = try options.allocator.alloc(u8, @max(options.datagram_buf_bytes, 1));

            return .{
                .allocator = options.allocator,
                .app = options.app,
                .stream_refusal_code = options.stream_refusal_code,
                .tracked_streams = @max(options.max_tracked_streams, 1),
                .read_chunk = read_chunk,
                .datagram_buf = datagram_buf,
                .hooks = options.hooks,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.read_chunk);
            self.allocator.free(self.datagram_buf);
            self.* = undefined;
        }

        /// Whether an `on_stream_data` hook was registered at `init`
        /// and streams are serviced. Instance-based: exactly what the
        /// service path dispatches on. Assert it in tests —
        /// `try std.testing.expect(driver.streamsServiced());` — so a
        /// callback that was never registered fails loudly.
        pub fn streamsServiced(self: *const Self) bool {
            return self.hooks.on_stream_data != null;
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
            const session = sessionOf(slot) orelse return;
            if (self.hooks.on_stream_end) |f| {
                var it = session.table.iterator();
                while (it.next()) |entry| {
                    f(self.app, session, entry, .reaped) catch {};
                    session.table.release(entry.id);
                }
            }
            if (self.hooks.on_disconnect) |f| f(self.app, session);
            session.table.deinit();
            session.outbox.deinit();
            self.allocator.destroy(session);
            slot.user_data = null;
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
            try self.drainEvents(session);
            if (self.hooks.on_stream_data != null) try self.serviceStreams(session);
            try self.serviceDatagrams(session);
            try session.outbox.flushAll(session.conn);
        }

        fn sessionOf(slot: *quic.Server.Slot) ?*Session {
            const ptr = slot.user_data orelse return null;
            return @ptrCast(@alignCast(ptr));
        }

        fn ensureSession(self: *Self, slot: *quic.Server.Slot) !*Session {
            if (sessionOf(slot)) |session| return session;
            const session = try self.allocator.create(Session);
            errdefer self.allocator.destroy(session);
            session.* = .{
                .slot = slot,
                .conn = slot.conn,
                .table = try Table.init(self.allocator, self.tracked_streams),
                .outbox = Outbox.init(self.allocator),
            };
            // A failing on_connect must unwind COMPLETELY: table and
            // outbox freed, slot pointer cleared — otherwise
            // `willCloseHook` (or the next pass) dereferences a freed
            // session through the stale `user_data`.
            errdefer {
                session.table.deinit();
                session.outbox.deinit();
                slot.user_data = null;
            }
            slot.user_data = session;
            if (self.hooks.on_connect) |f| try f(self.app, session);
            return session;
        }

        fn drainEvents(self: *Self, session: *Session) anyerror!void {
            while (session.conn.pollEvent()) |ev| switch (ev) {
                .handshake_established => {
                    if (self.hooks.on_handshake) |f| try f(self.app, session);
                },
                .stream_opened => |info| {
                    try self.onStreamOpened(session, info);
                },
                .close => |close_ev| {
                    if (self.hooks.on_close) |f| try f(self.app, session, close_ev);
                },
                else => {
                    if (self.hooks.on_event) |f| try f(self.app, session, ev);
                },
            };
        }

        fn onStreamOpened(self: *Self, session: *Session, info: quic.StreamOpenedInfo) !void {
            // With neither stream hook registered nothing can ever
            // read, observe, or release this stream — tracking it
            // would be the silent black hole this module bans. Refuse
            // loudly instead, exactly like a full table. (Datagram- or
            // event-only apps get wire-visible refusals for free.)
            if (self.hooks.on_stream_data == null and self.hooks.on_stream_open == null) {
                session.conn.streamStopSending(info.stream_id, self.stream_refusal_code) catch {};
                return;
            }
            // Fresh-only state init: `track` is idempotent, and a
            // re-track of a live stream must not wipe its state.
            const fresh = session.table.get(info.stream_id) == null;
            const entry = session.table.track(info.stream_id) orelse {
                // Loud refusal: a stream we cannot service must be
                // told to stop, or the peer waits forever on bytes we
                // will never read. A queueing failure here is almost
                // certainly OOM — the connection is doomed regardless
                // — so the frame is best-effort.
                session.conn.streamStopSending(info.stream_id, self.stream_refusal_code) catch {};
                return;
            };
            if (fresh) {
                entry.state = default_stream_state;
                entry.bidi = info.bidi;
            }
            if (self.hooks.on_stream_open) |f| try f(self.app, session, entry, info.bidi);
        }

        fn serviceStreams(self: *Self, session: *Session) anyerror!void {
            var it = session.table.iterator();
            while (it.next()) |entry| {
                try self.serviceStream(session, entry);
            }
        }

        fn serviceStream(self: *Self, session: *Session, entry: *StreamEntry) anyerror!void {
            var ended: ?StreamEnd = null;

            read_loop: while (true) {
                const res = session.conn.streamReadFin(entry.id, self.read_chunk) catch |err| switch (err) {
                    // The stream already left the live table (reaped
                    // after both halves went terminal). Done.
                    error.StreamNotFound => {
                        ended = .reaped;
                        break :read_loop;
                    },
                    else => return err,
                };
                if (res.n > 0) {
                    try self.hooks.on_stream_data.?(self.app, session, entry, self.read_chunk[0..res.n]);
                }
                // An empty read means "nothing readable right now" —
                // including a reordering hole below the read offset.
                // Never an EOF signal; the terminal test below is.
                if (res.n == 0) break :read_loop;
            }

            if (ended == null) {
                if (session.conn.streamRecvState(entry.id)) |st| {
                    if (st.terminal) ended = if (st.reset_seen) .reset else .fin;
                } else {
                    ended = .reaped;
                }
            }

            const end = ended orelse return; // more to come on a later pass
            // Deferred so the release happens even when the hook
            // errors: "onStreamEnd exactly once" must hold — a resumed
            // loop or the teardown sweep must never deliver a second
            // end for this stream. The recv half is done; any staged
            // *send* tail lives on in the Outbox until it drains (the
            // response to this stream's request is typically still in
            // flight) — which is why the table and the Outbox release
            // at different times.
            defer session.table.release(entry.id);
            if (self.hooks.on_stream_end) |f| try f(self.app, session, entry, end);
        }

        fn serviceDatagrams(self: *Self, session: *Session) anyerror!void {
            while (true) {
                const info = session.conn.receiveDatagramInfo(self.datagram_buf) orelse break;
                if (self.hooks.on_datagram) |f| {
                    // With `Options.datagram_buf_bytes` sized to the
                    // advertised `max_datagram_frame_size` this is
                    // unreachable; anything less fails loudly instead
                    // of silently dropping the tail.
                    if (info.payload_len > info.len) return error.DatagramBufferTooSmall;
                    try f(self.app, session, self.datagram_buf[0..info.len]);
                }
                // Without an `onDatagram` callback the payload is
                // dropped by design — but it is still popped: a full
                // inbound DATAGRAM queue makes the *transport* close
                // the connection (protocol violation), so draining is
                // mandatory even for datagram-agnostic applications.
            }
        }

        /// The session riding on `slot`, for applications that keep
        /// their own slot references. Null before the first service
        /// pass reaches the slot.
        pub fn sessionOn(self: *const Self, slot: *quic.Server.Slot) ?*Session {
            _ = self;
            return sessionOf(slot);
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

const HookedApp = struct {
    pub const StreamState = struct { received: usize = 0 };
    pub const ConnState = struct { opens: u32 = 0 };

    fn onStreamData(_: *HookedApp, _: *HookedDriver.Session, _: *HookedDriver.StreamEntry, _: []const u8) anyerror!void {}
    fn onDatagram(_: *HookedApp, _: *HookedDriver.Session, _: []const u8) anyerror!void {}
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
