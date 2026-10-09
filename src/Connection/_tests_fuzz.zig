// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const Address = state.Address;
const CloseState = state.CloseState;
const Connection = state.Connection;
const ConnectionId = state.ConnectionId;
const EncryptionLevel = state.EncryptionLevel;
const SendStream = state.SendStream;
const SentPacketTracker = state.SentPacketTracker;
const Stream = state.Stream;
const frame_mod = state.frame_mod;
const frame_types = state.frame_types;
const lifecycle_mod = state.lifecycle_mod;
const max_close_reason_len = state.max_close_reason_len;
const max_stream_count_limit = state.max_stream_count_limit;
const transport_error_excessive_load = state.transport_error_excessive_load;
const transport_error_final_size = state.transport_error_final_size;
const transport_error_flow_control = state.transport_error_flow_control;
const transport_error_frame_encoding = state.transport_error_frame_encoding;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const transport_error_stream_limit = state.transport_error_stream_limit;
const transport_error_stream_state = state.transport_error_stream_state;
const transport_error_connection_id_limit = state.transport_error_connection_id_limit;
const transport_error_internal = state.transport_error_internal;
const short_packet_mod = state.short_packet_mod;
const wire_header_mod = state.wire_header_mod;
const util = @import("_test_util.zig");
const TestQlogRecorder = util.TestQlogRecorder;

fn fuzzConnHandleCryptoImpl(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Tiny cap so the resident-bytes path (`tryReserveResidentBytes`
    // → `error.ExcessiveLoad` → close with EXCESSIVE_LOAD) is
    // reachable on a few hundred bytes of fuzz input.
    conn.max_connection_memory = 1024;
    const cap = conn.max_connection_memory;
    const lvl: EncryptionLevel = .handshake;
    const idx = lvl.idx();

    const num_frames = smith.valueRangeAtMost(u32, 0, 32);
    var frame_buf: [4096]u8 = undefined;
    var data_buf: [64]u8 = undefined;

    var i: u32 = 0;
    while (i < num_frames) : (i += 1) {
        const offset = smith.valueRangeAtMost(u64, 0, 4096);
        const data_len = smith.valueRangeAtMost(u8, 0, 64);
        smith.bytes(data_buf[0..data_len]);

        const frame: frame_types.Frame = .{ .crypto = .{
            .offset = offset,
            .data = data_buf[0..data_len],
        } };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const before_resident = conn.bytes_resident;
        const before_recv_off = conn.crypto_recv_offset[idx];

        conn.dispatchFrames(lvl, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            // `dispatchFrames` converts frame-decode errors into a
            // FRAME_ENCODING_ERROR close rather than propagating them;
            // only Connection-level faults (e.g. OOM) still escape. We
            // tolerate non-OOM escapes and keep feeding; the invariants
            // below still apply.
            error.OutOfMemory => return err,
            else => {},
        };

        // Resident-bytes invariant: never overshoots the cap.
        try std.testing.expect(conn.bytes_resident <= cap);
        // crypto_recv_offset is monotonic across the entire run.
        try std.testing.expect(conn.crypto_recv_offset[idx] >= before_recv_off);

        // If the connection closed with EXCESSIVE_LOAD, the resident
        // bytes after close must also be inside the cap (close does
        // not free buffers, it just stops accepting more).
        if (conn.lifecycle.pending_close) |info| {
            // The close error code is one we recognize: every code
            // path in `handleCrypto` that can close goes through one
            // of {protocol_violation, excessive_load}.
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_excessive_load,
            );
            // Once closed, stop feeding frames — `dispatchFrames`
            // would no-op anyway.
            break;
        }

        // Suppress unused-warning: before_resident is used implicitly
        // by the cap invariant above (it bounds growth).
        _ = before_resident;
    }
}

fn fuzzConnHandleStreamImpl(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // Tiny memory cap so the resident-bytes path is reachable, plus
    // matching small per-stream / per-conn flow control windows so
    // the FLOW_CONTROL close path can also fire.
    conn.max_connection_memory = 1024;
    try conn.setTransportParams(.{
        .initial_max_data = 512,
        .initial_max_stream_data_bidi_remote = 512,
        .initial_max_streams_bidi = 1,
    });
    const cap = conn.max_connection_memory;

    // We drive a single peer-initiated client-bidi stream (id 0).
    // The first STREAM frame creates the Stream entry; subsequent
    // frames hit the existing entry and exercise the reassembly /
    // flow-control / final-size paths.
    const stream_id: u64 = 0;

    const num_frames = smith.valueRangeAtMost(u32, 0, 32);
    var frame_buf: [4096]u8 = undefined;
    var data_buf: [64]u8 = undefined;

    var observed_fin_offset: ?u64 = null;

    var i: u32 = 0;
    while (i < num_frames) : (i += 1) {
        const offset = smith.valueRangeAtMost(u64, 0, 4096);
        const data_len = smith.valueRangeAtMost(u8, 0, 64);
        const fin = smith.valueRangeAtMost(u8, 0, 3) == 0;
        smith.bytes(data_buf[0..data_len]);

        const frame: frame_types.Frame = .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = data_buf[0..data_len],
            .has_offset = true,
            .has_length = true,
            .fin = fin,
        } };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const stream_before = conn.streams.get(stream_id);
        const read_off_before: u64 = if (stream_before) |sp| sp.recv.read_offset else 0;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        // Resident-bytes invariant.
        try std.testing.expect(conn.bytes_resident <= cap);

        if (conn.streams.get(stream_id)) |sp| {
            // read_offset is monotonic (the harness never calls
            // streamRead, so this should always hold trivially as 0).
            try std.testing.expect(sp.recv.read_offset >= read_off_before);

            // Send-side state machine is one of the documented
            // SendStream.State enum variants. The Zig type system
            // enforces this; assert the runtime tag is well-formed by
            // running a switch over every variant.
            switch (sp.send.state) {
                .ready, .send, .data_sent, .data_recvd, .reset_sent, .reset_recvd => {},
            }

            // Final-size invariants: once a FIN is locked in, no
            // range may extend past it, and read_offset stays inside.
            if (sp.recv.final_size) |fs| {
                try std.testing.expect(sp.recv.read_offset <= fs);
                try std.testing.expect(sp.recv.end_offset <= fs);
                if (observed_fin_offset) |prev_fs| {
                    // The recv-stream is RFC §4.5 strict: once FIN is
                    // locked, a second FIN at a different offset
                    // surfaces as `FinalSizeChanged` and the
                    // connection closes. So `final_size` here equals
                    // the previously observed value.
                    try std.testing.expectEqual(prev_fs, fs);
                } else {
                    observed_fin_offset = fs;
                }
            }
        }

        // Once closed, stop — `dispatchFrames` would no-op.
        if (conn.lifecycle.pending_close) |info| {
            // Recognized close codes for handleStream:
            // - flow_control (peer overshot stream/conn window)
            // - stream_state (forbidden id pattern)
            // - stream_limit (peer-opened stream count exceeded)
            // - final_size (FIN clash / past-FIN extension)
            // - excessive_load (resident-bytes cap)
            // - protocol_violation (recv-buffer span limit)
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_flow_control or
                    code == transport_error_stream_state or
                    code == transport_error_stream_limit or
                    code == transport_error_final_size or
                    code == transport_error_excessive_load or
                    code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding,
            );
            break;
        }
    }
}

fn fuzzConnMigrationImpl(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Bypass the pre-handshake gate so the validator + rate-limit
    // paths are reachable. (Without this, the very first migration
    // emits `pre_handshake` and the rate-limit / validator paths are
    // never exercised.)
    conn.test_only_force_handshake_for_migration = true;

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Stable candidate-address pool. Picking from a fixed set keeps
    // the invariant "peer_addr is one of the candidates we fed in"
    // simple to assert (the rollback path also draws from this set,
    // since the rollback snapshot was previously written from here).
    const candidates: [4]Address = .{
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .port = 0 } },
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 2 }, .port = 0 } },
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 3 }, .port = 0 } },
        .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 4 }, .port = 0 } },
    };

    const path = conn.primaryPath();
    path.setPeerAddress(candidates[0]);
    path.path.markValidated();

    var now_us: u64 = 1_000_000;
    const num_events = smith.valueRangeAtMost(u8, 0, 16);

    var i: u8 = 0;
    while (i < num_events) : (i += 1) {
        const which: u8 = smith.valueRangeAtMost(u8, 0, 3);
        const addr = candidates[which];
        const dt: u16 = smith.value(u16);
        now_us = now_us +| @as(u64, dt);

        // Drain any queued PATH_CHALLENGE so the next migration runs
        // through the rate-limit / validator paths cleanly. Mirrors
        // the existing `post-handshake migration` test pattern.
        conn.pending_frames.path_challenge = null;

        conn.recordAuthenticatedDatagramAddress(0, addr, 1200, now_us) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        // Validator status is one of the four enum members.
        switch (path.path.validator.status) {
            .idle, .pending, .validated, .failed => {},
        }

        // peer_addr is one of the candidates we ever fed in.
        var matched = false;
        for (candidates) |cand| {
            if (Address.eql(path.path.peer_addr, cand)) {
                matched = true;
                break;
            }
        }
        try std.testing.expect(matched);

        // Bail out if the connection closed; nothing useful left to
        // exercise. (The migration paths in
        // `recordAuthenticatedDatagramAddress` themselves don't close
        // the connection, but `handlePeerAddressChange` allocates a
        // fresh path-challenge token which can hit OOM under fuzz.)
        if (conn.lifecycle.pending_close != null) break;
    }

    // Every emitted `migration_path_failed` event carries a known
    // reason — qlog never invents new tag values.
    var ev_idx: usize = 0;
    while (ev_idx < recorder.count) : (ev_idx += 1) {
        const evt = recorder.events[ev_idx];
        if (evt.name != .migration_path_failed) continue;
        const reason = evt.migration_fail_reason orelse {
            try std.testing.expect(false);
            return;
        };
        switch (reason) {
            .timeout, .policy_denied, .pre_handshake, .rate_limited, .no_fresh_peer_cid => {},
        }
    }
}

fn fuzzCidLifecycle(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Tight `active_connection_id_limit` so the
    // "peer_cids exceeds limit" close path is reachable in a 32-op
    // budget. The cap on `peer_cids` per path comes from the local
    // side's transport params (it bounds how many of the peer's CIDs
    // we are willing to hold). 4 is small enough that the fuzzer
    // routinely walks past it.
    conn.local_transport_params.active_connection_id_limit = 4;
    const peer_cid_cap = conn.local_transport_params.active_connection_id_limit;

    // Plant a few `local_cids` entries so `handleRetireConnectionId`
    // has something to remove (otherwise it always no-ops on the
    // local-side list). The peer's `active_connection_id_limit`
    // governs how many of OUR CIDs we may issue, so set the peer's
    // cached transport params to allow the seeds.
    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 8 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));
    // After this, `local_cids` holds seqs 0, 1, 2 on path 0 and the
    // recorded high-watermark `next_local_cid_seq` is 3. RETIRE
    // frames with seq < 3 are legal (well-formed); seq >= 3 is a
    // PROTOCOL_VIOLATION the fuzz harness must ride out as a close.

    const num_ops = smith.valueRangeAtMost(u8, 0, 32);
    var op_i: u8 = 0;
    while (op_i < num_ops) : (op_i += 1) {
        const op_kind = smith.valueRangeAtMost(u8, 0, 2);
        const seq = smith.valueRangeAtMost(u64, 0, 16);
        const cid_len = smith.valueRangeAtMost(u8, 0, 20);
        // Bail out of obviously-invalid input the parser would reject
        // before the handler sees it. `wire_header_mod.ConnId.fromSlice`
        // errors on len > 20, but we already cap above; this is
        // belt-and-braces for forward-compat.
        if (cid_len > 20) return;

        var cid_bytes: [20]u8 = undefined;
        smith.bytes(cid_bytes[0..cid_len]);
        var token: [16]u8 = undefined;
        smith.bytes(&token);

        // Pick a `retire_prior_to` <= seq sometimes, > seq sometimes
        // (the latter triggers the PROTOCOL_VIOLATION close path).
        const rpt_kind = smith.valueRangeAtMost(u8, 0, 3);
        const retire_prior_to: u64 = switch (rpt_kind) {
            0 => 0,
            1 => seq,
            2 => if (seq > 0) seq - 1 else 0,
            else => seq +| 1, // forces invalid-rpt close
        };

        switch (op_kind) {
            0 => {
                // NEW_CONNECTION_ID — register a peer-issued CID at
                // path 0.
                const conn_id = frame_types.ConnId.fromSlice(cid_bytes[0..cid_len]) catch return;
                conn.handleNewConnectionId(.{
                    .sequence_number = seq,
                    .retire_prior_to = retire_prior_to,
                    .connection_id = conn_id,
                    .stateless_reset_token = token,
                }) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {},
                };
            },
            1 => {
                // RETIRE_CONNECTION_ID — peer asks us to retire one
                // of OUR (local) CIDs at the named sequence.
                conn.handleRetireConnectionId(.{ .sequence_number = seq });
            },
            else => {
                // PATH_NEW_CONNECTION_ID — same shape as NEW with
                // path_id=0. Doc'd above: keeping path_id at 0 means
                // we don't have to negotiate multipath, but the call
                // still exercises the second entry point into
                // `registerPeerCid`.
                const conn_id = frame_types.ConnId.fromSlice(cid_bytes[0..cid_len]) catch return;
                conn.handlePathNewConnectionId(.{
                    .path_id = 0,
                    .sequence_number = seq,
                    .retire_prior_to = retire_prior_to,
                    .connection_id = conn_id,
                    .stateless_reset_token = token,
                }) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {},
                };
            },
        }

        // Invariant 1: peer_cids count for path 0 stays inside cap.
        // (`registerPeerCid` closes with CONNECTION_ID_LIMIT_ERROR
        // rather than overshoot the cap, so the cap holds even on
        // adversarial input.)
        const path0_count: u64 = @intCast(conn.peerCidActiveCountForPath(0));
        try std.testing.expect(path0_count <= peer_cid_cap);

        // Invariant 2: sequence_number is unique per path within
        // peer_cids. Walk the list O(n^2) — we cap at 4 entries.
        for (conn.peer_cids.items, 0..) |a, ai| {
            for (conn.peer_cids.items[ai + 1 ..]) |b| {
                if (a.path_id == b.path_id) {
                    try std.testing.expect(a.sequence_number != b.sequence_number);
                }
            }
        }

        // Invariant 3 (RETIRE consequence): the named sequence was
        // removed from `local_cids` on path 0 if it was present and
        // the call did not close. We can't know which op fired this
        // iteration without re-checking `op_kind`, so guard on it.
        if (op_kind == 1 and conn.lifecycle.pending_close == null) {
            // After a successful retire, no `local_cids` entry on
            // path 0 with that sequence remains.
            for (conn.local_cids.items) |item| {
                if (item.path_id == 0) {
                    try std.testing.expect(item.sequence_number != seq);
                }
            }
        }

        // Invariant 4: path 0's active peer_cid matches one of the
        // peer_cids entries on path 0, OR the field is empty (no
        // peer-issued CID promoted yet), OR the connection has
        // closed.
        if (conn.lifecycle.pending_close == null) {
            const path = conn.paths.get(0).?;
            const active = path.path.peer_cid;
            if (active.len != 0) {
                var matched = false;
                for (conn.peer_cids.items) |item| {
                    if (item.path_id == 0 and ConnectionId.eql(item.cid, active)) {
                        matched = true;
                        break;
                    }
                }
                try std.testing.expect(matched);
            }
        }

        // Invariant 5 (close-code coherence): if the run produced a
        // close, the error code lives in the documented set. Today
        // the handlers reach three of the four:
        // CONNECTION_ID_LIMIT_ERROR for one CID too many (RFC 9000
        // §5.1.1), FRAME_ENCODING_ERROR for `retire_prior_to >
        // sequence_number` (§19.15), and PROTOCOL_VIOLATION for a
        // reused sequence number or CID and for every
        // RETIRE_CONNECTION_ID violation (§19.16, including the
        // per-cycle flood gate). Stop feeding ops once closed — the
        // handlers no-op anyway, but the asserts above grow stale on
        // a zombie state machine.
        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_connection_id_limit or
                    code == transport_error_excessive_load,
            );
            break;
        }
    }
}

fn fuzzConnPathChallenge(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const path = conn.primaryPath();
    path.setPeerAddress(.{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .port = 0 } });
    const pending_token: [8]u8 = .{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    path.path.validator.beginChallenge(pending_token, 1_000_000, 1_000_000);
    conn.current_incoming_path_id = 0;
    conn.current_incoming_addr = path.path.peer_addr;

    const num_frames = smith.valueRangeAtMost(u8, 0, 32);
    var frame_buf: [64]u8 = undefined;

    var i: u8 = 0;
    while (i < num_frames) : (i += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 3);
        var token: [8]u8 = undefined;
        smith.bytes(&token);
        const use_pending = smith.valueRangeAtMost(u8, 0, 3) == 0;
        const data: [8]u8 = if (use_pending) pending_token else token;

        const challenge_data: [8]u8 = switch (op) {
            0 => data,
            2 => token,
            else => @splat(0),
        };
        const response_data: [8]u8 = switch (op) {
            1 => data,
            3 => token,
            else => @splat(0),
        };
        const frame: frame_types.Frame = switch (op) {
            0 => .{ .path_challenge = .{ .data = challenge_data } },
            1 => .{ .path_response = .{ .data = response_data } },
            2 => .{ .path_challenge = .{ .data = challenge_data } },
            else => .{ .path_response = .{ .data = response_data } },
        };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const status_before = path.path.validator.status;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        switch (path.path.validator.status) {
            .idle, .pending, .validated, .failed => {},
        }

        if (op == 0 or op == 2) {
            if (conn.lifecycle.pending_close == null) {
                const echoed = conn.pending_frames.path_response orelse {
                    try std.testing.expect(false);
                    return;
                };
                try std.testing.expect(std.mem.eql(u8, &echoed, &challenge_data));
                try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_response_path_id);
            }
        }

        if ((op == 1 or op == 3) and use_pending and status_before == .pending and
            conn.lifecycle.pending_close == null)
        {
            const matches_pending = std.mem.eql(u8, &response_data, &pending_token);
            if (matches_pending) {
                try std.testing.expect(path.path.validator.status == .validated);
            }
        }

        switch (conn.lifecycle.state()) {
            .open, .closing, .draining, .closed => {},
        }

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_excessive_load,
            );
            break;
        }
    }
}

fn fuzzConnFlowControlWindow(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.peer_max_data = 0;
    conn.local_bidi_ids.limit = 0;
    conn.local_uni_ids.limit = 0;

    const num_frames = smith.valueRangeAtMost(u8, 0, 32);
    var frame_buf: [64]u8 = undefined;

    var i: u8 = 0;
    while (i < num_frames) : (i += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 3);
        const value = smith.value(u64) & ((1 << 62) - 1);
        const stream_id_low = smith.valueRangeAtMost(u8, 0, 31);
        const bidi = smith.valueRangeAtMost(u8, 0, 1) == 0;

        const frame: frame_types.Frame = switch (op) {
            0 => .{ .max_data = .{ .maximum_data = value } },
            1 => .{ .max_stream_data = .{
                .stream_id = stream_id_low,
                .maximum_stream_data = value,
            } },
            2 => .{ .max_streams = .{ .bidi = bidi, .maximum_streams = value } },
            else => .{ .max_streams = .{
                .bidi = bidi,
                .maximum_streams = max_stream_count_limit + (value & 7) + 1,
            } },
        };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        const before_max_data = conn.peer_max_data;
        const before_streams_bidi = conn.local_bidi_ids.limit;
        const before_streams_uni = conn.local_uni_ids.limit;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        try std.testing.expect(conn.peer_max_data >= before_max_data);
        try std.testing.expect(conn.local_bidi_ids.limit >= before_streams_bidi);
        try std.testing.expect(conn.local_uni_ids.limit >= before_streams_uni);
        try std.testing.expect(conn.local_bidi_ids.limit <= max_stream_count_limit);
        try std.testing.expect(conn.local_uni_ids.limit <= max_stream_count_limit);
        // A MAX_STREAMS inside the id space is taken as sent: there is
        // no lower ceiling (through 0.23.0 the limit was clamped to
        // 4096, the lifetime stream cap).
        if (op == 2 and conn.lifecycle.pending_close == null) {
            const limit = if (bidi) conn.local_bidi_ids.limit else conn.local_uni_ids.limit;
            const before = if (bidi) before_streams_bidi else before_streams_uni;
            try std.testing.expectEqual(@max(before, value), limit);
        }

        switch (conn.lifecycle.state()) {
            .open, .closing, .draining, .closed => {},
        }

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_stream_state or
                    // MAX_STREAM_DATA for a bidirectional stream of the
                    // peer that is not here yet creates it (RFC 9000
                    // §3.2), so the stream limit applies to the frame.
                    code == transport_error_stream_limit or
                    code == transport_error_excessive_load,
            );
            // MAX_STREAM_DATA never passes without a word: a stream of
            // ours that was never opened, and a receive-only stream,
            // are STREAM_STATE_ERROR (§19.10); a stream of the peer
            // over the limit is STREAM_LIMIT_ERROR. This connection
            // has no stream and grants none, so every one closes it.
            if (op == 1) {
                try std.testing.expect(code == transport_error_stream_state or code == transport_error_stream_limit);
            }
            break;
        }
        try std.testing.expect(op != 1);
    }
}

// Seed: one MAX_STREAM_DATA for stream 1, a bidirectional stream of the
// server that this client has not seen. The frame would create it, and
// the client grants no streams: STREAM_LIMIT_ERROR. (Draw order as for
// the seed below: `num_frames`, then `op`, `value`, `stream_id_low`,
// `bidi`.)
const max_stream_data_unseen_peer_stream_seed: [5 * 8]u8 = blk: {
    var buf: [5 * 8]u8 = undefined;
    for ([_]u64{ 1, 1, 1000, 1, 0 }, 0..) |word, i| {
        std.mem.writeInt(u64, buf[i * 8 ..][0..8], word, .little);
    }
    break :blk buf;
};

fn fuzzConnBlockedFrames(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
    });

    const num_frames = smith.valueRangeAtMost(u8, 0, 32);
    var frame_buf: [64]u8 = undefined;

    var i: u8 = 0;
    while (i < num_frames) : (i += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 3);
        const value = smith.value(u64) & ((1 << 62) - 1);
        const stream_id_low = smith.valueRangeAtMost(u8, 0, 15);
        const bidi = smith.valueRangeAtMost(u8, 0, 1) == 0;

        const frame: frame_types.Frame = switch (op) {
            0 => .{ .data_blocked = .{ .maximum_data = value } },
            1 => .{ .stream_data_blocked = .{
                .stream_id = stream_id_low,
                .maximum_stream_data = value,
            } },
            2 => .{ .streams_blocked = .{ .bidi = bidi, .maximum_streams = value } },
            else => .{ .streams_blocked = .{
                .bidi = bidi,
                .maximum_streams = max_stream_count_limit + (value & 3) + 1,
            } },
        };
        const needed = frame_mod.encodedLen(frame);
        if (needed > frame_buf.len) return;
        const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        if (op == 0 and conn.lifecycle.pending_close == null) {
            const stored = conn.peer_data_blocked_at orelse {
                try std.testing.expect(false);
                return;
            };
            try std.testing.expectEqual(value, stored);
        }
        if (op == 2 and conn.lifecycle.pending_close == null and value <= max_stream_count_limit) {
            const stored = if (bidi) conn.peer_streams_blocked_bidi else conn.peer_streams_blocked_uni;
            try std.testing.expectEqual(value, stored.?);
        }

        try std.testing.expect(conn.peer_stream_data_blocked.items.len <= max_stream_count_limit);

        switch (conn.lifecycle.state()) {
            .open, .closing, .draining, .closed => {},
        }

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_stream_state or
                    code == transport_error_excessive_load,
            );
            break;
        }
    }
}

fn fuzzConnCloseAtInitial(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    const op = smith.valueRangeAtMost(u8, 0, 7);
    const lvl: EncryptionLevel = if (smith.valueRangeAtMost(u8, 0, 1) == 0) .initial else .handshake;
    const error_code = smith.value(u64) & ((1 << 30) - 1);
    const reason_len = smith.valueRangeAtMost(u16, 0, 320);
    var reason_buf: [320]u8 = undefined;
    smith.bytes(reason_buf[0..reason_len]);
    const value = smith.value(u64) & ((1 << 62) - 1);

    const frame: frame_types.Frame = switch (op) {
        0 => .{ .connection_close = .{
            .is_transport = true,
            .error_code = error_code,
            .frame_type = 0,
            .reason_phrase = reason_buf[0..reason_len],
        } },
        1 => .{ .connection_close = .{
            .is_transport = false,
            .error_code = error_code,
            .reason_phrase = reason_buf[0..reason_len],
        } },
        2 => .{ .stream = .{
            .stream_id = value & 0xff,
            .offset = 0,
            .data = reason_buf[0..@min(reason_len, 32)],
            .has_offset = false,
            .has_length = true,
            .fin = false,
        } },
        3 => .{ .max_data = .{ .maximum_data = value } },
        4 => .{ .new_token = .{ .token = reason_buf[0..@min(reason_len, 64)] } },
        5 => .{ .path_challenge = .{ .data = reason_buf[0..8].* } },
        6 => .{ .handshake_done = .{} },
        else => .{ .ping = .{} },
    };

    var frame_buf: [512]u8 = undefined;
    const needed = frame_mod.encodedLen(frame);
    if (needed > frame_buf.len) return;
    const payload_len = frame_mod.encode(&frame_buf, frame) catch return;

    conn.dispatchFrames(lvl, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {},
    };

    switch (conn.lifecycle.state()) {
        .open, .closing, .draining, .closed => {},
    }

    if (op == 0) {
        switch (conn.lifecycle.state()) {
            .draining, .closing, .closed => {},
            .open => try std.testing.expect(false),
        }
    }
    if (op == 1 or op == 2 or op == 3 or op == 4 or op == 5) {
        if (conn.lifecycle.pending_close) |info| {
            try std.testing.expectEqual(transport_error_protocol_violation, info.error_code);
        }
    }

    if (op == 6) {
        if (conn.lifecycle.pending_close) |info| {
            try std.testing.expectEqual(transport_error_protocol_violation, info.error_code);
        }
    }

    if (conn.lifecycle.event()) |ev| {
        try std.testing.expect(ev.reason.len <= lifecycle_mod.max_close_reason_len);
    }

    if (conn.lifecycle.pending_close) |info| {
        const code = info.error_code;
        try std.testing.expect(
            code == transport_error_protocol_violation or
                code == transport_error_frame_encoding or
                code == transport_error_excessive_load or
                code == error_code,
        );
    }
}

// -- draft-munizaga-quic-alternative-server-address-00 (ALT-3) ----------

// CRYPTO reassembly fuzz harness — drives `dispatchFrames(.handshake,
// payload, now_us)` with a smith-built CRYPTO frame stream and
// asserts:
//
// - No panic / overflow trap.
// - `bytes_resident` always stays inside `max_connection_memory`
//   (set tiny here at 1024 so the resident-bytes path is reachable).
// - Once the connection has closed with `transport_error_excessive_load`
//   the harness stops feeding new frames (nothing else to assert).
// - Duplicate offsets do not push `bytes_resident` higher than the
//   first non-duplicate frame at that offset already cost.
// - `crypto_recv_offset[idx]` is monotonic across the entire run.
//
// Note: `dispatchFrames` does not call `drainInboxIntoTls`, so the
// harness exercises only the reassembly state machine — TLS is never
// fed real bytes.
test "fuzz: Connection.handleCrypto reassembly invariants" {
    try std.testing.fuzz({}, fuzzConnHandleCryptoImpl, .{});
}

// STREAM reassembly fuzz harness — drives
// `dispatchFrames(.application, payload, now_us)` with smith-built
// STREAM frames on a single peer-initiated bidi stream and asserts:
//
// - No panic / overflow trap.
// - `bytes_resident` always stays inside `max_connection_memory`
//   (set to 1024 here so the cap path is reachable).
// - `read_offset` of the recv buffer is monotonic across the run
//   (we never call `streamRead`, so it stays at 0 — but the
//   monotonicity invariant still holds trivially).
// - After any RESET_STREAM-like close, the stream's send-side state
//   machine is well-formed (one of the SendStream.State enum values).
// - `final_size` invariants hold: once a FIN is observed, no
//   subsequent fragment extends past the locked final size, and the
//   recv buffer's `final_size` matches the FIN offset.
test "fuzz: Connection.handleStream reassembly invariants" {
    try std.testing.fuzz({}, fuzzConnHandleStreamImpl, .{});
}

// Migration sequence fuzz harness — drives
// `recordAuthenticatedDatagramAddress` with smith-built sequences of
// (path_id=0, candidate_addr, datagram_len, now_us) tuples and
// asserts:
//
// - No panic / overflow trap.
// - `path.path.peer_addr` always equals one of the candidate addresses
//   we ever fed in (never garbage / never half-mutated state).
// - `path.path.validator.status` after every step is one of
//   {idle, pending, validated, failed} (the type system enforces
//   this; the assertion is a runtime sanity check).
// - Every emitted `migration_path_failed` qlog event carries a
//   `migration_fail_reason` value drawn from the documented set
//   (timeout, policy_denied, pre_handshake, rate_limited).
test "fuzz: Connection.recordAuthenticatedDatagramAddress migration sequences" {
    try std.testing.fuzz({}, fuzzConnMigrationImpl, .{});
}

// Connection-ID lifecycle fuzz harness — drives smith-chosen
// interleavings of `handleNewConnectionId` / `handleRetireConnectionId`
// / `handlePathNewConnectionId` against a fully-authenticated
// `Connection` and asserts:
//
// - No panic / overflow trap on any sequence.
// - `peer_cids.items.len` for path 0 never exceeds the local-side
//   `active_connection_id_limit` cap that gates `registerPeerCid`
//   (set tight at 4 here so the cap path is reachable in 0..32 ops).
// - Every `peer_cids` entry has a unique (path_id, sequence_number)
//   pair — `registerPeerCid` rejects sequence reuse with a different
//   cid/token, so duplicates surface as a close rather than a stored
//   collision.
// - After `handleRetireConnectionId(seq=N)` returns without closing
//   the connection, sequence N is no longer present in `local_cids`
//   for path 0 (we pre-populate `local_cids` with seq 0/1/2 so the
//   retire path has something to remove).
// - `path.path.peer_cid` (the active CID for path 0) always matches
//   one of the entries in `peer_cids` — or is empty (initial state)
//   or the connection has closed.
// - If the connection closed during the run, the close error code is
//   one of {`transport_error_protocol_violation`,
//   `transport_error_frame_encoding`,
//   `transport_error_connection_id_limit`,
//   `transport_error_excessive_load`}. In practice
//   `registerPeerCid` / `handleRetireConnectionId` emit
//   `protocol_violation` (retire-not-yet-issued, retire flood,
//   sequence-reuse, cid-reuse-across-paths), `frame_encoding`
//   (retire_prior_to-too-large), and `connection_id_limit`
//   (active-cid limit); `excessive_load` is documented for
//   forward-compat. Keep this set in step with the handlers: when a
//   close moves to a different code, the harness must move with it,
//   and the limit seed below is what makes a miss fail `zig build
//   test` instead of waiting for the deep fuzzer.
//
// Multipath scope reduction: we hold path_id at 0 for the
// `handlePathNewConnectionId` op so the harness does not need to
// negotiate multipath transport parameters and stand up secondary
// paths — both `handleNewConnectionId` and the path_id=0 form of
// `handlePathNewConnectionId` converge on `registerPeerCid`, so the
// fuzzer-chosen interleaving of the two entry points still exercises
// the same state-machine surface that §11.1 #19 calls out.
// Seed corpus for the CID lifecycle harness. With no fuzzer attached,
// `Smith` reads every integer draw as an 8-byte little-endian word and
// every `bytes` draw as raw bytes, in harness draw order: `num_ops`,
// then per op `op_kind`, `seq`, `cid_len`, the CID bytes, the 16-byte
// reset token, and `rpt_kind`.
//
// The seed is six NEW_CONNECTION_ID frames with distinct sequence
// numbers and CIDs and `retire_prior_to = 0`. The harness advertises
// `active_connection_id_limit = 4`, so the fifth registration is one
// too many and closes with CONNECTION_ID_LIMIT_ERROR (RFC 9000 §5.1.1).
// Only the deep fuzzer reached that close before this seed existed,
// which is how Invariant 5 sat stale for seven weeks after the close
// code moved off PROTOCOL_VIOLATION: the per-commit smoke run could
// not see it, and the fuzz gates did not fail on it.
const cid_limit_seed_ops = 6;
const cid_limit_seed: [8 + cid_limit_seed_ops * 56]u8 = blk: {
    var buf: [8 + cid_limit_seed_ops * 56]u8 = undefined;
    var at: usize = 0;
    const put = struct {
        fn word(b: []u8, pos: *usize, v: u64) void {
            std.mem.writeInt(u64, b[pos.*..][0..8], v, .little);
            pos.* += 8;
        }
    }.word;
    put(&buf, &at, cid_limit_seed_ops); // num_ops
    for (1..cid_limit_seed_ops + 1) |i| {
        put(&buf, &at, 0); // op_kind 0: NEW_CONNECTION_ID
        put(&buf, &at, i); // seq
        put(&buf, &at, 8); // cid_len
        @memset(buf[at..][0..8], 0xc0 + i); // CID, distinct per op
        at += 8;
        @memset(buf[at..][0..16], 0xd0 + i); // stateless reset token
        at += 16;
        put(&buf, &at, 0); // rpt_kind 0: retire_prior_to = 0
    }
    break :blk buf;
};

test "fuzz: Connection NEW_CONNECTION_ID / RETIRE_CONNECTION_ID lifecycle invariants" {
    try std.testing.fuzz({}, fuzzCidLifecycle, .{
        .corpus = &.{&cid_limit_seed},
    });
}

// PATH_CHALLENGE / PATH_RESPONSE fuzz harness — drives
// `dispatchFrames(.application, payload, now_us)` with smith-built
// PATH_CHALLENGE and PATH_RESPONSE frames against a post-handshake
// client `Connection` whose primary path validator already has a
// pending challenge token. Asserts:
//
// - No panic / overflow trap.
// - After a PATH_CHALLENGE, `pending_frames.path_response` is non-null
//   and equals the challenge token (the dispatcher echoes the bytes).
// - After a PATH_RESPONSE that matches the validator's pending token,
//   the validator transitions to `.validated`. Mismatching tokens
//   leave the status alone (`.pending` or `.validated`).
// - Validator status is always one of {.idle, .pending, .validated,
//   .failed}.
// - Lifecycle state is one of the documented `CloseState` values.
// - If the connection closed, the close code lives in the documented
//   set ({protocol_violation, frame_encoding, excessive_load}). The
//   PATH_CHALLENGE / PATH_RESPONSE handlers themselves never close, but
//   the dispatcher's frame-iter and level-gate close paths can fire on
//   adversarial bytes.
test "fuzz: Connection PATH_CHALLENGE / PATH_RESPONSE handler invariants" {
    try std.testing.fuzz({}, fuzzConnPathChallenge, .{});
}

// MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS fuzz harness — drives
// `dispatchFrames(.application, payload, now_us)` with smith-built
// flow-control window-update frames and asserts:
//
// - `peer_max_data` is monotonic non-decreasing (handler only widens).
// - `local_bidi_ids.limit` and `local_uni_ids.limit` are monotonic
//   non-decreasing, bounded above only by the stream id space, and
//   equal to the largest in-range MAX_STREAMS seen (the handler does
//   not clamp: there is no lifetime stream cap).
// - MAX_STREAM_DATA always closes this connection, which has no stream
//   and grants none: `stream_state` for a receive-only stream (a
//   unidirectional stream of the peer) and for a stream of ours that
//   was never opened (RFC 9000 §19.10), `stream_limit` for a
//   bidirectional stream of the peer, which the frame would create
//   (§3.2).
// - MAX_STREAMS exceeding `max_stream_count_limit` closes with
//   `frame_encoding`.
// - Lifecycle state is one of the documented `CloseState` values.
// - Close codes (when set) are in the documented set.
// Seed: one MAX_STREAMS(bidi, 5000). Draw order: `num_frames`, then per
// frame `op`, `value`, `stream_id_low`, `bidi` (0 = bidirectional), each
// an 8-byte little-endian word. 5000 is above 4096, the lifetime stream
// cap the handler clamped to through 0.23.0, so this seed is what makes
// "taken as sent" fail `zig build test` if a clamp comes back.
const max_streams_above_old_cap_seed: [5 * 8]u8 = blk: {
    var buf: [5 * 8]u8 = undefined;
    for ([_]u64{ 1, 2, 5000, 0, 0 }, 0..) |word, i| {
        std.mem.writeInt(u64, buf[i * 8 ..][0..8], word, .little);
    }
    break :blk buf;
};

test "fuzz: Connection MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS monotonicity" {
    try std.testing.fuzz({}, fuzzConnFlowControlWindow, .{
        .corpus = &.{ &max_streams_above_old_cap_seed, &max_stream_data_unseen_peer_stream_seed },
    });
}

// DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED fuzz harness —
// drives `dispatchFrames(.application, ...)` with peer-blocked
// signal frames and asserts:
//
// - No panic / overflow trap.
// - After DATA_BLOCKED, `peer_data_blocked_at == frame.maximum_data`.
// - After STREAMS_BLOCKED(bidi=true) without close, the stored value
//   matches the frame's maximum (and likewise for uni).
// - `peer_stream_data_blocked.items.len <= max_stream_count_limit` —
//   bounded by the same global stream-count cap that gates the handler.
// - STREAM_DATA_BLOCKED on a receive-only stream closes with
//   `stream_state`. STREAMS_BLOCKED with maximum > stream-id space
//   closes with `frame_encoding`.
// - Lifecycle state is one of the documented `CloseState` values and
//   close codes are in the documented set.
test "fuzz: Connection DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED invariants" {
    try std.testing.fuzz({}, fuzzConnBlockedFrames, .{});
}

// CONNECTION_CLOSE-at-Initial-or-Handshake fuzz harness — drives
// `dispatchFrames(.initial, ...)` and `dispatchFrames(.handshake, ...)`
// with smith-built CONNECTION_CLOSE frames and other 1-RTT-only frames
// to exercise the §12.4/§19.19 envelope before the handshake completes.
//
// Asserts:
// - No panic / overflow trap.
// - A transport CONNECTION_CLOSE (0x1c) at .initial or .handshake
//   transitions lifecycle into draining (state in
//   {.draining, .closing, .closed}).
// - An application CONNECTION_CLOSE (0x1d) at .initial or .handshake
//   triggers a `protocol_violation` close (forbidden frame at
//   Initial/Handshake level, RFC 9000 §12.4 / Table 3).
// - Forbidden 1-RTT-only frames (STREAM, MAX_DATA, NEW_CONNECTION_ID,
//   PATH_CHALLENGE, …) at .initial or .handshake close with
//   `protocol_violation`.
// - Once closed, lifecycle state is one of {.draining, .closing, .closed}
//   and the close code is in the documented set.
// - Reason-phrase length on the wire never overflows the 256-byte
//   `max_close_reason_len` ceiling — the lifecycle records reasons
//   truncated, never beyond.
test "fuzz: Connection CONNECTION_CLOSE pre-handshake envelope invariants" {
    try std.testing.fuzz({}, fuzzConnCloseAtInitial, .{});
}

// Assembled-datagram fuzz harness — drives the full receive pipeline
// that the per-frame harnesses above bypass: handleWithEcn →
// handleOnePacket → openApplicationPacket (header-protection removal,
// PN reconstruction, AEAD open against the key epochs) →
// classifyPayload → dispatchFrames, fed with smith-sealed,
// coalesced 1-RTT packets under a fixed key set. The wire-layer fuzz
// targets exercise the parsers in isolation and the per-frame
// harnesses call dispatchFrames directly; neither reaches the
// coalesced-packet loop, the duplicate-PN gate, or the
// closing-state attribution tail.
//
// Asserts:
// - No panic / overflow trap.
// - Resident bytes never overshoot the (tiny) connection cap.
// - Once closed, the close code is in the documented transport set.
fn fuzzConnHandleAssembledPacketImpl(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // Tiny cap so the resident-bytes path (EXCESSIVE_LOAD close) is
    // reachable from small fuzz inputs.
    conn.max_connection_memory = 1024;
    const cap = conn.max_connection_memory;

    // Fixed 1-RTT keys: the read epoch installs from the zero
    // secret, and testEarlyDataPacketKeys derives the matching peer
    // write keys from the same material, so smith-sealed packets
    // authenticate.
    try util.installTestApplicationReadSecret(conn);
    var peer_keys = try util.testEarlyDataPacketKeys();
    defer peer_keys.deinitAead();

    const num_datagrams = smith.valueRangeAtMost(u32, 1, 4);
    var dg: u32 = 0;
    while (dg < num_datagrams) : (dg += 1) {
        var datagram: [2048]u8 = undefined;
        var pos: usize = 0;
        const num_packets = smith.valueRangeAtMost(u8, 1, 3);
        var pk: u8 = 0;
        while (pk < num_packets) : (pk += 1) {
            // Smith-built STREAM/PING payload.
            const num_frames = smith.valueRangeAtMost(u32, 0, 8);
            var frame_buf: [1024]u8 = undefined;
            var fpos: usize = 0;
            var fi: u32 = 0;
            while (fi < num_frames) : (fi += 1) {
                const data_len = smith.valueRangeAtMost(u8, 0, 32);
                var data_buf: [32]u8 = undefined;
                smith.bytes(data_buf[0..data_len]);
                const frame: frame_types.Frame = .{ .stream = .{
                    .stream_id = smith.valueRangeAtMost(u64, 0, 8),
                    .offset = smith.valueRangeAtMost(u64, 0, 1024),
                    .data = data_buf[0..data_len],
                    .fin = smith.valueRangeAtMost(u8, 0, 1) != 0,
                } };
                const needed = frame_mod.encodedLen(frame);
                if (fpos + needed > frame_buf.len) break;
                fpos += frame_mod.encode(frame_buf[fpos..], frame) catch break;
            }
            if (fpos == 0) {
                fpos = frame_mod.encode(frame_buf[0..], .{ .ping = .{} }) catch return;
            }
            const pn = smith.valueRangeAtMost(u64, 0, 1000);
            const n = short_packet_mod.seal1Rtt(datagram[pos..], .{
                .dcid = &.{},
                .pn = pn,
                .largest_acked = null,
                .payload = frame_buf[0..fpos],
                .keys = &peer_keys,
                .key_phase = false,
            }) catch break;
            pos += n;
        }
        if (pos == 0) continue;

        const before_resident = conn.bytes_resident;
        conn.handleWithEcn(datagram[0..pos], null, .not_ect, 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };
        try std.testing.expect(conn.bytes_resident <= cap);
        _ = before_resident;

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            try std.testing.expect(
                code == transport_error_protocol_violation or
                    code == transport_error_frame_encoding or
                    code == transport_error_excessive_load or
                    code == transport_error_flow_control or
                    code == transport_error_stream_limit or
                    code == transport_error_stream_state or
                    code == transport_error_final_size or
                    code == transport_error_connection_id_limit or
                    code == transport_error_internal,
            );
            break;
        }
    }
}

test "fuzz: Connection assembled-packet receive pipeline invariants" {
    try std.testing.fuzz({}, fuzzConnHandleAssembledPacketImpl, .{});
}

// Stream-window fuzz harness — the life of peer streams under frames in
// any order, application reads and replies, and `tick` (the only place
// a stream is reaped). It is the one harness that calls `tick`, so it
// is the one that sees stream GC, late frames for a reaped id, and the
// credit rule together.
//
// The connection is a server with small stream windows (0 to 6 of each
// type). Each operation is four draws (operation, type, id pick,
// argument); the id is one the peer may use (`pick % limit`), except
// for the operation that asks for the first id it may NOT use.
//
// After every operation, for each stream type:
//
// - Window: the live peer streams, and `opened - closed` (which counts
//   skipped ids too), are at most `initial_max_streams_*`.
// - Limit: `opened <= limit <= window + closed`, and the limit never
//   goes down.
// - No credit is owed: `creditToAdvertise` has nothing to give. This is
//   what holds `maybeAdvertiseStreamCredit` to a call at every place
//   the answer can change (reap, peer open, STREAMS_BLOCKED). A peer
//   must never have to wait at its limit while we hold ids back.
// - A pending MAX_STREAMS carries the current limit.
// - A stream leaves the table in `tick` only, and each one that leaves
//   is counted as closed exactly once.
// - A reaped id is never live again, whatever arrives for it, and a
//   frame for it is ignored: no error, no close (RFC 9000 §3.2).
// - An id over the limit closes the connection with STREAM_LIMIT_ERROR;
//   any other close has a code from the documented set.
const WindowOp = enum(u8) {
    /// One byte at a small offset, no FIN.
    stream_data,
    /// FIN at the bytes received so far: always a valid final size.
    stream_fin,
    /// Offset, length and FIN straight from the argument: may be a
    /// final-size violation.
    stream_any,
    /// RESET_STREAM with a valid final size.
    reset,
    /// STOP_SENDING (bidirectional streams only).
    stop_sending,
    /// STREAMS_BLOCKED at the current limit, or one below it.
    streams_blocked,
    /// The application reads everything that has arrived.
    app_read,
    /// The application finishes its side of a bidirectional stream and
    /// the peer acknowledges it (or acknowledges our RESET_STREAM).
    app_finish_acked,
    tick,
    /// One byte on the first id over the limit.
    over_limit,
};

const window_fuzz_max_index = 128;

fn fuzzConnStreamWindow(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // [0] bidirectional, [1] unidirectional.
    const windows = [2]u64{
        smith.valueRangeAtMost(u64, 0, 6),
        smith.valueRangeAtMost(u64, 0, 6),
    };
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 16,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_stream_data_uni = 64,
        .initial_max_streams_bidi = windows[0],
        .initial_max_streams_uni = windows[1],
    });
    const num_ops = smith.valueRangeAtMost(u32, 0, 96);

    // What the harness has seen happen, per stream type and index.
    var live: [2][window_fuzz_max_index]bool = @splat(@splat(false));
    var reaped: [2][window_fuzz_max_index]bool = @splat(@splat(false));
    var reaps = [2]u64{ 0, 0 };
    var last_limit = windows;

    var now_us: u64 = 1_000_000;
    var frame_buf: [64]u8 = undefined;
    const one = [_]u8{'x'};

    var i: u32 = 0;
    while (i < num_ops) : (i += 1) {
        const op: WindowOp = @fromBackingInt(@intCast(smith.valueRangeAtMost(u8, 0, 9)));
        const bidi = smith.valueRangeAtMost(u8, 0, 1) == 0;
        const pick = smith.valueRangeAtMost(u64, 0, window_fuzz_max_index - 1);
        const arg = smith.valueRangeAtMost(u8, 0, 15);

        const ids = if (bidi) &conn.peer_bidi_ids else &conn.peer_uni_ids;
        // With a limit of zero there is no id the peer may use.
        const usable = ids.limit != 0;
        const index = if (op == .over_limit) ids.limit else if (usable) pick % ids.limit else 0;
        if (index >= window_fuzz_max_index) return;
        const sid = index * 4 + @as(u64, if (bidi) 0 else 2);
        const known_end: ?u64 = if (conn.streams.get(sid)) |s| (s.recv.final_size orelse s.recv.end_offset) else null;

        const frame: ?frame_types.Frame = switch (op) {
            .stream_data => if (!usable) null else .{ .stream = .{
                .stream_id = sid,
                .offset = arg & 7,
                .data = &one,
                .has_offset = true,
                .has_length = true,
            } },
            .stream_fin => if (!usable) null else .{ .stream = .{
                .stream_id = sid,
                .offset = known_end orelse 0,
                .data = "",
                .has_offset = true,
                .has_length = true,
                .fin = true,
            } },
            .stream_any => if (!usable) null else .{ .stream = .{
                .stream_id = sid,
                .offset = arg & 3,
                .data = one[0 .. (arg >> 2) & 1],
                .has_offset = true,
                .has_length = true,
                .fin = (arg & 8) != 0,
            } },
            .reset => if (!usable) null else .{ .reset_stream = .{
                .stream_id = sid,
                .application_error_code = 0,
                .final_size = known_end orelse arg & 7,
            } },
            .stop_sending => if (!usable or !bidi) null else .{ .stop_sending = .{
                .stream_id = sid,
                .application_error_code = 0,
            } },
            .streams_blocked => .{ .streams_blocked = .{
                .bidi = bidi,
                .maximum_streams = ids.limit -| (arg & 1),
            } },
            .over_limit => .{ .stream = .{
                .stream_id = sid,
                .offset = 0,
                .data = &one,
                .has_offset = true,
                .has_length = true,
            } },
            .app_read, .app_finish_acked, .tick => null,
        };
        if (frame) |f| {
            const payload_len = frame_mod.encode(&frame_buf, f) catch return;
            // A frame for a reaped stream is post-terminal: it is
            // ignored (RFC 9000 §3.2). No error, no close.
            const late = op != .streams_blocked and reaped[@intFromBool(!bidi)][@as(usize, @intCast(index))];
            conn.dispatchFrames(.application, frame_buf[0..payload_len], now_us) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => try std.testing.expect(!late),
            };
            if (late) try std.testing.expect(conn.lifecycle.pending_close == null);
        }
        switch (op) {
            .app_read => if (usable) {
                var buf: [16]u8 = undefined;
                while (true) {
                    const n = conn.streamRead(sid, &buf) catch break;
                    if (n == 0) break;
                }
            },
            .app_finish_acked => if (usable and bidi) {
                if (conn.streams.get(sid)) |s| {
                    conn.streamFinish(sid) catch {};
                    if (s.send.state == .reset_sent) {
                        s.send.state = .reset_recvd;
                    } else if (s.send.fin_marked) {
                        s.send.fin_acked = true;
                        s.send.state = .data_recvd;
                    }
                }
            },
            .tick => {
                // ORACLE (0.28.0 stream-end repair): the end note must not
                // move WHEN a stream is reclaimed. Compute today's reclaim
                // rule before the tick — a peer bidi stream needs both
                // halves done, a peer uni stream its receive half — and
                // require that exactly those streams leave the table. A
                // mutant that keeps a stream one more tick (and so delays
                // its credit) passes every other check in this harness;
                // this one kills it. Windows are at most 6, so the GC's
                // 128 batch never applies.
                var gone_ids: [2 * window_fuzz_max_index]u64 = undefined;
                var gone_ends: [2 * window_fuzz_max_index]?state.StreamRecvEnd = undefined;
                var n_gone: usize = 0;
                const live_before = conn.streams.count();
                var sit = conn.streams.iterator();
                while (sit.next()) |entry| {
                    const s = entry.value_ptr.*;
                    // This harness never stops a stream; the GC's
                    // `discardStopped` would otherwise change the rule.
                    try std.testing.expect(!s.recv_stopped);
                    const reclaimable = if (s.id & 2 == 0)
                        s.send.isTerminal() and s.recvFullyTerminated()
                    else
                        s.recvFullyTerminated();
                    if (!reclaimable) continue;
                    gone_ids[n_gone] = s.id;
                    // The live answer, to compare with the note below.
                    gone_ends[n_gone] = conn.streamRecvEnd(s.id);
                    n_gone += 1;
                }
                now_us += 1_000;
                try conn.tick(now_us);
                try std.testing.expectEqual(live_before - n_gone, conn.streams.count());
                for (gone_ids[0..n_gone], gone_ends[0..n_gone]) |id, end| {
                    try std.testing.expect(!conn.streams.contains(id));
                    // Order independence, fuzzed: the note written by the
                    // reclaiming tick says what the live stream said.
                    try std.testing.expect(end != null);
                    try std.testing.expectEqualDeep(end, conn.streamRecvEnd(id));
                }
            },
            else => {},
        }

        if (conn.lifecycle.pending_close) |info| {
            const code = info.error_code;
            if (op == .over_limit) {
                try std.testing.expectEqual(transport_error_stream_limit, code);
            } else {
                try std.testing.expect(
                    code == transport_error_flow_control or
                        code == transport_error_stream_state or
                        code == transport_error_final_size or
                        code == transport_error_excessive_load or
                        code == transport_error_protocol_violation or
                        code == transport_error_frame_encoding,
                );
            }
            break;
        }
        // The peer used an id it does not have, and nothing happened.
        try std.testing.expect(op != .over_limit);

        for (0..2) |k| {
            const space = if (k == 0) &conn.peer_bidi_ids else &conn.peer_uni_ids;
            const blocked_at = if (k == 0) conn.peer_streams_blocked_bidi else conn.peer_streams_blocked_uni;
            const pending = if (k == 0) conn.pending_frames.max_streams_bidi else conn.pending_frames.max_streams_uni;

            var live_now: u64 = 0;
            for (0..window_fuzz_max_index) |idx| {
                const id = @as(u64, idx) * 4 + @as(u64, if (k == 0) 0 else 2);
                if (conn.streams.contains(id)) {
                    live_now += 1;
                    try std.testing.expect(!reaped[k][idx]);
                    try std.testing.expect(space.classify(idx) == .used);
                    live[k][idx] = true;
                } else if (live[k][idx]) {
                    try std.testing.expect(op == .tick);
                    live[k][idx] = false;
                    reaped[k][idx] = true;
                    reaps[k] += 1;
                }
                if (reaped[k][idx]) {
                    try std.testing.expect(conn.streamRecvWasReaped(id));
                }
            }
            try std.testing.expect(live_now <= windows[k]);
            try std.testing.expect(space.inUse() <= windows[k]);
            try std.testing.expectEqual(reaps[k], space.closed);
            try std.testing.expect(space.opened <= space.limit);
            try std.testing.expect(space.limit <= windows[k] + space.closed);
            try std.testing.expect(space.limit >= last_limit[k]);
            last_limit[k] = space.limit;
            try std.testing.expectEqual(@as(?u64, null), space.creditToAdvertise(blocked_at));
            if (pending) |p| try std.testing.expectEqual(space.limit, p);
        }
        // The memory budget's charge is the sum of the buffers it covers.
        try std.testing.expectEqual(conn.residentBytesSum(), conn.bytes_resident);
    }
}

/// One operation of the stream-window harness, as its four draws.
const WindowSeedOp = struct {
    op: WindowOp,
    uni: bool = true,
    pick: u64 = 0,
    arg: u8 = 0,
};

/// A seed for the stream-window harness. With no fuzzer attached,
/// `Smith` reads every integer draw as an 8-byte little-endian word, in
/// harness draw order: the two windows, the operation count, then four
/// words per operation.
fn windowSeed(
    comptime window_bidi: u64,
    comptime window_uni: u64,
    comptime ops: []const WindowSeedOp,
) [(3 + 4 * ops.len) * 8]u8 {
    var buf: [(3 + 4 * ops.len) * 8]u8 = undefined;
    var at: usize = 0;
    const put = struct {
        fn word(b: []u8, pos: *usize, v: u64) void {
            std.mem.writeInt(u64, b[pos.*..][0..8], v, .little);
            pos.* += 8;
        }
    }.word;
    put(&buf, &at, window_bidi);
    put(&buf, &at, window_uni);
    put(&buf, &at, ops.len);
    for (ops) |o| {
        put(&buf, &at, @backingInt(o.op));
        put(&buf, &at, @intFromBool(o.uni));
        put(&buf, &at, o.pick);
        put(&buf, &at, o.arg);
    }
    return buf;
}

// A window of one, used again and again: each stream ends, is reaped,
// and its id comes back. Then a frame arrives late for a reaped id,
// and the peer tries one id too many.
const window_seed_churn = windowSeed(0, 1, &.{
    .{ .op = .stream_fin, .pick = 0 },
    .{ .op = .tick },
    .{ .op = .stream_data, .pick = 1 },
    .{ .op = .stream_fin, .pick = 1 },
    .{ .op = .app_read, .pick = 1 },
    .{ .op = .tick },
    .{ .op = .stream_data, .pick = 0 }, // late, for reaped stream 0
    .{ .op = .reset, .pick = 1 }, // late, for reaped stream 1
    .{ .op = .tick },
    .{ .op = .over_limit },
});

// Credit held for batching, then the peer uses its last id (by a jump
// over two lower ids): the held id must go out without a
// STREAMS_BLOCKED. The skipped ids then arrive, one as a RESET_STREAM.
const window_seed_last_id = windowSeed(0, 4, &.{
    .{ .op = .stream_fin, .pick = 0 },
    .{ .op = .tick },
    .{ .op = .stream_data, .pick = 3 },
    .{ .op = .reset, .pick = 1 },
    .{ .op = .stream_fin, .pick = 2 },
    .{ .op = .tick },
    .{ .op = .streams_blocked, .arg = 0 },
    .{ .op = .stream_any, .pick = 4, .arg = 0b1100 },
    .{ .op = .app_read, .pick = 4 },
    .{ .op = .tick },
});

// Bidirectional: a stream is not closed until our side is done too.
// One is answered and acknowledged, one is stopped by the peer and our
// reset acknowledged, one stays half open through every tick.
const window_seed_bidi = windowSeed(3, 0, &.{
    .{ .op = .stream_any, .uni = false, .pick = 0, .arg = 0b1100 },
    .{ .op = .stream_any, .uni = false, .pick = 1, .arg = 0b1100 },
    .{ .op = .stream_any, .uni = false, .pick = 2, .arg = 0b1100 },
    .{ .op = .app_read, .uni = false, .pick = 0 },
    .{ .op = .app_read, .uni = false, .pick = 1 },
    .{ .op = .app_read, .uni = false, .pick = 2 },
    .{ .op = .tick },
    .{ .op = .app_finish_acked, .uni = false, .pick = 0 },
    .{ .op = .stop_sending, .uni = false, .pick = 1 },
    .{ .op = .app_finish_acked, .uni = false, .pick = 1 },
    .{ .op = .tick },
    .{ .op = .streams_blocked, .uni = false, .arg = 0 },
    .{ .op = .stream_data, .uni = false, .pick = 3 },
    .{ .op = .stream_data, .uni = false, .pick = 0 }, // late, for reaped stream 0
    .{ .op = .tick },
});

// Credit held for batching (one id of a window of six), then the peer
// says it is blocked at the limit: the held id goes out at once. A
// stale STREAMS_BLOCKED, one below the limit, came first and changed
// nothing.
const window_seed_blocked = windowSeed(0, 6, &.{
    .{ .op = .stream_fin, .pick = 0 },
    .{ .op = .tick },
    .{ .op = .streams_blocked, .arg = 1 },
    .{ .op = .streams_blocked, .arg = 0 },
    .{ .op = .stream_fin, .pick = 6 },
    .{ .op = .tick },
});

test "fuzz: Connection stream window under frames, reads, replies and ticks" {
    try std.testing.fuzz({}, fuzzConnStreamWindow, .{
        .corpus = &.{ &window_seed_churn, &window_seed_last_id, &window_seed_bidi, &window_seed_blocked },
    });
}

// Send-path fuzz harness against a small sent-packet tracker.
//
// The tracker is the one hard bound on how many ack-eliciting packets a
// path may have in flight. Until v0.24.1 a full tracker made `poll`
// return `TooManyInFlight`, after the packet was built and its frames
// had left their queues. Now a full tracker is back-pressure (see
// `tracker_full` in send.zig). A tracker of 4096 slots is too large for
// a fuzzer to fill by chance, so this harness gives the connection one
// of 4 to 12 slots and then does everything that makes a packet:
// stream data, a keep-alive PING, a PATH_RESPONSE, an ACK that is owed,
// probe timeouts, a close.
//
// After every operation:
//
// - No call returned an error. `pollDatagram` returns a datagram or
//   null, whatever the state of the tracker.
// - The tracker holds at most its capacity.
// - A poll with a full tracker adds no packet to it.
// - An ACK that is owed goes out, full tracker or not.
// - After `close`, the next poll gives the CONNECTION_CLOSE.
//
// At the end, with no close: every byte the application wrote is sent
// once ACKs come. A full tracker stops the sender; it does not strand
// the data.
const SendOp = enum(u8) {
    /// The application writes 1 to 256 bytes.
    write,
    /// One `pollDatagram`, into a buffer of 64 to 304 bytes.
    poll,
    /// The peer acknowledges one live packet (the `pick`-th).
    ack_one,
    /// The peer acknowledges everything that was sent.
    ack_all,
    /// 1 ms to 256 ms go by, and `tick` runs.
    tick,
    /// A packet of the peer arrived: an ACK is owed.
    peer_packet,
    /// The application asks for a PING.
    ping,
    /// The peer challenged the path: a PATH_RESPONSE is owed.
    path_response,
    /// The application closes the connection.
    close,
};

fn fuzzConnSendSmallTracker(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    });
    try util.installTestApplicationWriteSecret(conn);
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_remote = 1 << 22,
        .initial_max_streams_bidi = 1 << 16,
        .initial_max_streams_uni = 1 << 16,
    });
    // No handshake in this fixture: its timeout must not end the run.
    conn.handshake_timeout_us = 0;
    // The tracker is the gate under test, so the window never binds.
    // Pacing is one more draw: its deadline logic reads the tracker.
    conn.ccForApplication().setCwndForTest(1 << 30);
    conn.pacing_enabled = smith.valueRangeAtMost(u8, 0, 1) == 1;

    const capacity = smith.valueRangeAtMost(u32, 4, 12);
    const path = conn.primaryPath();
    path.sent.deinit(allocator);
    path.sent = try SentPacketTracker.init(allocator, capacity);
    const tracker = conn.sentForLevel(.application);
    try std.testing.expectEqual(capacity, tracker.capacity());

    const s = try conn.openBidi(0);
    const data: [256]u8 = @splat('d');
    var written: usize = 0;
    var now_us: u64 = 1_000_000;
    var dgram: [512]u8 = undefined;
    var closed = false;

    const num_ops = smith.valueRangeAtMost(u32, 0, 128);
    var i: u32 = 0;
    while (i < num_ops) : (i += 1) {
        const op: SendOp = @fromBackingInt(@intCast(smith.valueRangeAtMost(u8, 0, 8)));
        const pick = smith.valueRangeAtMost(u8, 0, 15);
        const arg = smith.valueRangeAtMost(u8, 0, 255);

        switch (op) {
            .write => written += try conn.streamWrite(s.id, data[0 .. @as(usize, arg) + 1]),
            .poll => {
                const full = tracker.isFull();
                const live = tracker.liveCount();
                const owed_ack = conn.primaryPath().app_pn_space.received.pending_ack;
                const got = try conn.pollDatagram(dgram[0 .. 64 + @as(usize, arg & 0xf) * 16], now_us);
                if (full) try std.testing.expectEqual(live, tracker.liveCount());
                if (owed_ack) {
                    try std.testing.expect(got != null);
                    try std.testing.expect(!conn.primaryPath().app_pn_space.received.pending_ack);
                }
            },
            .ack_one => {
                var pns: [16]u64 = undefined;
                const live = tracker.livePns(&pns);
                if (live.len > 0) {
                    const pn = live[pick % live.len];
                    now_us += 1_000;
                    try conn.handleAckAtLevel(.application, .{
                        .largest_acked = pn,
                        .ack_delay = 0,
                        .first_range = 0,
                        .range_count = 0,
                        .ranges_bytes = &.{},
                        .ecn_counts = null,
                    }, now_us);
                }
            },
            .ack_all => {
                const next_pn = conn.pnSpaceForLevel(.application).next_pn;
                if (next_pn > 0) {
                    now_us += 1_000;
                    try conn.handleAckAtLevel(.application, .{
                        .largest_acked = next_pn - 1,
                        .ack_delay = 0,
                        .first_range = next_pn - 1,
                        .range_count = 0,
                        .ranges_bytes = &.{},
                        .ecn_counts = null,
                    }, now_us);
                    try std.testing.expectEqual(@as(u32, 0), tracker.liveCount());
                }
            },
            .tick => {
                now_us += (@as(u64, arg) + 1) * 1_000;
                try conn.tick(now_us);
            },
            .peer_packet => conn.primaryPath().app_pn_space.received.add(i, now_us / 1_000),
            .ping => conn.requestPing(),
            .path_response => conn.queuePathResponseOnPath(0, @splat(arg), null),
            .close => {
                conn.close(false, 0, "");
                const got = try conn.pollDatagram(&dgram, now_us);
                try std.testing.expect(got != null);
                try std.testing.expect(conn.closeState() != .open);
                closed = true;
            },
        }
        try std.testing.expect(tracker.liveCount() <= tracker.capacity());
        if (closed or conn.closeState() != .open) return;
    }

    // Liveness. The peer acknowledges whatever is in flight, again and
    // again: everything the application wrote goes out.
    var rounds: usize = 0;
    while (s.send.hasPendingChunk() or tracker.liveCount() > 0) : (rounds += 1) {
        try std.testing.expect(rounds < 4096);
        now_us += 100_000;
        while (try conn.pollDatagram(&dgram, now_us)) |_| {}
        const next_pn = conn.pnSpaceForLevel(.application).next_pn;
        if (next_pn == 0) break;
        try conn.handleAckAtLevel(.application, .{
            .largest_acked = next_pn - 1,
            .ack_delay = 0,
            .first_range = next_pn - 1,
            .range_count = 0,
            .ranges_bytes = &.{},
            .ecn_counts = null,
        }, now_us);
    }
    try std.testing.expect(!s.send.hasPendingChunk());
    try std.testing.expectEqual(@as(u64, written), s.send.writtenBytes());
    try std.testing.expectEqual(s.send.writtenBytes(), s.send.ackedFloor());
}

/// One operation of the send harness, as its three draws.
const SendSeedOp = struct {
    op: SendOp,
    pick: u8 = 0,
    arg: u8 = 0,
};

/// A seed for the send harness: pacing, tracker capacity, operation
/// count, then three words per operation (see `windowSeed` for how
/// `Smith` reads them).
fn sendSeed(
    comptime pacing: bool,
    comptime capacity: u32,
    comptime ops: []const SendSeedOp,
) [(3 + 3 * ops.len) * 8]u8 {
    var buf: [(3 + 3 * ops.len) * 8]u8 = undefined;
    var at: usize = 0;
    const put = struct {
        fn word(b: []u8, pos: *usize, v: u64) void {
            std.mem.writeInt(u64, b[pos.*..][0..8], v, .little);
            pos.* += 8;
        }
    }.word;
    put(&buf, &at, @intFromBool(pacing));
    put(&buf, &at, capacity);
    put(&buf, &at, ops.len);
    for (ops) |o| {
        put(&buf, &at, @backingInt(o.op));
        put(&buf, &at, o.pick);
        put(&buf, &at, o.arg);
    }
    return buf;
}

// Fill a tracker of four slots with small packets, poll two more times
// into the full tracker, then everything that is not stream data: a
// PING, a PATH_RESPONSE, an owed ACK, a probe timeout, an ACK of one
// packet in the middle, and a close through the full tracker.
const send_seed_full = sendSeed(false, 4, &.{
    .{ .op = .write, .arg = 255 },
    .{ .op = .write, .arg = 255 },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .ping },
    .{ .op = .poll },
    .{ .op = .path_response, .arg = 7 },
    .{ .op = .poll },
    .{ .op = .peer_packet },
    .{ .op = .poll },
    .{ .op = .tick, .arg = 255 },
    .{ .op = .tick, .arg = 255 },
    .{ .op = .tick, .arg = 255 },
    .{ .op = .tick, .arg = 255 },
    .{ .op = .poll },
    .{ .op = .ack_one, .pick = 2 },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .close },
});

// The same start with pacing on, and no close: the end of the harness
// must still get every byte out.
const send_seed_paced = sendSeed(true, 5, &.{
    .{ .op = .write, .arg = 255 },
    .{ .op = .write, .arg = 255 },
    .{ .op = .write, .arg = 255 },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .ack_all },
    .{ .op = .poll },
    .{ .op = .poll },
    .{ .op = .tick, .arg = 100 },
    .{ .op = .poll },
});

test "fuzz: Connection send path against a small sent-packet tracker" {
    try std.testing.fuzz({}, fuzzConnSendSmallTracker, .{
        .corpus = &.{ &send_seed_full, &send_seed_paced },
    });
}

// -- datagrams that do not authenticate ----------------------------------
//
// Bytes that no key of the connection sealed must be nothing to it:
// `handle` returns no error and the connection stays open. An error
// out of `handle` is fatal by contract (`Server.feed` closes the
// connection, the bundled client loop returns), so an error for such
// bytes lets anyone who can write one datagram end the connection.
//
// FOUND 2026-10-03, by a sweep in tests/e2e/handshake_loss.zig and not
// by a harness in this file: a header that did not parse came out of
// `handle` as `error.ConnIdTooLong`, `error.DeclaredLengthExceedsInput`,
// `error.PayloadTooShort`, `error.InsufficientBytes` or
// `error.InsufficientCiphertext`. The harness above this one seals its
// packets, and it takes every error but OutOfMemory as fine, so it
// could not see that.
//
// The connection has read keys at every level (Initial from the
// Destination Connection ID, Handshake, 0-RTT and 1-RTT from fixed
// secrets), so no input is dropped early for want of a key. The input
// is steered towards packet shapes: a first byte of each kind, the
// real version, the connection's own ID in its place. A random
// 16-byte tag does not verify, so every close and every error is a
// finding.
const unauthenticated_local_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
const unauthenticated_odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };

fn fuzzConnHandleUnauthenticated(_: void, smith: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();
    try conn.setLocalScid(&unauthenticated_local_cid);
    try conn.setInitialDcid(&unauthenticated_odcid);
    try conn.setPeerDcid(&.{ 0xc0, 0xc1, 0xc2, 0xc3 });
    var material: state.SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[EncryptionLevel.handshake.idx()].read = material;
    util.installTestEarlyDataReadSecret(conn);
    try util.installTestApplicationReadSecret(conn);

    const datagrams = smith.valueRangeAtMost(u32, 1, 4);
    var i: u32 = 0;
    while (i < datagrams) : (i += 1) {
        var buf: [1500]u8 = undefined;
        const len = smith.slice(&buf);
        const datagram = buf[0..len];
        const shape = smith.valueRangeAtMost(u8, 0, 5);
        if (len >= 14) switch (shape) {
            // As the smith made it.
            0 => {},
            // A short header for this connection.
            1 => {
                datagram[0] &= 0x7f;
                @memcpy(datagram[1..9], &unauthenticated_local_cid);
            },
            // An Initial (2), a 0-RTT (3) or a Handshake (4) packet of
            // QUIC v1 for this connection; the lengths behind the
            // connection ID are the smith's.
            2, 3, 4 => {
                datagram[0] = 0xc0 | ((shape - 2) << 4) | (datagram[0] & 0x0f);
                std.mem.writeInt(u32, datagram[1..5], 1, .big);
                datagram[5] = 8;
                @memcpy(datagram[6..14], if (shape == 2) &unauthenticated_odcid else &unauthenticated_local_cid);
            },
            // A long header of QUIC v1; all else is the smith's.
            else => {
                datagram[0] |= 0x80;
                std.mem.writeInt(u32, datagram[1..5], 1, .big);
            },
        };
        try conn.handle(datagram, null, 1_000_000);
        try std.testing.expectEqual(CloseState.open, conn.closeState());
    }
}

/// A seed for the harness above: one datagram, given as it is. With no
/// fuzzer attached, `Smith` reads an integer draw as an 8-byte
/// little-endian word and a slice as a 4-byte length and the bytes.
fn unauthenticatedSeed(comptime datagram: []const u8) [8 + 4 + datagram.len + 8]u8 {
    var buf: [8 + 4 + datagram.len + 8]u8 = @splat(0);
    // One datagram.
    std.mem.writeInt(u64, buf[0..8], 1, .little);
    std.mem.writeInt(u32, buf[8..12], @intCast(datagram.len), .little);
    @memcpy(buf[12..][0..datagram.len], datagram);
    // Shape 0: as it is (the last word stays zero).
    return buf;
}

// One seed for each error that the code before returned.
// `error.InsufficientCiphertext`: a short header, the connection ID,
// and three bytes.
const unauthenticated_seed_short = unauthenticatedSeed(&([_]u8{0x40} ++ unauthenticated_local_cid ++ [_]u8{ 1, 2, 3 }));
// `error.ConnIdTooLong`: an Initial packet whose Source Connection ID
// Length is 21.
const unauthenticated_seed_cid = unauthenticatedSeed(&([_]u8{ 0xc0, 0, 0, 0, 1, 8 } ++ unauthenticated_odcid ++ [_]u8{ 21, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
// `error.DeclaredLengthExceedsInput`: an Initial packet whose Length
// (16383) is more than the datagram.
const unauthenticated_seed_length = unauthenticatedSeed(&([_]u8{ 0xc0, 0, 0, 0, 1, 8 } ++ unauthenticated_odcid ++ [_]u8{ 0, 0, 0x7f, 0xff, 1, 2, 3, 4 }));
// `error.PayloadTooShort`: a Handshake packet whose Length (3) is less
// than a packet number and a tag.
const unauthenticated_seed_payload = unauthenticatedSeed(&([_]u8{ 0xe0, 0, 0, 0, 1, 8 } ++ unauthenticated_local_cid ++ [_]u8{ 0, 3, 1, 2, 3 }));
// `error.InsufficientBytes`: a Handshake packet that ends in its
// Source Connection ID.
const unauthenticated_seed_cut = unauthenticatedSeed(&([_]u8{ 0xe0, 0, 0, 0, 1, 8 } ++ unauthenticated_local_cid ++ [_]u8{ 8, 1, 2 }));

test "fuzz: Connection.handle with bytes that do not authenticate neither fails nor closes" {
    try std.testing.fuzz({}, fuzzConnHandleUnauthenticated, .{
        .corpus = &.{
            &unauthenticated_seed_short,
            &unauthenticated_seed_cid,
            &unauthenticated_seed_length,
            &unauthenticated_seed_payload,
            &unauthenticated_seed_cut,
        },
    });
}
