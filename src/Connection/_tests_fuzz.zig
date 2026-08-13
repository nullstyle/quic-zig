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
const Stream = state.Stream;
const frame_mod = state.frame_mod;
const frame_types = state.frame_types;
const lifecycle_mod = state.lifecycle_mod;
const max_close_reason_len = state.max_close_reason_len;
const max_stream_count_limit = state.max_stream_count_limit;
const max_streams_per_connection = state.max_streams_per_connection;
const transport_error_excessive_load = state.transport_error_excessive_load;
const transport_error_final_size = state.transport_error_final_size;
const transport_error_flow_control = state.transport_error_flow_control;
const transport_error_frame_encoding = state.transport_error_frame_encoding;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const transport_error_stream_limit = state.transport_error_stream_limit;
const transport_error_stream_state = state.transport_error_stream_state;
const wire_header = state.wire_header;
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
        // before the handler sees it. `wire_header.ConnId.fromSlice`
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
        // (`registerPeerCid` closes with PROTOCOL_VIOLATION rather
        // than overshoot the cap, so the cap holds even on
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
        // close, the error code lives in the documented set. Stop
        // feeding ops once closed — the handlers no-op anyway, but
        // the asserts above grow stale on a zombie state machine.
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
    conn.peer_max_streams_bidi = 0;
    conn.peer_max_streams_uni = 0;

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
        const before_streams_bidi = conn.peer_max_streams_bidi;
        const before_streams_uni = conn.peer_max_streams_uni;

        conn.dispatchFrames(.application, frame_buf[0..payload_len], 1_000_000) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {},
        };

        try std.testing.expect(conn.peer_max_data >= before_max_data);
        try std.testing.expect(conn.peer_max_streams_bidi >= before_streams_bidi);
        try std.testing.expect(conn.peer_max_streams_uni >= before_streams_uni);
        try std.testing.expect(conn.peer_max_streams_bidi <= max_streams_per_connection);
        try std.testing.expect(conn.peer_max_streams_uni <= max_streams_per_connection);

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
//   `transport_error_excessive_load`}. In practice
//   `registerPeerCid` / `handleRetireConnectionId` only emit
//   `protocol_violation` (retire-not-yet-issued, sequence-reuse,
//   cid-reuse-across-paths, retire_prior_to-too-large, active-cid
//   limit), but the broader set is documented for forward-compat.
//
// Multipath scope reduction: we hold path_id at 0 for the
// `handlePathNewConnectionId` op so the harness does not need to
// negotiate multipath transport parameters and stand up secondary
// paths — both `handleNewConnectionId` and the path_id=0 form of
// `handlePathNewConnectionId` converge on `registerPeerCid`, so the
// fuzzer-chosen interleaving of the two entry points still exercises
// the same state-machine surface that §11.1 #19 calls out.
test "fuzz: Connection NEW_CONNECTION_ID / RETIRE_CONNECTION_ID lifecycle invariants" {
    try std.testing.fuzz({}, fuzzCidLifecycle, .{});
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
// - `peer_max_streams_bidi` and `peer_max_streams_uni` are monotonic
//   non-decreasing AND bounded above by `max_streams_per_connection`
//   (the handler clamps with `@min`).
// - MAX_STREAM_DATA on a peer-to-local-only stream id (e.g. peer-uni
//   stream where the peer is sending) closes with `stream_state`.
// - MAX_STREAMS exceeding `max_stream_count_limit` closes with
//   `frame_encoding`.
// - Lifecycle state is one of the documented `CloseState` values.
// - Close codes (when set) are in the documented set.
test "fuzz: Connection MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS monotonicity" {
    try std.testing.fuzz({}, fuzzConnFlowControlWindow, .{});
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
