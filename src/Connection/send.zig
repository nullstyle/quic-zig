//! The outbound send path of Connection: canSend gating, the poll /
//! pollDatagram / pollLevel entry points, and pollLevelOnPath — the
//! packet assembler that drains pending control frames, CRYPTO, streams
//! by priority, DATAGRAMs and PMTUD probes into a sealed packet under
//! congestion, flow, anti-amplification and key-phase constraints —
//! plus per-frame encode helpers and the pending-multipath-frame
//! emitters. Free-function siblings of `Connection`'s method-style send
//! API; the methods on `Connection` are thin thunks that delegate
//! here.

const std = @import("std");
const builtin = @import("builtin");
const state_mod = @import("../Connection.zig");
const conn_recv_dispatch = @import("recv_dispatch.zig");
const conn_flow = @import("flow.zig");
const conn_qlog = @import("qlog.zig");
const conn_keys = @import("keys.zig");
const conn_paths = @import("paths.zig");
const conn_streams = @import("streams.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const OutgoingDatagram = state_mod.OutgoingDatagram;
const PathState = state_mod.PathState;
const Stream = state_mod.Stream;
const level_mod = state_mod.level_mod;
const frame_mod = state_mod.frame_mod;
const frame_types = state_mod.frame_types;
const varint_mod = state_mod.varint_mod;
const long_packet_mod = state_mod.long_packet_mod;
const short_packet_mod = state_mod.short_packet_mod;
const send_stream_mod = state_mod.send_stream_mod;
const SentPacketTracker = state_mod.SentPacketTracker;
const path_frame_queue = state_mod.path_frame_queue;
const max_recv_plaintext = state_mod.max_recv_plaintext;
const max_application_ack_lower_ranges = state_mod.max_application_ack_lower_ranges;
const max_application_ack_ranges_bytes = state_mod.max_application_ack_ranges_bytes;
const default_mtu = state_mod.default_mtu;
const transport_error_application_error = state_mod.transport_error_application_error;
const Address = state_mod.Address;
const PacketKeys = state_mod.PacketKeys;
const ConnectionId = state_mod.ConnectionId;

// Doc comment lives on the `Connection.canSend` thunk in Connection.zig.
pub fn canSend(conn: *const Connection) bool {
    if (conn.lifecycle.pending_close != null) return true;
    if (conn.lifecycle.closed) return false;
    if (conn.anyPendingPing()) return true;
    if (conn.pending_handshake_done) return true;
    inline for (level_mod.all) |lvl| {
        const level_idx = lvl.idx();
        if (conn.outbox[level_idx].len > 0) return true;
        if (conn.crypto_retx[level_idx].items.len > 0) return true;
    }
    for (&conn.pn_spaces) |*space| {
        if (space.received.pending_ack) return true;
    }
    if (conn.pending_frames.max_data != null) return true;
    if (conn.pending_frames.max_stream_data.items.len > 0) return true;
    if (conn.pending_frames.max_streams_bidi != null or conn.pending_frames.max_streams_uni != null) return true;
    if (conn.pending_frames.data_blocked != null) return true;
    if (conn.pending_frames.stream_data_blocked.items.len > 0) return true;
    if (conn.pending_frames.streams_blocked_bidi != null or conn.pending_frames.streams_blocked_uni != null) return true;
    if (conn.pending_frames.new_connection_ids.items.len > 0) return true;
    if (conn.pending_frames.retire_connection_ids.items.len > 0) return true;
    if (conn.pending_frames.stop_sending.items.len > 0) return true;
    if (conn.pending_frames.new_token != null) return true;
    if (conn.pending_frames.path_response != null) return true;
    if (conn.pending_frames.path_challenge != null) return true;
    if (conn.pending_frames.path_abandons.items.len > 0) return true;
    if (conn.pending_frames.path_statuses.items.len > 0) return true;
    if (conn.pending_frames.path_new_connection_ids.items.len > 0) return true;
    if (conn.pending_frames.path_retire_connection_ids.items.len > 0) return true;
    if (conn.pending_frames.max_path_id != null) return true;
    if (conn.pending_frames.paths_blocked != null) return true;
    if (conn.pending_frames.path_cids_blocked != null) return true;
    if (conn.pending_frames.alternative_addresses.items.len > 0) return true;
    if (conn.pending_frames.send_datagrams.items.len > 0) return true;
    if (conn.pending_frames.ack_frequency != null or conn.pending_frames.immediate_ack) return true;
    var it = conn.streams.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.*.send.hasPendingChunk()) return true;
    }
    return false;
}

// Doc comment lives on the `Connection.poll` thunk in Connection.zig.
pub fn poll(
    conn: *Connection,
    dst: []u8,
    now_us: u64,
) Error!?usize {
    const datagram = (try pollDatagram(conn, dst, now_us)) orelse return null;
    return datagram.len;
}

// Doc comment lives on the `Connection.pollDatagram` thunk in Connection.zig.
pub fn pollDatagram(
    conn: *Connection,
    dst: []u8,
    now_us: u64,
) Error!?OutgoingDatagram {
    // Once `closed` is latched, the only legal outbound is a
    // CONNECTION_CLOSE frame queued by either the initial close or
    // a §10.2.1 ¶3 closing-state retransmit. Letting `pollLevel`
    // run handles both: its CC pre-empt path emits the queued
    // frame; otherwise nothing is emitted (no streams, no ACKs)
    // because every other branch is gated on stream/ACK state
    // that's empty in closing.
    conn.clock_us = @max(conn.clock_us, now_us);
    if (conn.lifecycle.closed and conn.lifecycle.pending_close == null) return null;
    conn.queueHandshakeDoneIfReady();
    conn.maybeAutoAckFrequency(now_us);
    // A connection at rest has nothing to send: it answers here instead
    // of in the builder below. The first time, with one walk of its
    // queues (`atRest`), which also primes the rest deadline; from
    // then on from that one field, until `touch`. A Debug build runs
    // the builder as well and checks that it agrees.
    if (conn.rest_deadline_valid or conn.atRest()) {
        if (!conn.rest_deadline_valid) _ = conn.nextTimerDeadline(now_us);
        if (builtin.mode == .debug) {
            const built = try pollDatagramFull(conn, dst, now_us);
            std.debug.assert(built == null);
        }
        return null;
    }
    return pollDatagramFull(conn, dst, now_us);
}

fn pollDatagramFull(
    conn: *Connection,
    dst: []u8,
    now_us: u64,
) Error!?OutgoingDatagram {
    try conn.refreshEarlyDataStatus();
    conn.poll_addr_override = null;
    conn.poll_sent_ack_eliciting = false;

    // The budget is for the DATAGRAM. A datagram that holds a packet
    // with a long header is `conn.mtu` bytes at most (1200; the peer's
    // `max_udp_payload_size` can only lower it, and not below 1200):
    // RFC 9000 section 14.2, nothing larger before the path is
    // probed, and a probe is a 1-RTT packet alone in its datagram.
    // Each packet gets what the ones in front of it left
    // (`poll_datagram_used`).
    //
    // Until v0.26.0 each PACKET was capped at the MTU on its own, and
    // `dst` was the rest of the caller's buffer. MEASURED with a
    // 4096-byte buffer: server Initial + Handshake 1310 bytes, client
    // padded Initial + Handshake ACK 1250, Handshake + 1-RTT 1313,
    // Initial + Handshake + 1-RTT 1453, Handshake + a PMTUD probe
    // 2427. A path that carries 1232 bytes dropped each of them.
    const long_dst = dst[0..@min(dst.len, conn.mtu)];
    var initial: InitialInDatagram = .{ .payload = &Connection.scratch().initial_payload };
    conn.poll_initial = &initial;
    defer conn.poll_initial = null;
    conn.poll_datagram_used = 0;
    defer conn.poll_datagram_used = 0;
    conn.poll_close_emitted = false;
    defer conn.poll_close_emitted = false;

    var pos: usize = 0;
    // Initial first (must lead a coalesced datagram).
    if (try pollLevel(conn, .initial, long_dst, now_us)) |n| pos += n;
    conn.poll_datagram_used = pos;
    // Client 0-RTT uses a long header but shares the Application
    // packet-number space. If the Initial filled this datagram, this
    // simply waits for the next poll.
    if (pos < long_dst.len) {
        if (try pollLevel(conn, .early_data, long_dst[pos..], now_us)) |n| pos += n;
    }
    conn.poll_datagram_used = pos;
    // Handshake next (after Initial keys are dropped post-handshake,
    // there's nothing here; otherwise it's CRYPTO + ACK).
    var sent_handshake = false;
    if (pos < long_dst.len) {
        if (try pollLevel(conn, .handshake, long_dst[pos..], now_us)) |n| {
            pos += n;
            sent_handshake = true;
        }
    }
    conn.poll_datagram_used = pos;
    // Application last (the 1-RTT short header MUST be the last
    // packet in a coalesced datagram per §12.2). Only schedule a
    // non-zero path when there are no Initial/Handshake bytes already
    // in this datagram. A 1-RTT packet alone has the caller's whole
    // buffer (its own limit is the path's MTU, and a PMTUD probe is
    // larger than that on purpose).
    const app_path_id = if (pos == 0)
        conn_paths.applicationPathForPoll(
            conn,
        ).id
    else
        conn.primaryPath().id;
    const app_start_pos = pos;
    const app_dst = if (pos == 0) dst else long_dst;
    if (pos < app_dst.len) {
        if (try pollLevelOnPath(conn, .application, app_path_id, app_dst[pos..], now_us)) |n| pos += n;
    }
    // A CONNECTION_CLOSE went into this datagram, at each level that
    // has keys (see the close step of `pollLevelOnPath`). It counts as
    // one emit.
    if (conn.poll_close_emitted) {
        noteCloseEmitted(conn, now_us);
        conn_qlog.emitConnectionStateIfChanged(conn);
    }
    if (pos == 0) return null;
    // A packet leaves: the loss and probe timers move with it. Not
    // `touch`: the owner is draining this connection right now and
    // re-arms its timer when the drain ends (`Server.slotDrained`),
    // so no wake is owed.
    conn.rest_deadline_valid = false;

    // RFC 9000 section 14.1: the datagram is complete, so the padding
    // that an Initial packet in it needs is known now.
    if (initial.sealed) {
        const before = pos;
        pos = try padInitialDatagram(conn, long_dst, pos, &initial);
        conn_qlog.emitPacketSentWithPayload(
            conn,
            .initial,
            initial.pn,
            @intCast(initial.len + (pos - before)),
            initial.payload[0..initial.payload_len],
        );
    }

    // RFC 9001 §4.9.1: "a client MUST discard Initial keys when it
    // first sends a Handshake packet". An Initial packet in front of
    // that Handshake packet in this datagram (the ACK for the
    // ServerHello) is sealed by now, padding and all (which is why
    // this is not done at the Handshake level above: the padding
    // needs the keys). From here the client sends no Initial packet:
    // a server that discarded its Initial keys cannot read one, and
    // one that drops a datagram it cannot begin to read would lose
    // the Handshake packet behind it.
    if (sent_handshake and conn.role == .client and !conn.initial_keys_discarded) conn_keys.discardInitialKeys(conn);

    // RFC 9000 §10.1 ¶3: a send restarts the idle timer only for the
    // first ack-eliciting packet since the last packet received and
    // processed. Through v0.31.0 every datagram restarted it, and the
    // backed-off probes to a dead peer kept its connection alive about
    // three times the timeout (found by the qmsg session, 2026-10-06).
    if (conn.poll_sent_ack_eliciting and !conn.ack_eliciting_sent_since_recv) {
        conn.last_activity_us = now_us;
        conn.ack_eliciting_sent_since_recv = true;
    }
    const out_path = conn_paths.pathForId(conn, app_path_id);
    const out_addr = if (pos > app_start_pos) conn.poll_addr_override orelse out_path.peerAddress() else out_path.peerAddress();
    conn.poll_addr_override = null;
    if (out_addr) |addr| {
        if (Address.eql(addr, out_path.path.peer_addr)) out_path.path.onDatagramSent(pos);
    } else {
        out_path.path.onDatagramSent(pos);
    }
    // Debit the pacer unconditionally: exempt sends (probes, close,
    // ACK-only) bypass the gate but still spend credit, pushing the
    // bucket negative so the next data send waits its turn — the rate
    // accounting stays truthful (RFC 9002 §7.7).
    if (conn.pacing_enabled) out_path.path.pacer.consume(pos);
    return .{
        .len = pos,
        .to = out_addr,
        .path_id = out_path.id,
    };
}

/// RFC 9000 section 14.1: the least a datagram may be that holds an
/// Initial packet of a client, or an ack-eliciting Initial packet of
/// a server. It is also the size that every QUIC path carries.
pub const min_initial_datagram_len: usize = default_mtu;

/// What `pollDatagram` keeps of the Initial packet it has sealed, so
/// that it can seal it a second time with PADDING frames behind the
/// payload.
///
/// The padding belongs to the datagram, not to the packet: a client's
/// `[Initial][Handshake]` must be 1200 bytes together. How much the
/// Initial packet must grow is known only when the packets behind it
/// are built, and those are built with the room the Initial packet
/// left. So the Initial packet is sealed without padding, the rest of
/// the datagram is built, and if the datagram is short, the Initial
/// packet is sealed again, longer, and the rest moves back. Only the
/// second sealing leaves this endpoint: one packet number, one
/// plaintext on the wire.
pub const InitialInDatagram = struct {
    sealed: bool = false,
    /// Length of the sealed packet, without padding.
    len: usize = 0,
    pn: u64 = 0,
    largest_acked: ?u64 = null,
    quic_bit: u1 = 1,
    /// The packet asks for an acknowledgment (a server pads only for
    /// such a packet).
    ack_eliciting: bool = false,
    /// The sent-packet tracker holds a record of the packet, whose
    /// size must follow the padding.
    tracked: bool = false,
    payload_len: usize = 0,
    /// The connection's scratch (`Connection.Scratch.initial_payload`):
    /// inline, the buffer made every `.{}` a 4 KB template copy.
    payload: *[max_recv_plaintext]u8,
};

/// Seal one Initial packet of this connection into `dst`. The one
/// place that knows what every Initial packet carries: the version,
/// the two connection IDs, and (client) the token of a Retry, which
/// RFC 9000 section 8.1.2 wants in ALL Initial packets after it.
fn sealInitialPacket(
    conn: *Connection,
    dst: []u8,
    pn: u64,
    largest_acked: ?u64,
    payload: []const u8,
    keys: *const PacketKeys,
    quic_bit: u1,
    pad_to: usize,
) Error!usize {
    const scid = conn.longHeaderScid();
    return try long_packet_mod.sealInitial(dst, .{
        .version = conn.version,
        .dcid = conn.peer_dcid.slice(),
        .scid = scid.slice(),
        .token = if (conn.role == .client) conn.retry_token.items else &.{},
        .pn = pn,
        .largest_acked = largest_acked,
        .payload = payload,
        .keys = keys,
        .pad_to = pad_to,
        .quic_bit = quic_bit,
    });
}

/// Must the datagram that holds this Initial packet be 1200 bytes?
/// RFC 9000 section 14.1: every datagram of a client that carries an
/// Initial packet (ACK-only ones too: a server drops a shorter
/// datagram that begins with an Initial packet); a datagram of a
/// server that carries an ack-eliciting Initial packet.
fn initialNeedsExpansion(conn: *const Connection, ack_eliciting: bool) bool {
    return conn.role == .client or ack_eliciting;
}

/// Make a datagram that holds an Initial packet at least 1200 bytes
/// long (RFC 9000 section 14.1): seal the Initial packet again with
/// PADDING frames behind its payload, and move the packets behind it
/// back. `dst` is the datagram's budget, `pos` the bytes in it.
/// Returns the new length.
fn padInitialDatagram(
    conn: *Connection,
    dst: []u8,
    pos: usize,
    initial: *const InitialInDatagram,
) Error!usize {
    if (!initialNeedsExpansion(conn, initial.ack_eliciting)) return pos;
    if (pos >= min_initial_datagram_len) return pos;
    // `pollLevelOnPath` builds such a packet only when the datagram
    // may become this long (the buffer, and for a server the
    // anti-amplification allowance). The one packet it builds without
    // that check is a client's CONNECTION_CLOSE, which must not fail
    // for a short buffer: it then goes as it is.
    if (dst.len < min_initial_datagram_len) return pos;
    const pad = min_initial_datagram_len - pos;
    const keys: *const PacketKeys = if (conn.initial_keys_write) |*k| k else return pos;
    if (pos > initial.len) {
        // The slices overlap, and the bytes move toward the end.
        @memmove(dst[initial.len + pad .. pos + pad], dst[initial.len..pos]);
    }
    const n = try sealInitialPacket(
        conn,
        dst[0 .. initial.len + pad],
        initial.pn,
        initial.largest_acked,
        initial.payload[0..initial.payload_len],
        keys,
        initial.quic_bit,
        initial.len + pad,
    );
    std.debug.assert(n == initial.len + pad);
    // Padding is bytes on the wire: it counts toward the bytes in
    // flight (RFC 9002 section 2: PADDING makes a packet count), and
    // `pollDatagram` counts the whole datagram against the
    // anti-amplification limit and the pacer.
    if (initial.tracked) _ = conn.sentForLevel(.initial).growPacket(initial.pn, pad);
    conn.qlog_bytes_sent +|= pad;
    return pos + pad;
}

// Doc comment lives on the `Connection.pollLevel` thunk in Connection.zig.
pub fn pollLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    dst: []u8,
    now_us: u64,
) Error!?usize {
    return pollLevelOnPath(conn, lvl, conn.primaryPath().id, dst, now_us);
}

/// A stream chunk packed into the packet being built, with its stream
/// and the connection-local key ACK and loss route by.
pub const SentStreamChunk = struct {
    stream: *Stream,
    chunk: send_stream_mod.Chunk,
    stream_key: u64,
};

pub fn pollLevelOnPath(
    conn: *Connection,
    lvl: EncryptionLevel,
    app_path_id: u32,
    dst: []u8,
    now_us: u64,
) Error!?usize {
    // Determine keys for this level. Initial keys are derived
    // from `initial_dcid`; Handshake/Application keys come from
    // the TLS bridge.
    var keys: *const PacketKeys = undefined;
    var have_keys = false;
    switch (lvl) {
        .initial => {
            try conn_keys.ensureInitialKeys(
                conn,
            );
            if (conn.initial_keys_write) |*k| {
                keys = k;
                have_keys = true;
            }
        },
        .handshake, .application => {
            if (lvl == .application) try conn_keys.prepareApplicationWriteKeys(conn, now_us);
            if (try conn.packetKeys(lvl, .write)) |k| {
                keys = k;
                have_keys = true;
            }
        },
        .early_data => {
            if (!conn.canSendEarlyData()) return null;
            if (try conn.packetKeys(lvl, .write)) |k| {
                keys = k;
                have_keys = true;
            }
        },
    }
    if (!have_keys) return null;
    if (!conn.peer_dcid_set) return Error.PeerDcidNotSet;

    // Build payload.
    const app_path = conn_paths.pathForId(conn, app_path_id);
    const pn_space = conn.pnSpaceForLevelOnPath(lvl, app_path);
    const sent_tracker = conn.sentForLevelOnPath(lvl, app_path);
    const pending_ping = conn.pendingPingForLevelOnPath(lvl, app_path);
    // A full tracker has no slot for one more ack-eliciting packet,
    // and a packet that is not tracked can never be acknowledged or
    // declared lost. So a full tracker closes the gate that a full
    // congestion window closes, and more: nothing ack-eliciting is
    // built at all, probes included, until an ACK or a loss frees a
    // slot. (A probe timeout frees one itself: it takes the oldest
    // packet out before it asks for a probe.) ACK and CONNECTION_CLOSE
    // are not tracked and still go.
    //
    // The question is asked HERE, before a frame leaves its queue and
    // before a packet number is used. When `record` refuses, at the
    // end of this function, the packet is sealed and its frames are
    // gone from their queues: a refusal there cannot be undone.
    // MEASURED 2026-10-03, before this gate: the 4097th small packet
    // in flight made `poll` return `TooManyInFlight`.
    const tracker_full = sent_tracker.isFull();
    // RFC 8899 DPLPMTUD probes can grow the plaintext above 1200
    // bytes (up to `pmtud_config.max_mtu`). `max_recv_plaintext`
    // is the AEAD-supported ceiling on either direction; sizing
    // `pl_buf` to that gives headroom for any probe size we'd
    // accept on receive.
    const pl_buf: *[max_recv_plaintext]u8 = &Connection.scratch().pl_buf;
    var pl_pos: usize = 0;
    var ack_eliciting = false;
    var sent_packet: SentPacketTracker.SentPacket = .{
        .pn = 0,
        .sent_time_us = now_us,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    var sent_packet_recorded = false;
    errdefer if (!sent_packet_recorded) sent_packet.deinit(conn.allocator);
    var sent_crypto_chunk: ?struct {
        level_idx: usize,
        offset: u64,
        data: []u8,
    } = null;
    var sent_datagram: ?SentPacketTracker.SentDatagram = null;
    var crypto_copy: ?[]u8 = null;
    var retx_crypto_index: ?usize = null;
    // The part of the first retransmission chunk that did not fit this
    // packet (see the CRYPTO step). It replaces the chunk at commit.
    var retx_crypto_rest: ?[]u8 = null;
    errdefer if (crypto_copy) |bytes| conn.allocator.free(bytes);
    errdefer if (retx_crypto_rest) |bytes| conn.allocator.free(bytes);

    // Header overhead (worst case) varies by long/short.
    const packet_dcid: *const ConnectionId = if (lvl == .application)
        &app_path.path.peer_cid
    else
        &conn.peer_dcid;
    const packet_scid = conn.longHeaderScid();

    // RFC 8899 DPLPMTUD probe scheduler: when the active path is in
    // `search` and no probe is in flight, build a PADDING+PING
    // packet sized to `pmtu + probe_step` (capped at the upper
    // bound or `pmtud_config.max_mtu`). The probe rides at
    // .application level only; Initial / Handshake follow their
    // own padding / size rules (§14 minimum-MTU 1200 floor on
    // first-flight Initials).
    //
    // The probe ceiling is `pmtud_config.max_mtu`, NOT
    // `Connection.mtu`. The static `mtu` field is the negotiated
    // peer ceiling and is advisory for application data; DPLPMTUD
    // explicitly probes ABOVE it on the assumption the path can
    // carry larger datagrams than the peer's handshake-time
    // advertised receive size. Embedders that want a tighter cap
    // can set `pmtud_config.max_mtu` accordingly.
    //
    // A probe is alone in its datagram (`poll_datagram_used == 0`):
    // behind a Handshake packet the DATAGRAM would be longer than the
    // size the probe stands for, and its loss or its ACK would say
    // nothing about that size. (MEASURED before v0.26.0: a Handshake
    // packet + a probe = one datagram of 2427 bytes.)
    var probe_target_size: ?u16 = null;
    if (lvl == .application and
        !tracker_full and
        conn.poll_datagram_used == 0 and
        conn.pmtud_config.enable and
        app_path.pmtudIsSearching() and
        app_path.path.isValidated())
    {
        if (app_path.pmtudNextProbeSize(
            conn.pmtud_config.probe_step,
            conn.pmtud_config.max_mtu,
        )) |sz| {
            // Don't exceed the embedder's caller buffer.
            if (@as(usize, sz) <= dst.len) probe_target_size = sz;
        }
    }

    // How long this packet may become.
    const packet_room: usize = blk: {
        // The PMTU floor decides how big this packet may become.
        // For .application we read it off the chosen path
        // (DPLPMTUD updates this in step). For Initial/Handshake
        // we use conn.mtu (the connection-wide ceiling — these
        // levels never change per-path). Both are independently
        // capped against `dst`: the embedder's buffer, or what is
        // left of the datagram that `pollDatagram` is building.
        const level_mtu: usize = if (lvl == .application) app_path.pmtu else conn.mtu;
        var room = @min(level_mtu, dst.len);
        // When we've decided to emit a DPLPMTUD probe, the probe
        // size IS the packet capacity for this build (we want the
        // resulting datagram to be exactly that size). The probe
        // size is already capped at `pmtud_config.max_mtu` and
        // `dst.len` by the scheduler above.
        if (probe_target_size) |sz| room = @min(@as(usize, sz), dst.len);
        // RFC 9000 §8.1: anti-amplification applies to ALL bytes the
        // endpoint sends on an unvalidated path, not just 1-RTT.
        // Initial and Handshake bytes count too — otherwise an off-path
        // attacker can spoof a small Initial and force us to emit a
        // full-MTU Initial+Handshake response (a >10x amplification
        // factor when the spoofed Initial is unpadded).
        //
        // The path counts a datagram when it is complete, so the
        // packets that are already in this one are taken off here.
        // (Until v0.26.0 they were not: each coalesced packet had the
        // whole allowance.)
        if (!app_path.path.isValidated()) {
            const allowance = Connection.u64ToUsizeClamped(app_path.path.antiAmpAllowance()) -| conn.poll_datagram_used;
            room = @min(room, allowance);
        }
        break :blk room;
    };
    const max_payload: usize = blk: {
        const dcid_len: usize = packet_dcid.len;
        const scid_len: usize = packet_scid.len;
        const long_overhead: usize = 1 + 4 + 1 + dcid_len + 1 + scid_len + 8 + 4 + 16 + 8; // ample
        const short_overhead: usize = 1 + dcid_len + 4 + 16;
        const overhead: usize = if (lvl == .application) short_overhead else long_overhead;
        if (packet_room <= overhead) break :blk 0;
        // pl_buf is sized to `max_recv_plaintext` so we can
        // accommodate DPLPMTUD probes that grow above the
        // historical 1200-byte default. The plaintext budget
        // never needs more than that on either direction.
        break :blk @min(max_recv_plaintext, packet_room - overhead);
    };
    // `dst[pos..]` arrived too small to seal even an empty packet. This
    // is the routine "no room left in this datagram" outcome — the same
    // back-pressure signal the unvalidated branch above returns when its
    // anti-amp budget is spent. Caller (`pollDatagram` and the embedder
    // poll loop) treats `null` as "nothing to add at this level, move
    // on / try again next tick." Returning `Error.OutputTooSmall` here
    // would escape through `poll` and abort the entire endpoint —
    // particularly hot once the anti-amp fix forces real validation
    // and the validated path's first 1-RTT poll runs against a tiny
    // residual after Initial+Handshake have filled most of the MTU.
    if (max_payload == 0) return null;
    // RFC 9000 section 14.1: a datagram of a server that holds an
    // ack-eliciting Initial packet is 1200 bytes at least. When this
    // datagram cannot become that long (the anti-amplification
    // allowance does not cover it, or the caller's buffer is shorter),
    // the server puts nothing into an Initial packet that asks for an
    // acknowledgment: no CRYPTO data and no PING. An ACK still goes.
    // The data waits for the client's next datagram, as it does when
    // the allowance is zero. (Every padded byte counts against the
    // allowance: `pollDatagram` counts the datagram as it leaves.)
    //
    // The Initial packet is first in its datagram, so `packet_room` is
    // the room of the whole datagram here.
    const initial_ack_eliciting_blocked = lvl == .initial and
        conn.role == .server and
        packet_room < min_initial_datagram_len;
    // Pacing joins the same boolean that scopes cwnd blocking: ACK
    // emission, PTO PINGs, PATH_CHALLENGE, and CONNECTION_CLOSE are
    // outside this gate by construction (they never consult it), so a
    // paced-blocked poll still keeps the connection responsive.
    //
    // The two halves stay separately visible because flow-control
    // credit is exempt from the PACING half only (see `app_credit`
    // below) — and the pacing check must run unconditionally (not
    // short-circuited behind the cwnd check): it lazily refills the
    // path's bucket, and a receive-mostly endpoint whose polls never
    // reached it would freeze its bucket at whatever debt the exempt
    // ACK sends left behind.
    const cwnd_blocked = tracker_full or conn.congestionBlockedOnPath(lvl, app_path);
    const pacing_blocked =
        conn.pacingBlockedOnPath(lvl, app_path, now_us, @min(@as(u64, @intCast(app_path.pmtu)), @as(u64, @intCast(dst.len))));
    const congestion_blocked = cwnd_blocked or pacing_blocked;
    const path_response_addr_overrides_current = blk: {
        if (lvl != .application) break :blk false;
        if (conn.pending_frames.path_response == null) break :blk false;
        if (conn.pending_frames.path_response_path_id != app_path.id) break :blk false;
        const addr = conn.pending_frames.path_response_addr orelse break :blk false;
        break :blk !Address.eql(addr, app_path.path.peer_addr);
    };
    const app_control_blocked = congestion_blocked or path_response_addr_overrides_current;

    // Peer-initiated migration just queued a PATH_CHALLENGE on this
    // path: the receive side observed an authenticated datagram from
    // a fresh 4-tuple, `handlePeerAddressChange` snapshotted the old
    // state into `migration_rollback`, armed the validator, and
    // queued the challenge. RFC 9000 §8.2.1 ¶3 says probing-frame
    // datagrams MUST be padded to 1200 bytes (subject to anti-amp).
    //
    // Quiche's path-validation state machine is sensitive to where
    // PATH_CHALLENGE sits in the FIRST server datagram on the new
    // tuple: when ACK / MAX_DATA / MAX_STREAMS / NEW_CONNECTION_ID
    // precede it (the historical drain order), quiche occasionally
    // misroutes the packet's path-validation handling and stalls
    // the migration. Detect the freshly-migrated path here and emit
    // PATH_CHALLENGE FIRST on the next packet — before ACK and
    // every other queued control frame. This guarantees:
    //   1. PATH_CHALLENGE leads the packet (deterministic frame
    //      order across runs);
    //   2. PATH_CHALLENGE is in the FIRST emitted packet on the
    //      new path (no slot stolen by an earlier ACK-only packet
    //      because ACK is reordered behind us).
    //
    // The condition is intentionally narrow: the path must have a
    // queued PATH_CHALLENGE for THIS app_path AND the path must be
    // in the peer-migration validation window (`pending_migration_reset`
    // + `validator.status == .pending`). Client-initiated migration
    // hits the same condition (it also sets `pending_migration_reset`).
    // PATH_RESPONSE-only paths (peer probed us; we're echoing) and
    // ordinary CID-rotation paths don't trigger this fast path.
    const emit_path_challenge_first = blk: {
        if (lvl != .application) break :blk false;
        if (tracker_full) break :blk false;
        if (path_response_addr_overrides_current) break :blk false;
        if (conn.pending_frames.path_challenge == null) break :blk false;
        if (conn.pending_frames.path_challenge_path_id != app_path.id) break :blk false;
        if (!app_path.pending_migration_reset) break :blk false;
        if (app_path.path.validator.status != .pending) break :blk false;
        // PATH_CHALLENGE is 9 bytes (1 type + 8 token). Anti-amp
        // may have clamped `max_payload` below that; if so, we
        // can't emit a probing frame at all this poll. Skip the
        // fast path; the regular drain path will retry on the
        // next poll once anti-amp credit accrues.
        if (max_payload < 9) break :blk false;
        break :blk true;
    };

    // RFC 9000 §10.2.1 ¶2: "An endpoint MUST NOT send any frames
    // other than CONNECTION_CLOSE in the closing state." Once the
    // connection has flipped `closed` and there is no queued CC
    // (the pre-empt path below is the only escape hatch), every
    // other frame this function would emit — ACKs, CRYPTO retx,
    // streams, control frames — is illegal. Bail out before any
    // frame-builder runs. The first emit reaches this point with
    // `pending_close != null` and proceeds via the pre-empt path;
    // §10.2.1 ¶3 retransmits re-arm `pending_close` and re-enter
    // the same path on the next `poll`.
    if (conn.lifecycle.closed and conn.lifecycle.pending_close == null) return null;

    // CONNECTION_CLOSE pre-empts everything: if pending, that's
    // the only frame we emit, and we mark the connection
    // closed once it goes on the wire.
    if (conn.lifecycle.pending_close) |info| {
        // RFC 9000 §10.2.3: the close must be in a packet that the
        // peer can read, and during the handshake the two ends do not
        // have the same keys at the same time. A server has 1-RTT
        // WRITE keys as soon as its flight is built; the client can
        // read 1-RTT only when it has the whole flight. A client that
        // has sent a Handshake packet has no Initial keys. A server
        // has 1-RTT READ keys only with the client's Finished. So ("a
        // server SHOULD send a CONNECTION_CLOSE frame in both
        // Handshake and Initial packets", "an endpoint SHOULD send a
        // CONNECTION_CLOSE frame in both Handshake and 1-RTT
        // packets") `pollDatagram` puts the close into ONE datagram
        // at EVERY level this endpoint has write keys for. "Has keys"
        // is the whole rule: Initial keys go when the peer is known
        // to be past them, Handshake keys when the handshake is
        // confirmed, and after that there is only 1-RTT, where the
        // close has gone alone since before this rule.
        //
        // Until v0.26.0 the close went at ONE level, and with 1-RTT
        // write keys that level was 1-RTT: a peer in the middle of
        // the handshake could not read it, learned no error code, and
        // waited for its own timeout.
        //
        // A direct `pollLevel(lvl, ...)` has no datagram to share:
        // there the close still waits for the highest level (and an
        // application close then keeps its own code and reason).
        const in_datagram = conn.poll_initial != null;
        if (!in_datagram and lvl != .application and conn.app_write_current != null) {
            return null;
        }
        // Secure-by-default redaction: keep the reason off the wire
        // by default. Embedders can opt in to wire-visible reasons
        // via `reveal_close_reason_on_wire = true`. Local sticky
        // reason (`lifecycle.record(...)` above the close path) is
        // always retained for embedder telemetry.
        const wire_reason: []const u8 = if (conn.reveal_close_reason_on_wire)
            info.reason
        else
            &[_]u8{};
        // RFC 9000 §10.2.3 ¶4 (and Table 3 §12.4): the
        // application-variant CONNECTION_CLOSE (0x1d) MUST NOT be
        // emitted at Initial or Handshake encryption levels —
        // those levels predate application data, so an
        // application-error code there is meaningless. Convert to
        // the transport variant (0x1c) with a generic
        // APPLICATION_ERROR (0x0c) code; the embedder still sees
        // the original via the sticky `closeEvent()` (the
        // record(.local, ...) path above ran before queueing
        // pending_close). At 1-RTT (.application) and 0-RTT
        // (.early_data) — both of which carry application data —
        // the original variant goes on the wire unchanged.
        const force_transport_at_level = !info.is_transport and
            (lvl == .initial or lvl == .handshake);
        const wire_is_transport = info.is_transport or force_transport_at_level;
        const wire_error_code = if (force_transport_at_level)
            transport_error_application_error
        else
            info.error_code;
        const wire_frame_type = if (wire_is_transport) info.frame_type else 0;
        const close_frame = frame_types.ConnectionClose{
            .is_transport = wire_is_transport,
            .error_code = wire_error_code,
            .frame_type = wire_frame_type,
            // §10.2.3 ¶3, for the conversion above: "Endpoints MUST
            // clear the value of the Reason Phrase field". An
            // Initial or Handshake packet is not protected the way
            // 1-RTT is, and the reason is the application's own
            // words. (Until v0.26.0 the reason went with the
            // converted frame when the embedder had turned
            // `reveal_close_reason_on_wire` on.)
            .reason_phrase = if (force_transport_at_level) &[_]u8{} else wire_reason,
        };
        const wrote = try frame_mod.encode(
            pl_buf[0..max_payload],
            .{ .connection_close = close_frame },
        );
        pl_pos += wrote;
        // RFC 9000 §10.2 ¶2: "After sending a CONNECTION_CLOSE
        // frame, an endpoint immediately enters the closing
        // state." We arm the closing-state machinery via
        // `noteCloseEmit` further below (it needs the sealed-byte
        // count and the timer derived from PTO). Before the seal,
        // clear `pending_close` so a recursive `close()` from a
        // mid-emit error path doesn't double-queue the frame. Inside
        // `pollDatagram` the close stays pending for the levels
        // behind this one, and `pollDatagram` does both when the
        // datagram is complete.
        if (!in_datagram) conn.lifecycle.pending_close = null;
        // No ack-eliciting flag — CONNECTION_CLOSE isn't
        // ack-eliciting per §13.2.1, but we do still want to
        // record it (it occupies a PN). Skip stream/CRYPTO/etc.
        const pn = pn_space.nextPn() orelse return Error.PnSpaceExhausted;
        const largest_acked_close = pn_space.largest_acked_sent;
        const close_quic_bit = conn_paths.nextQuicBit(
            conn,
        );
        const n_close = switch (lvl) {
            // A client's Initial packet with the close is padded like
            // every other one (a server drops a shorter datagram that
            // begins with an Initial packet, and with it the close),
            // and carries the token of a Retry like every other one.
            // Until v0.26.0 it had neither. A buffer that is too short
            // for the padding does not stop a close: it then goes as
            // it is.
            .initial => try sealInitialPacket(
                conn,
                dst,
                pn,
                largest_acked_close,
                pl_buf[0..pl_pos],
                keys,
                close_quic_bit,
                if (conn.poll_initial == null and initialNeedsExpansion(conn, false) and dst.len >= min_initial_datagram_len)
                    min_initial_datagram_len
                else
                    0,
            ),
            .handshake => try long_packet_mod.sealHandshake(dst, .{
                .version = conn.version,
                .dcid = packet_dcid.slice(),
                .scid = packet_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked_close,
                .payload = pl_buf[0..pl_pos],
                .keys = keys,
                .quic_bit = close_quic_bit,
            }),
            .application => try short_packet_mod.seal1Rtt(dst, .{
                .dcid = packet_dcid.slice(),
                .pn = pn,
                .largest_acked = largest_acked_close,
                .payload = pl_buf[0..pl_pos],
                .keys = keys,
                .staging = &Connection.scratch().stage_buf,
                .key_phase = conn_keys.applicationWriteKeyPhase(
                    conn,
                ),
                .multipath_path_id = if (conn.multipathNegotiated()) app_path.id else null,
                .quic_bit = close_quic_bit,
            }),
            .early_data => try long_packet_mod.sealZeroRtt(dst, .{
                .version = conn.version,
                .dcid = packet_dcid.slice(),
                .scid = packet_scid.slice(),
                .pn = pn,
                .largest_acked = largest_acked_close,
                .payload = pl_buf[0..pl_pos],
                .keys = keys,
                .quic_bit = close_quic_bit,
            }),
        };
        var close_packet: SentPacketTracker.SentPacket = .{
            .pn = pn,
            .sent_time_us = now_us,
            .bytes = n_close,
            .ack_eliciting = false,
            .in_flight = false,
            .is_early_data = lvl == .early_data,
        };
        if (lvl == .application) conn_keys.recordApplicationPacketProtected(conn, &close_packet);
        if (conn.ecn_enabled) pn_space.ect_marked_sent +|= 1;
        // The close packet is not ack-eliciting: nothing waits for its
        // ACK, and it is not in flight. A full tracker must not stop
        // it (the close would be lost: `pending_close` is cleared
        // above), so it then goes out untracked.
        if (!tracker_full) try sent_tracker.record(close_packet);
        // RFC 9000 §10.2.1 closing state. The first emit arms a
        // 3*PTO closing-state deadline; subsequent §10.2.1 ¶3
        // retransmits leave the deadline at its original value
        // (extending it would let a chatty peer keep the slot
        // alive past §10.2 ¶5's bound).
        if (in_datagram) {
            // One emit for the whole datagram (the counter is the
            // exponent of the back-off for the next one).
            conn.poll_close_emitted = true;
        } else {
            noteCloseEmitted(conn, now_us);
        }
        conn.qlog_packets_sent +|= 1;
        conn.qlog_bytes_sent +|= n_close;
        if (lvl == .initial and conn.poll_initial != null) {
            noteInitialInDatagram(conn.poll_initial.?, n_close, pn, largest_acked_close, close_quic_bit, false, !tracker_full, pl_buf[0..pl_pos]);
        } else {
            conn_qlog.emitPacketSent(conn, lvl, pn, @intCast(n_close), 1);
        }
        if (!in_datagram) conn_qlog.emitConnectionStateIfChanged(
            conn,
        );
        return n_close;
    }

    // 0) PATH_CHALLENGE-first on a freshly-migrated path. RFC 9000
    // §8.2 / §9 — quiche's path-validation state machine expects
    // PATH_CHALLENGE to lead the first server datagram on the new
    // tuple; reordering it behind ACK / MAX_DATA / etc. (the
    // historical drain order, see section 2d below) loses
    // interop with quiche's `BA` (rebind-addr) test. The fast
    // path here writes the 9-byte frame BEFORE every other queued
    // frame so it's first on the wire AND so it can never be
    // pushed past the per-packet capacity by a fat ACK or a
    // freshly-queued NEW_CONNECTION_ID. Subsequent frames
    // (ACK, MAX_DATA, etc.) coalesce behind it as usual.
    if (emit_path_challenge_first) {
        const tok = conn.pending_frames.path_challenge.?;
        const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
            .path_challenge = .{ .data = tok },
        });
        pl_pos += wrote;
        try sent_packet.addRetransmitFrame(conn.allocator, .{
            .path_challenge = .{ .data = tok },
        });
        conn.pending_frames.path_challenge = null;
        ack_eliciting = true;
    }

    // 1) ACK frame (if pending in this level's space).
    const recv_tracker = &pn_space.received;
    if (lvl != .early_data and recv_tracker.pending_ack) {
        const ranges_buf: *[default_mtu]u8 = &Connection.scratch().ranges_buf;
        const available = max_payload - pl_pos;
        var ranges_budget: usize = @min(ranges_buf.len, available);
        if (lvl == .application) {
            ranges_budget = @min(ranges_budget, max_application_ack_ranges_bytes);
        }
        // RFC 9000 §13.4.1: outgoing ACK frames include ECN
        // counts when (a) we still believe ECN works on this
        // path (`validation == .testing`), AND (b) at least one
        // received packet at this level was ECN-marked. Otherwise
        // we stay at the no-ECN frame type so we don't mislead
        // the peer's monotonicity validation.
        const ack_ecn_counts: ?frame_types.EcnCounts = blk: {
            if (!conn.ecn_enabled) break :blk null;
            if (pn_space.validation == .failed) break :blk null;
            if (!pn_space.hasObservedEcn()) break :blk null;
            break :blk frame_types.EcnCounts{
                .ect0 = pn_space.recv_ect0,
                .ect1 = pn_space.recv_ect1,
                .ecn_ce = pn_space.recv_ce,
            };
        };
        while (true) {
            const max_lower_ranges = if (lvl == .application)
                max_application_ack_lower_ranges
            else
                std.math.maxInt(u64);
            const ack_frame = try recv_tracker.toAckFrameLimitedRangesWithEcn(
                conn.ackDelayScaled(recv_tracker, now_us),
                ranges_buf,
                ranges_budget,
                max_lower_ranges,
                ack_ecn_counts,
            );
            const frame: frame_types.Frame = if (lvl == .application and app_path.id != 0)
                .{ .path_ack = .{
                    .path_id = app_path.id,
                    .largest_acked = ack_frame.largest_acked,
                    .ack_delay = ack_frame.ack_delay,
                    .first_range = ack_frame.first_range,
                    .range_count = ack_frame.range_count,
                    .ranges_bytes = ack_frame.ranges_bytes,
                    .ecn_counts = ack_frame.ecn_counts,
                } }
            else
                .{ .ack = ack_frame };
            const needed = frame_mod.encodedLen(frame);
            if (needed <= available) {
                const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], frame);
                pl_pos += wrote;
                recv_tracker.markAckSent();
                break;
            }
            if (ranges_budget == 0 or ack_frame.ranges_bytes.len == 0) break;
            const overflow = needed - available;
            const reduced_budget = if (overflow >= ack_frame.ranges_bytes.len)
                @as(usize, 0)
            else
                ack_frame.ranges_bytes.len - overflow;
            ranges_budget = if (reduced_budget >= ack_frame.ranges_bytes.len)
                ack_frame.ranges_bytes.len - 1
            else
                reduced_budget;
        }
    }

    // 1a) PTO probe PING. A lost PING is not retransmitted as a
    // frame, but a later PTO will queue another probe.
    if (!tracker_full and !path_response_addr_overrides_current and !initial_ack_eliciting_blocked and lvl != .early_data and pending_ping.* and pl_pos + 1 <= max_payload) {
        const ping_len = try frame_mod.encode(
            pl_buf[pl_pos..max_payload],
            .{ .ping = .{} },
        );
        pl_pos += ping_len;
        pending_ping.* = false;
        ack_eliciting = true;
    }

    // 1a-pmtud) RFC 8899 DPLPMTUD probe PING. Always pairs with
    // PADDING below to inflate the datagram to `probe_target_size`.
    // The probe is structurally identical to a PTO PING (frame
    // type 0x01, 1 byte) but the in-flight bookkeeping is
    // DPLPMTUD-specific (recorded via `pmtudOnProbeSent` after the
    // seal so loss detection can route the loss outcome to
    // `pmtudOnProbeLost` instead of normal CC). The packet is
    // ack-eliciting per RFC 9000 §14.4 and §13.2.1.
    var pmtud_probe_emitted = false;
    if (probe_target_size != null and pl_pos + 1 <= max_payload) {
        const ping_len = try frame_mod.encode(
            pl_buf[pl_pos..max_payload],
            .{ .ping = .{} },
        );
        pl_pos += ping_len;
        ack_eliciting = true;
        pmtud_probe_emitted = true;
    }

    // 1b) Server handshake confirmation. HANDSHAKE_DONE is
    // application-level, ack-eliciting, and retransmittable.
    if (!app_control_blocked and lvl == .application and conn.pending_handshake_done and pl_pos + 1 <= max_payload) {
        const wrote = try frame_mod.encode(
            pl_buf[pl_pos..max_payload],
            .{ .handshake_done = .{} },
        );
        pl_pos += wrote;
        try sent_packet.addRetransmitFrame(conn.allocator, .{ .handshake_done = .{} });
        conn.pending_handshake_done = false;
        ack_eliciting = true;
    }

    // 1c) Server NEW_TOKEN issuance (RFC 9000 §19.7). The frame
    // is application-level, ack-eliciting, and retransmittable;
    // we emit at most one per session. Frame layout: type byte
    // (0x07) + varint(token.len) + token bytes.
    if (!app_control_blocked and lvl == .application) if (conn.pending_frames.new_token) |item| {
        const overhead_nt: usize = 1 + varint_mod.encodedLen(item.len) + item.len;
        if (max_payload >= pl_pos + overhead_nt) {
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .new_token = .{ .token = item.slice() },
            });
            pl_pos += wrote;
            // Stash a copy in the retransmit slot so loss
            // recovery can requeue from the captured bytes
            // (the pending-frames slot is about to be cleared).
            var retx_item: SentPacketTracker.NewTokenRetransmit = .{};
            @memcpy(retx_item.bytes[0..item.len], item.slice());
            retx_item.len = item.len;
            try sent_packet.addRetransmitFrame(conn.allocator, .{
                .new_token = retx_item,
            });
            conn.pending_frames.new_token = null;
            ack_eliciting = true;
        }
    };

    // 2) CRYPTO frame: retransmit lost data first, then drain
    // fresh outbox bytes at this level into one frame.
    const out_idx = lvl.idx();
    const crypto_allowed = lvl != .early_data and !congestion_blocked and !initial_ack_eliciting_blocked;
    if (crypto_allowed and conn.crypto_retx[out_idx].items.len > 0 and pl_pos + 25 < max_payload) {
        const max_data = max_payload - pl_pos - 25;
        const chunk = conn.crypto_retx[out_idx].items[0];
        // A chunk that does not fit whole is cut: the front goes now,
        // the rest stays first in the queue. A chunk is as long as
        // the room was when its data went out the first time, in a
        // full packet as a rule. The room is seldom the same again:
        // an ACK frame or a PING is in front of it now, or an Initial
        // packet takes part of the datagram. Until v0.26.0 a chunk
        // that did not fit whole was not sent, and no fresh CRYPTO
        // data behind it either: with the datagram's budget shared
        // between its packets, that could be every time.
        const send_len = @min(chunk.data.len, max_data);
        const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
            .crypto = .{
                .offset = chunk.offset,
                .data = chunk.data[0..send_len],
            },
        });
        pl_pos += wrote;
        const copy = try conn.allocator.dupe(u8, chunk.data[0..send_len]);
        crypto_copy = copy;
        sent_crypto_chunk = .{
            .level_idx = out_idx,
            .offset = chunk.offset,
            .data = copy,
        };
        if (send_len == chunk.data.len) {
            retx_crypto_index = 0;
        } else {
            // The rest gets its own allocation now, while an error
            // can still leave everything as it was.
            retx_crypto_rest = try conn.allocator.dupe(u8, chunk.data[send_len..]);
        }
        ack_eliciting = true;
    } else if (crypto_allowed and conn.outbox[out_idx].len > 0 and pl_pos + 25 < max_payload) {
        const max_data = max_payload - pl_pos - 25;
        const drain_len = @min(conn.outbox[out_idx].len, max_data);
        const data_slice = conn.outbox[out_idx].buf[0..drain_len];
        const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
            .crypto = .{
                .offset = conn.crypto_send_offset[out_idx],
                .data = data_slice,
            },
        });
        pl_pos += wrote;
        const copy = try conn.allocator.dupe(u8, data_slice);
        crypto_copy = copy;
        sent_crypto_chunk = .{
            .level_idx = out_idx,
            .offset = conn.crypto_send_offset[out_idx],
            .data = copy,
        };
        conn.crypto_send_offset[out_idx] += drain_len;
        // Shift the outbox left to drop what we just consumed.
        const remaining = conn.outbox[out_idx].len - drain_len;
        @memmove(
            conn.outbox[out_idx].buf[0..remaining],
            conn.outbox[out_idx].buf[drain_len..conn.outbox[out_idx].len],
        );
        conn.outbox[out_idx].len = remaining;
        ack_eliciting = true;
    }

    // 2a) MAX_DATA / MAX_STREAM_DATA (application only). We queue these
    // when the application drains receive buffers so peers can
    // continue uploads beyond their current stream window.
    // Every block below has the same shape: gate on the 1-RTT
    // control budget, build the payload ONCE, and let
    // `encodeFrameIfFits` do the size check against
    // `frame_mod.encodedLen` — never a hand-rolled re-derivation of
    // the encoder's length math. Only the per-frame dequeue stays
    // inline, since that part is genuinely per-frame.
    const app_control = !app_control_blocked and lvl == .application;

    // Flow-control credit and blocked-signal frames are exempt from
    // the PACING half of the gate (cwnd and the path-response
    // override still apply). Pacing exists to smooth data bursts
    // (RFC 9002 §7.7 is a SHOULD about emission timing); RFC 9000
    // §4.2 warns that withheld credit deadlocks the connection — and
    // that deadlock is reachable: a receive-mostly endpoint's exempt
    // ACK sends debit the bucket faster than a low pacing rate
    // refills it, so a MAX_STREAM_DATA grant queued behind the paced
    // gate never leaves while the peer sits send-blocked forever
    // (found by the 2-flow BBR fairness cell). These frames are a few
    // dozen bytes and ride the same exempt shape ACKs do; they still
    // debit the bucket, keeping the rate accounting truthful.
    const app_credit = lvl == .application and
        !cwnd_blocked and !path_response_addr_overrides_current;

    if (app_credit and conn.pending_frames.max_data != null) {
        const md: frame_types.MaxData = .{ .maximum_data = conn.pending_frames.max_data.? };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .max_data = md })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .max_data = md });
            conn.pending_frames.max_data = null;
            ack_eliciting = true;
        }
    }
    if (app_credit and conn.pending_frames.max_stream_data.items.len > 0) {
        const item = conn.pending_frames.max_stream_data.items[0];
        const msd: frame_types.MaxStreamData = .{
            .stream_id = item.stream_id,
            .maximum_stream_data = item.maximum_stream_data,
        };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .max_stream_data = msd })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .max_stream_data = msd });
            _ = conn.pending_frames.max_stream_data.orderedRemove(0);
            ack_eliciting = true;
        }
    }
    if (app_credit and (conn.pending_frames.max_streams_bidi != null or conn.pending_frames.max_streams_uni != null)) {
        const bidi = conn.pending_frames.max_streams_bidi != null;
        const pending = conn_flow.pendingMaxStreamsSlot(conn, bidi);
        const ms: frame_types.MaxStreams = .{
            .bidi = bidi,
            .maximum_streams = pending.*.?,
        };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .max_streams = ms })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .max_streams = ms });
            pending.* = null;
            ack_eliciting = true;
        }
    }
    if (app_credit and conn.pending_frames.data_blocked != null) {
        const db: frame_types.DataBlocked = .{ .maximum_data = conn.pending_frames.data_blocked.? };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .data_blocked = db })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .data_blocked = db });
            conn.pending_frames.data_blocked = null;
            ack_eliciting = true;
        }
    }
    if (app_credit and conn.pending_frames.stream_data_blocked.items.len > 0) {
        const item = conn.pending_frames.stream_data_blocked.items[0];
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .stream_data_blocked = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .stream_data_blocked = item });
            _ = conn.pending_frames.stream_data_blocked.orderedRemove(0);
            ack_eliciting = true;
        }
    }
    if (app_credit and (conn.pending_frames.streams_blocked_bidi != null or conn.pending_frames.streams_blocked_uni != null)) {
        const bidi = conn.pending_frames.streams_blocked_bidi != null;
        const pending = conn_flow.pendingStreamsBlockedSlot(conn, bidi);
        const sb: frame_types.StreamsBlocked = .{
            .bidi = bidi,
            .maximum_streams = pending.*.?,
        };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .streams_blocked = sb })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .streams_blocked = sb });
            pending.* = null;
            ack_eliciting = true;
        }
    }

    // 2b) NEW_CONNECTION_ID (application only). Advertise spare
    // CIDs so peers can validate/migrate additional paths.
    if (app_control and conn.pending_frames.new_connection_ids.items.len > 0) {
        const item = conn.pending_frames.new_connection_ids.items[0];
        const ncid: frame_types.NewConnectionId = .{
            .sequence_number = item.sequence_number,
            .retire_prior_to = item.retire_prior_to,
            .connection_id = item.connection_id,
            .stateless_reset_token = item.stateless_reset_token,
        };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .new_connection_id = ncid })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .new_connection_id = ncid });
            _ = conn.pending_frames.new_connection_ids.orderedRemove(0);
            ack_eliciting = true;
        }
    }

    if (app_control and conn.pending_frames.retire_connection_ids.items.len > 0) {
        const item = conn.pending_frames.retire_connection_ids.items[0];
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .retire_connection_id = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .retire_connection_id = item });
            _ = conn.pending_frames.retire_connection_ids.orderedRemove(0);
            ack_eliciting = true;
        }
    }

    // 2bx) ALTERNATIVE_V4/V6_ADDRESS (application only).
    // draft-munizaga-quic-alternative-server-address-00 §6 / §7:
    // application-data PN space, ack-eliciting. One frame per
    // packet keeps the size budgeting trivial and matches the
    // NEW_CONNECTION_ID drain pattern above; back-pressured advertise
    // calls accumulate in `pending_frames.alternative_addresses` and
    // drain across subsequent polls.
    if (app_control and conn.pending_frames.alternative_addresses.items.len > 0) {
        const item = conn.pending_frames.alternative_addresses.items[0];
        const candidate: frame_types.Frame = switch (item) {
            .v4 => |a| .{ .alternative_v4_address = a },
            .v6 => |a| .{ .alternative_v6_address = a },
        };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, candidate)) {
            const retx: SentPacketTracker.RetransmitFrame = switch (item) {
                .v4 => |a| .{ .alternative_v4_address = a },
                .v6 => |a| .{ .alternative_v6_address = a },
            };
            try sent_packet.addRetransmitFrame(conn.allocator, retx);
            _ = conn.pending_frames.alternative_addresses.orderedRemove(0);
            ack_eliciting = true;
        }
    }

    // 2c) STOP_SENDING (at most one per packet — application only).
    if (app_control and conn.pending_frames.stop_sending.items.len > 0) {
        const item = conn.pending_frames.stop_sending.items[0];
        const ss: frame_types.StopSending = .{
            .stream_id = item.stream_id,
            .application_error_code = item.application_error_code,
        };
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .stop_sending = ss })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .stop_sending = ss });
            _ = conn.pending_frames.stop_sending.orderedRemove(0);
            ack_eliciting = true;
        }
    }

    // 2c2) ACK_FREQUENCY / IMMEDIATE_ACK (application only; the
    //      Acknowledgement Frequency extension). ACK_FREQUENCY is
    //      queued again when lost while it is still the latest
    //      request; IMMEDIATE_ACK is not (its packet's loss is moot).
    if (app_control and conn.pending_frames.ack_frequency != null) {
        const af = conn.pending_frames.ack_frequency.?;
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .ack_frequency = af })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .ack_frequency = af });
            conn.pending_frames.ack_frequency = null;
            ack_eliciting = true;
        }
    }
    if (app_control and conn.pending_frames.immediate_ack) {
        if (try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .immediate_ack = .{} })) {
            conn.pending_frames.immediate_ack = false;
            ack_eliciting = true;
        }
    }

    // 2d) PATH_RESPONSE / PATH_CHALLENGE (application level only,
    //     RFC 9000 §19.17/19.18). PATH_RESPONSE has the highest
    //     priority on the application path so we don't make the
    //     peer wait through a stream-data backlog.
    // RFC 9000 §8.2.1 + §9.4: PATH_CHALLENGE / PATH_RESPONSE are
    // probing frames that exist precisely to validate (or echo
    // validation on) a path whose congestion state we don't know
    // yet. Gating them on the *old* path's `congestion_blocked`
    // creates a deadlock at migration time: the file transfer
    // saturates the old cwnd, the address rebinds, the cwnd
    // (still old) rejects the PATH_CHALLENGE that's needed to
    // validate the new path, and the migration never completes.
    // The runner's rebind-addr verifier catches this directly:
    // it requires the FIRST server packet on a new client path to
    // contain a PATH_CHALLENGE frame. The 9-byte probe is small
    // enough that letting it past the CC limit is harmless; the
    // anti-amp `max_payload` clamp on unvalidated paths is the
    // real ceiling. A subsequent PATH_RESPONSE arrival resets the
    // path's CC to initial values via
    // `resetPathRecoveryAfterMigration`.
    var path_response_used_addr_override = false;
    if (!tracker_full and lvl == .application and conn.pending_frames.path_response != null and
        conn.pending_frames.path_response_path_id == app_path.id and pl_pos + 9 <= max_payload)
    {
        if (conn.pending_frames.path_response_addr) |addr| {
            path_response_used_addr_override = !Address.eql(addr, app_path.path.peer_addr);
        }
        const pr: frame_types.PathResponse = .{ .data = conn.pending_frames.path_response.? };
        conn.poll_addr_override = conn.pending_frames.path_response_addr;
        // The enclosing condition already reserved the frame's exact
        // encoded size, so this cannot fail to fit.
        std.debug.assert(try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .path_response = pr }));
        try sent_packet.addRetransmitFrame(conn.allocator, .{ .path_response = pr });
        conn.pending_frames.path_response = null;
        conn.pending_frames.path_response_addr = null;
        ack_eliciting = true;
    }
    if (!tracker_full and !path_response_used_addr_override and
        lvl == .application and conn.pending_frames.path_challenge != null and
        conn.pending_frames.path_challenge_path_id == app_path.id and pl_pos + 9 <= max_payload)
    {
        const pc: frame_types.PathChallenge = .{ .data = conn.pending_frames.path_challenge.? };
        // Same reservation as PATH_RESPONSE above: cannot fail to fit.
        std.debug.assert(try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .path_challenge = pc }));
        try sent_packet.addRetransmitFrame(conn.allocator, .{ .path_challenge = pc });
        conn.pending_frames.path_challenge = null;
        ack_eliciting = true;
    }

    // 2e) Draft-21 multipath control frames. Coalesce as many as
    //     fit while preserving per-frame retransmit metadata.
    if (!path_response_used_addr_override and !congestion_blocked and lvl == .application) {
        if (try emitPendingMultipathFrames(conn, &sent_packet, pl_buf, &pl_pos, max_payload)) {
            ack_eliciting = true;
        }
    }

    // 2e) RESET_STREAM frames for streams in reset_sent state
    //     whose RESET hasn't been queued yet. At most one per
    //     packet; remaining resets ride subsequent packets.
    if (!path_response_used_addr_override and !congestion_blocked and lvl == .application) {
        var rs_it = conn.streams.iterator();
        while (rs_it.next()) |entry| {
            const s = entry.value_ptr.*;
            if (s.send.reset) |*ri| {
                if (ri.queued) continue;
                const rs: frame_types.ResetStream = .{
                    .stream_id = s.id,
                    .application_error_code = ri.error_code,
                    .final_size = ri.final_size,
                };
                if (!try encodeFrameIfFits(pl_buf, &pl_pos, max_payload, .{ .reset_stream = rs })) break;
                try sent_packet.addRetransmitFrame(conn.allocator, .{ .reset_stream = rs });
                ri.queued = true;
                // The reset is on its way: nothing more to send here.
                conn_streams.noteSendable(conn, s);
                ack_eliciting = true;
                break;
            }
        }
    }

    // 3a) DATAGRAM frame (Application PN space). One queued
    //     payload per packet; LEN-prefixed so DATAGRAM doesn't
    //     have to be the last frame.
    if (!path_response_used_addr_override and !congestion_blocked and (lvl == .application or lvl == .early_data) and conn.pending_frames.send_datagrams.items.len > 0) {
        const dg = conn.pending_frames.send_datagrams.items[0];
        const dg_overhead: usize = 1 + varint_mod.encodedLen(dg.data.len);
        if (max_payload >= pl_pos + dg_overhead + dg.data.len) {
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .datagram = .{ .data = dg.data, .has_length = true },
            });
            pl_pos += wrote;
            _ = conn.pending_frames.send_datagrams.orderedRemove(0);
            conn.pending_frames.send_datagram_bytes -= dg.data.len;
            sent_datagram = .{
                .id = dg.id,
                .len = dg.data.len,
                .path_id = app_path.id,
            };
            conn.allocator.free(dg.data);
            ack_eliciting = true;
        }
    }

    // 3b) STREAM frames (Application PN space). Pack as many
    // independent streams as fit; each chunk gets its own
    // connection-local key so ACK/loss can still route precisely.
    // The array lives in the connection's scratch: as a local it was
    // a 1,280-byte 0xAA fill per packet (2% of the engine's CPU).
    const sent_chunks: *[SentPacketTracker.max_stream_keys_per_packet]SentStreamChunk = &Connection.scratch().sent_chunks;
    var sent_chunk_count: usize = 0;
    var planned_conn_new_bytes: u64 = 0;
    if (!path_response_used_addr_override and !congestion_blocked and (lvl == .application or lvl == .early_data)) {
        // RFC 9218: emit ready streams in urgency order (then stream id)
        // rather than hash-map order, so a higher-urgency stream's bytes
        // lead each packet. Bounded to the per-packet chunk cap; excess
        // ready streams are served on later packets. With no explicit
        // priorities every stream is urgency 3, so this is stream-id order.
        const ready_streams = conn.collectSendableStreamsByPriority(&Connection.scratch().pri_buf);
        for (ready_streams) |s| {
            if (sent_chunk_count >= sent_chunks.len) break;
            const stream_overhead: usize = 25;
            if (max_payload <= pl_pos + stream_overhead) break;
            const budget = max_payload - pl_pos - stream_overhead;
            const raw_chunk = s.send.peekChunk(budget) orelse continue;
            const chunk = (try conn_streams.limitChunkToSendFlowAfterPlanned(
                conn,
                s,
                raw_chunk,
                planned_conn_new_bytes,
            )) orelse continue;
            const data_slice = s.send.chunkBytesContiguous(chunk, &Connection.scratch().chunk_buf);
            const wrote = try frame_mod.encode(pl_buf[pl_pos..max_payload], .{
                .stream = .{
                    .stream_id = s.id,
                    .offset = chunk.offset,
                    .data = data_slice,
                    .has_offset = chunk.offset != 0,
                    .has_length = true,
                    .fin = chunk.fin,
                },
            });
            pl_pos += wrote;
            sent_chunks[sent_chunk_count] = .{
                .stream = s,
                .chunk = chunk,
                .stream_key = conn.nextStreamPacketKey(),
            };
            sent_chunk_count += 1;
            planned_conn_new_bytes +|= conn_streams.streamFlowNewBytes(s, chunk);
            ack_eliciting = true;
        }
    }

    if (pl_pos == 0) {
        // draft-cheng-02 §3.4 / draft-ietf-ccwg-bbr-06 §4.1.2.4: this
        // poll ran every frame builder dry at full budget — the app
        // (not the congestion window) is what's limiting delivery. If
        // the cwnd/pacer gate left headroom, mark the connection
        // app-limited: rate samples stay tainted until C.delivered
        // passes the marker, so an idle app can never deflate the
        // bandwidth estimate. A cwnd-full or pacer-throttled poll must
        // NOT mark (that is congestion-, not app-limited). Known
        // imprecision, accepted: a stream with buffered data but no
        // flow credit also produces no chunk and marks app-limited —
        // that under-claims bandwidth, never over-claims it.
        if ((lvl == .application or lvl == .early_data) and !congestion_blocked) {
            app_path.path.delivery.markAppLimited(sent_tracker.bytes_in_flight);
        }
        return null;
    }

    // 4) Allocate PN at this level, seal at the right header type.
    const pn = pn_space.nextPn() orelse return Error.PnSpaceExhausted;
    const largest_acked = pn_space.largest_acked_sent;
    const quic_bit = conn_paths.nextQuicBit(
        conn,
    );
    const n = switch (lvl) {
        .initial => blk: {
            // RFC 9000 §14.1: a client MUST expand every UDP datagram
            // carrying an Initial packet to ≥1200 bytes, ACK-only
            // Initials included; a server, every datagram with an
            // ack-eliciting Initial packet. Servers drop shorter
            // Initial-leading datagrams (see `Server.feed`), so an
            // unpadded ACK-only Initial stalls the peer's first flight
            // until its probe timeouts.
            //
            // The padding is for the DATAGRAM. Inside `pollDatagram`
            // the packet is sealed without padding here, and
            // `padInitialDatagram` seals it again when the rest of the
            // datagram is known. A direct `pollLevel(.initial, ...)`
            // has no datagram around it: the packet pads itself.
            const expand = initialNeedsExpansion(conn, ack_eliciting);
            // A buffer too short for the padded datagram: an error, as
            // it always was for a client. (A server does not come here
            // with an ack-eliciting packet: `initial_ack_eliciting_blocked`.)
            if (expand and packet_room < min_initial_datagram_len) return Error.OutputTooSmall;
            const pad_to: usize = if (expand and conn.poll_initial == null) min_initial_datagram_len else 0;
            break :blk try sealInitialPacket(conn, dst, pn, largest_acked, pl_buf[0..pl_pos], keys, quic_bit, pad_to);
        },
        .handshake => try long_packet_mod.sealHandshake(dst, .{
            .version = conn.version,
            .dcid = packet_dcid.slice(),
            .scid = packet_scid.slice(),
            .pn = pn,
            .largest_acked = largest_acked,
            .payload = pl_buf[0..pl_pos],
            .keys = keys,
            .quic_bit = quic_bit,
        }),
        .application => try short_packet_mod.seal1Rtt(dst, .{
            .dcid = packet_dcid.slice(),
            .pn = pn,
            .largest_acked = largest_acked,
            .payload = pl_buf[0..pl_pos],
            .keys = keys,
            .staging = &Connection.scratch().stage_buf,
            .key_phase = conn_keys.applicationWriteKeyPhase(
                conn,
            ),
            .multipath_path_id = if (conn.multipathNegotiated()) app_path.id else null,
            .quic_bit = quic_bit,
            // RFC 8899 DPLPMTUD: when a probe is in flight from
            // this poll, pad to the probed size so the resulting
            // datagram is exactly that big.
            //
            // RFC 9000 §8.2.1 ¶3: a datagram containing a
            // PATH_CHALLENGE MUST be padded to at least 1200 bytes,
            // unless anti-amplification on the path forbids it. The
            // anti-amp clamp on `max_payload` upstream already
            // gates that; when we emitted PATH_CHALLENGE first
            // (peer-initiated migration) honor the §8.2.1 floor.
            // The DPLPMTUD probe path takes precedence when both
            // are set — that path is gated on a validated path,
            // so the two conditions don't actually overlap, but we
            // pick the larger of the two for safety.
            .pad_to = if (probe_target_size) |sz|
                @as(usize, sz)
            else if (emit_path_challenge_first)
                @min(default_mtu, dst.len)
            else
                0,
        }),
        .early_data => try long_packet_mod.sealZeroRtt(dst, .{
            .version = conn.version,
            .dcid = packet_dcid.slice(),
            .scid = packet_scid.slice(),
            .pn = pn,
            .largest_acked = largest_acked,
            .payload = pl_buf[0..pl_pos],
            .keys = keys,
            .quic_bit = quic_bit,
        }),
    };

    // 5) Commit.
    sent_packet.pn = pn;
    sent_packet.bytes = n;
    sent_packet.ack_eliciting = ack_eliciting;
    sent_packet.in_flight = ack_eliciting;
    if (ack_eliciting) conn.poll_sent_ack_eliciting = true;
    sent_packet.is_early_data = lvl == .early_data;
    sent_packet.datagram = sent_datagram;
    if (lvl == .application) conn_keys.recordApplicationPacketProtected(conn, &sent_packet);
    for (sent_chunks[0..sent_chunk_count]) |sc| {
        try sent_packet.addStreamRef(conn.allocator, .{
            .stream_id = sc.stream.id,
            .stream_key = sc.stream_key,
        });
    }
    // Delivery-rate stamps (draft-cheng-02 §3.2): application/0-RTT
    // in-flight packets only — Initial/Handshake flights are never
    // sampled (the congestion controller is application-level only),
    // and non-in-flight packets (ACK-only, CONNECTION_CLOSE) must not
    // touch the estimator's idle-restart clocks. Stamped before
    // `record` so the tracker's copy carries the fields, with the
    // tracker's pre-record bytes-in-flight as the draft's C.inflight.
    if ((lvl == .application or lvl == .early_data) and sent_packet.in_flight) {
        app_path.path.delivery.onPacketSent(&sent_packet, sent_tracker.bytes_in_flight);
        app_path.path.cc.onPacketSent(
            now_us,
            sent_tracker.bytes_in_flight,
            sent_packet.bytes,
            app_path.path.delivery.isAppLimited(),
        );
    }
    if (sent_packet.ack_eliciting) {
        if (conn.ecn_enabled) pn_space.ect_marked_sent +|= 1;
        try sent_tracker.record(sent_packet);
        sent_packet_recorded = true;
    } else {
        sent_packet.deinit(conn.allocator);
        sent_packet_recorded = true;
    }
    for (sent_chunks[0..sent_chunk_count]) |sc| {
        try sc.stream.send.recordSent(sc.stream_key, sc.chunk);
        conn.recordStreamFlowSent(sc.stream, sc.chunk);
        conn_streams.noteSendable(conn, sc.stream);
    }
    if (sent_crypto_chunk) |sc| {
        try conn.sent_crypto[sc.level_idx].append(conn.allocator, .{
            .pn = pn,
            .offset = sc.offset,
            .data = sc.data,
        });
        crypto_copy = null;
    }
    if (retx_crypto_index) |idx| {
        const old = conn.crypto_retx[out_idx].orderedRemove(idx);
        conn.allocator.free(old.data);
    }
    if (retx_crypto_rest) |rest| {
        const first = &conn.crypto_retx[out_idx].items[0];
        const sent_len = first.data.len - rest.len;
        conn.allocator.free(first.data);
        first.* = .{ .offset = first.offset + sent_len, .data = rest };
        retx_crypto_rest = null;
    }
    if ((lvl == .application or lvl == .early_data) and
        ack_eliciting and app_path.pto_probe_count > 0)
    {
        app_path.pto_probe_count -= 1;
    }

    // RFC 8899 DPLPMTUD: stamp the in-flight probe metadata. The
    // recorded `sent_packet` already carries `bytes = n`, but the
    // probe-size field is independent of the post-seal byte count
    // (n equals the probe size when `pad_to` is set, but on the
    // off-chance the path-specific overhead miscounted by a byte
    // we want the definitive value the probe scheduler asked for).
    if (lvl == .application) if (probe_target_size) |sz| {
        if (pmtud_probe_emitted) {
            app_path.pmtudOnProbeSent(pn, sz);
        }
    };

    // qlog hooks for the outgoing packet.
    conn.qlog_packets_sent +|= 1;
    conn.qlog_bytes_sent +|= n;
    if (lvl == .initial and conn.poll_initial != null) {
        // `pollDatagram` may make this packet longer (padding). It
        // reports the packet when its size is final.
        noteInitialInDatagram(conn.poll_initial.?, n, pn, largest_acked, quic_bit, ack_eliciting, ack_eliciting, pl_buf[0..pl_pos]);
    } else {
        conn_qlog.emitPacketSentWithPayload(conn, lvl, pn, @intCast(n), pl_buf[0..pl_pos]);
    }

    return n;
}

/// A CONNECTION_CLOSE has left (in one packet, or in the packets of
/// one datagram): the connection is in the closing state now.
fn noteCloseEmitted(conn: *Connection, now_us: u64) void {
    const closing_deadline = now_us + conn.drainingDurationUs();
    conn.lifecycle.noteCloseEmit(now_us, closing_deadline);
    conn.lifecycle.updateDrainingDeadline(closing_deadline);
}

/// Leave with `pollDatagram` what it needs to seal this Initial packet
/// a second time (see `InitialInDatagram`).
fn noteInitialInDatagram(
    initial: *InitialInDatagram,
    len: usize,
    pn: u64,
    largest_acked: ?u64,
    quic_bit: u1,
    ack_eliciting: bool,
    tracked: bool,
    payload: []const u8,
) void {
    initial.sealed = true;
    initial.len = len;
    initial.pn = pn;
    initial.largest_acked = largest_acked;
    initial.quic_bit = quic_bit;
    initial.ack_eliciting = ack_eliciting;
    initial.tracked = tracked;
    initial.payload_len = payload.len;
    @memcpy(initial.payload[0..payload.len], payload);
}

fn encodeFrameIfFits(
    pl_buf: *[max_recv_plaintext]u8,
    pl_pos: *usize,
    max_payload: usize,
    frame: frame_types.Frame,
) Error!bool {
    const needed = frame_mod.encodedLen(frame);
    if (max_payload < pl_pos.* + needed) return false;
    const wrote = try frame_mod.encode(pl_buf[pl_pos.*..max_payload], frame);
    pl_pos.* += wrote;
    return true;
}

pub fn emitOnePendingMultipathFrame(
    conn: *Connection,
    sent_packet: *SentPacketTracker.SentPacket,
    pl_buf: *[max_recv_plaintext]u8,
    pl_pos: *usize,
    max_payload: usize,
) Error!bool {
    if (conn.pending_frames.path_abandons.items.len > 0) {
        const item = conn.pending_frames.path_abandons.items[0];
        if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_abandon = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .path_abandon = item });
            _ = conn.pending_frames.path_abandons.orderedRemove(0);
            return true;
        }
    }
    if (conn.pending_frames.path_statuses.items.len > 0) {
        const item = conn.pending_frames.path_statuses.items[0];
        const status: frame_types.PathStatus = .{
            .path_id = item.path_id,
            .sequence_number = item.sequence_number,
        };
        const frame: frame_types.Frame = if (item.available)
            .{ .path_status_available = status }
        else
            .{ .path_status_backup = status };
        if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, frame)) {
            try sent_packet.addRetransmitFrame(
                conn.allocator,
                if (item.available)
                    .{ .path_status_available = status }
                else
                    .{ .path_status_backup = status },
            );
            _ = conn.pending_frames.path_statuses.orderedRemove(0);
            return true;
        }
    }
    if (conn.pending_frames.path_new_connection_ids.items.len > 0) {
        const item = conn.pending_frames.path_new_connection_ids.items[0];
        if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_new_connection_id = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .path_new_connection_id = item });
            _ = conn.pending_frames.path_new_connection_ids.orderedRemove(0);
            return true;
        }
    }
    if (conn.pending_frames.path_retire_connection_ids.items.len > 0) {
        const item = conn.pending_frames.path_retire_connection_ids.items[0];
        if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_retire_connection_id = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .path_retire_connection_id = item });
            _ = conn.pending_frames.path_retire_connection_ids.orderedRemove(0);
            return true;
        }
    }
    if (conn.pending_frames.max_path_id) |maximum_path_id| {
        const item: frame_types.MaxPathId = .{ .maximum_path_id = maximum_path_id };
        if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .max_path_id = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .max_path_id = item });
            conn.pending_frames.max_path_id = null;
            return true;
        }
    }
    if (conn.pending_frames.paths_blocked) |maximum_path_id| {
        const item: frame_types.PathsBlocked = .{ .maximum_path_id = maximum_path_id };
        if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .paths_blocked = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .paths_blocked = item });
            conn.pending_frames.paths_blocked = null;
            return true;
        }
    }
    if (conn.pending_frames.path_cids_blocked) |item| {
        if (try encodeFrameIfFits(pl_buf, pl_pos, max_payload, .{ .path_cids_blocked = item })) {
            try sent_packet.addRetransmitFrame(conn.allocator, .{ .path_cids_blocked = item });
            conn.pending_frames.path_cids_blocked = null;
            return true;
        }
    }
    return false;
}

pub fn emitPendingMultipathFrames(
    conn: *Connection,
    sent_packet: *SentPacketTracker.SentPacket,
    pl_buf: *[max_recv_plaintext]u8,
    pl_pos: *usize,
    max_payload: usize,
) Error!bool {
    var emitted = false;
    const control_budget = SentPacketTracker.max_retransmit_frames - 1;
    while (sent_packet.retransmit_frames.items.len < control_budget) {
        const before = pl_pos.*;
        if (!try emitOnePendingMultipathFrame(conn, sent_packet, pl_buf, pl_pos, max_payload)) break;
        emitted = true;
        if (pl_pos.* == before) break;
    }
    return emitted;
}
