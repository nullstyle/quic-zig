// JSON-SEQ qlog writer — maps the `conn_qlog.QlogEvent` surface onto
// draft-ietf-quic-qlog event records. Rendering is separated from file
// I/O so the mapping is testable without a filesystem: `renderHeader` /
// `renderEvent` build one record (RS byte + JSON + '\n') into a caller
// list; `Writer` owns the amortized buffer and the file plumbing.

const std = @import("std");
const conn_qlog = @import("../conn/conn_qlog.zig");
const root = @import("root.zig");

const QlogEvent = conn_qlog.QlogEvent;

/// RFC 7464 record separator every JSON-SEQ record starts with.
pub const record_separator: u8 = 0x1e;

pub const VantagePoint = enum { client, server };

fn writeJsonEscaped(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(allocator, "\\\""),
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '\n' => try out.appendSlice(allocator, "\\n"),
        '\r' => try out.appendSlice(allocator, "\\r"),
        '\t' => try out.appendSlice(allocator, "\\t"),
        0x00...0x08, 0x0b...0x0c, 0x0e...0x1f => try out.print(allocator, "\\u{x:0>4}", .{c}),
        else => try out.append(allocator, c),
    };
}

/// Relative event time in milliseconds with microsecond precision.
fn relTimeMs(at_us: u64, reference_time_us: u64) f64 {
    const rel: f64 = if (at_us >= reference_time_us)
        @floatFromInt(at_us - reference_time_us)
    else
        -@as(f64, @floatFromInt(reference_time_us - at_us));
    return rel / 1000.0;
}

/// qlog `<category>:<type>` name for an event. Standard names where a
/// standard event exists; `quic-zig:` namespace otherwise.
pub fn qlogName(name: conn_qlog.QlogEventName) []const u8 {
    return switch (name) {
        .connection_started => "quic:connection_started",
        .connection_state_updated => "quic:connection_state_updated",
        .parameters_set => "quic:parameters_set",
        .packet_sent => "quic:packet_sent",
        .packet_received => "quic:packet_received",
        .packet_dropped => "quic:packet_dropped",
        .stream_state_updated => "quic:stream_state_updated",
        .packet_lost => "recovery:packet_lost",
        .metrics_updated => "recovery:metrics_updated",
        .congestion_state_updated => "recovery:congestion_state_updated",
        .application_read_key_installed,
        .application_read_key_updated,
        .application_write_key_installed,
        .application_write_key_updated,
        .application_write_update_acked,
        .key_updated,
        => "security:key_updated",
        .application_read_key_discarded => "security:key_discarded",
        // No standard equivalents — custom namespace, permitted by the
        // schema and ignored by tools that don't know it.
        .application_read_key_discard_scheduled => "quic-zig:key_discard_scheduled",
        .aead_confidentiality_limit_reached => "quic-zig:aead_confidentiality_limit_reached",
        .aead_integrity_limit_reached => "quic-zig:aead_integrity_limit_reached",
        .loss_detected => "quic-zig:loss_detected",
        .migration_path_validated => "quic-zig:migration_path_validated",
        .migration_path_failed => "quic-zig:migration_path_failed",
    };
}

/// qlog `packet_type` strings (draft-ietf-quic-qlog-quic-events data
/// definitions).
fn packetTypeName(kind: conn_qlog.QlogPacketKind) []const u8 {
    return switch (kind) {
        .initial => "initial",
        .handshake => "handshake",
        .zero_rtt => "0RTT",
        .one_rtt => "1RTT",
        .retry => "retry",
        .version_negotiation => "version_negotiation",
    };
}

/// The 1-RTT key_type strings; the generic `key_updated` derives one
/// from the encryption level instead.
fn keyTypeName(event: QlogEvent) []const u8 {
    return switch (event.name) {
        .application_read_key_installed,
        .application_read_key_updated,
        .application_read_key_discard_scheduled,
        .application_read_key_discarded,
        => "server_1rtt_secret",
        .application_write_key_installed,
        .application_write_key_updated,
        .application_write_update_acked,
        => "client_1rtt_secret",
        else => switch (event.level) {
            .initial => "initial_secret",
            .handshake => "handshake_secret",
            .early_data => "client_0rtt_secret",
            .application => "1rtt_secret",
        },
    };
}

const FieldWriter = struct {
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    first: bool = true,

    fn sep(self: *FieldWriter) !void {
        if (!self.first) try self.out.appendSlice(self.allocator, ",");
        self.first = false;
    }

    fn num(self: *FieldWriter, name: []const u8, value: anytype) !void {
        try self.sep();
        try self.out.print(self.allocator, "\"{s}\":{d}", .{ name, value });
    }

    fn numMs(self: *FieldWriter, name: []const u8, us: u64) !void {
        try self.sep();
        try self.out.print(self.allocator, "\"{s}\":{d:.3}", .{ name, @as(f64, @floatFromInt(us)) / 1000.0 });
    }

    fn str(self: *FieldWriter, name: []const u8, value: []const u8) !void {
        try self.sep();
        try self.out.print(self.allocator, "\"{s}\":\"", .{name});
        try writeJsonEscaped(self.out, self.allocator, value);
        try self.out.appendSlice(self.allocator, "\"");
    }

    fn boolean(self: *FieldWriter, name: []const u8, value: bool) !void {
        try self.sep();
        try self.out.print(self.allocator, "\"{s}\":{}", .{ name, value });
    }

    fn hex(self: *FieldWriter, name: []const u8, bytes: []const u8) !void {
        try self.sep();
        try self.out.print(self.allocator, "\"{s}\":\"", .{name});
        for (bytes) |b| try self.out.print(self.allocator, "{x:0>2}", .{b});
        try self.out.appendSlice(self.allocator, "\"");
    }

    fn raw(self: *FieldWriter, name: []const u8, json: []const u8) !void {
        try self.sep();
        try self.out.print(self.allocator, "\"{s}\":{s}", .{ name, json });
    }
};

/// Renders the trace-header record (RS + JSON + '\n') into `out`.
pub fn renderHeader(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    vantage_point: VantagePoint,
    title: []const u8,
    odcid: ?[]const u8,
    reference_time_us: u64,
) !void {
    try out.append(allocator, record_separator);
    try out.appendSlice(allocator, "{\"qlog_version\":\"");
    try out.appendSlice(allocator, root.qlog_version);
    try out.appendSlice(allocator, "\",\"qlog_format\":\"JSON-SEQ\",\"title\":\"");
    try writeJsonEscaped(out, allocator, title);
    try out.appendSlice(allocator, "\",\"trace\":{\"vantage_point\":{\"type\":\"");
    try out.appendSlice(allocator, @tagName(vantage_point));
    try out.appendSlice(allocator, "\"},\"common_fields\":{");
    if (odcid) |cid| {
        try out.appendSlice(allocator, "\"ODCID\":\"");
        for (cid) |b| try out.print(allocator, "{x:0>2}", .{b});
        try out.appendSlice(allocator, "\",");
    }
    try out.print(
        allocator,
        "\"reference_time\":{d:.3},\"time_format\":\"relative\"}}}}}}\n",
        .{@as(f64, @floatFromInt(reference_time_us)) / 1000.0},
    );
}

/// Renders one event record (RS + JSON + '\n') into `out`.
pub fn renderEvent(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    event: QlogEvent,
    reference_time_us: u64,
) !void {
    try out.append(allocator, record_separator);
    try out.print(allocator, "{{\"time\":{d:.3},\"name\":\"{s}\",\"data\":{{", .{
        relTimeMs(event.at_us, reference_time_us),
        qlogName(event.name),
    });
    var fields: FieldWriter = .{ .out = out, .allocator = allocator };

    switch (event.name) {
        .connection_started => {
            if (event.role) |role| try fields.str("role", @tagName(role));
            if (event.local_scid) |cid| try fields.hex("src_cid", cid.bytes[0..cid.len]);
            if (event.peer_scid) |cid| try fields.hex("dst_cid", cid.bytes[0..cid.len]);
        },
        .connection_state_updated => {
            if (event.old_state) |s| try fields.str("old", @tagName(s));
            if (event.new_state) |s| try fields.str("new", @tagName(s));
        },
        .parameters_set => {
            try fields.str("owner", "remote");
            if (event.peer_idle_timeout_ms) |v| try fields.num("max_idle_timeout", v);
            if (event.peer_max_udp_payload_size) |v| try fields.num("max_udp_payload_size", v);
            if (event.peer_initial_max_data) |v| try fields.num("initial_max_data", v);
            if (event.peer_initial_max_streams_bidi) |v| try fields.num("initial_max_streams_bidi", v);
            if (event.peer_initial_max_streams_uni) |v| try fields.num("initial_max_streams_uni", v);
            if (event.peer_active_connection_id_limit) |v| try fields.num("active_connection_id_limit", v);
            if (event.peer_max_ack_delay_ms) |v| try fields.num("max_ack_delay", v);
            if (event.peer_max_datagram_frame_size) |v| try fields.num("max_datagram_frame_size", v);
        },
        .packet_sent, .packet_received, .packet_lost => {
            // header sub-object: {"packet_type":...,"packet_number":...}
            try fields.sep();
            try out.appendSlice(allocator, "\"header\":{");
            var header_fields: FieldWriter = .{ .out = out, .allocator = allocator };
            if (event.packet_kind) |kind| try header_fields.str("packet_type", packetTypeName(kind));
            if (event.packet_number) |pn| try header_fields.num("packet_number", pn);
            try out.appendSlice(allocator, "}");
            if (event.packet_size) |size| {
                try fields.sep();
                try out.print(allocator, "\"raw\":{{\"length\":{d}}}", .{size});
            }
            if (event.name == .packet_sent or event.name == .packet_received) {
                if (event.frames_summary != 0) try fields.num("frame_count", event.frames_summary);
            }
            if (event.name == .packet_lost) {
                if (event.loss_reason) |reason| try fields.str("trigger", @tagName(reason));
            }
        },
        .packet_dropped => {
            if (event.packet_kind) |kind| {
                try fields.sep();
                try out.appendSlice(allocator, "\"header\":{");
                var header_fields: FieldWriter = .{ .out = out, .allocator = allocator };
                try header_fields.str("packet_type", packetTypeName(kind));
                try out.appendSlice(allocator, "}");
            }
            if (event.packet_size) |size| {
                try fields.sep();
                try out.print(allocator, "\"raw\":{{\"length\":{d}}}", .{size});
            }
            if (event.drop_reason) |reason| try fields.str("trigger", @tagName(reason));
        },
        .metrics_updated => {
            if (event.cwnd) |v| try fields.num("congestion_window", v);
            if (event.bytes_in_flight) |v| try fields.num("bytes_in_flight", v);
            if (event.ssthresh) |v| try fields.num("ssthresh", v);
            if (event.smoothed_rtt_us) |v| try fields.numMs("smoothed_rtt", v);
            if (event.rtt_var_us) |v| try fields.numMs("rtt_variance", v);
            if (event.min_rtt_us) |v| try fields.numMs("min_rtt", v);
            if (event.latest_rtt_us) |v| try fields.numMs("latest_rtt", v);
            if (event.pacing_rate) |v| try fields.num("pacing_rate", v);
        },
        .congestion_state_updated => {
            if (event.congestion_state) |s| try fields.str("new", @tagName(s));
        },
        .stream_state_updated => {
            if (event.stream_id) |id| try fields.num("stream_id", id);
            if (event.stream_state) |s| try fields.str("new", @tagName(s));
        },
        .loss_detected => {
            if (event.lost_count) |v| try fields.num("packets_lost", v);
            if (event.bytes_lost) |v| try fields.num("bytes_lost", v);
            if (event.loss_reason) |reason| try fields.str("trigger", @tagName(reason));
            if (event.pn_space) |space| try fields.str("pn_space", @tagName(space));
        },
        .migration_path_validated, .migration_path_failed => {
            if (event.path_id) |id| try fields.num("path_id", id);
            if (event.migration_fail_reason) |reason| try fields.str("trigger", @tagName(reason));
        },
        // All key-flavored events share the key_updated/key_discarded
        // data shape.
        .application_read_key_installed,
        .application_read_key_updated,
        .application_read_key_discard_scheduled,
        .application_read_key_discarded,
        .application_write_key_installed,
        .application_write_key_updated,
        .application_write_update_acked,
        .key_updated,
        .aead_confidentiality_limit_reached,
        .aead_integrity_limit_reached,
        => {
            try fields.str("key_type", keyTypeName(event));
            if (event.key_epoch) |epoch| try fields.num("key_phase", epoch) else if (event.key_phase) |phase| try fields.boolean("key_phase_bit", phase);
            if (event.discard_deadline_us) |deadline| try fields.numMs("discard_at", deadline);
        },
    }

    if (event.details.len != 0) try fields.str("details", event.details);
    try out.appendSlice(allocator, "}}\n");
}

/// Streaming qlog writer over a `std.Io.File`. One instance per
/// connection/trace; not thread-safe (the qlog callback contract is
/// already single-threaded per connection).
pub const Writer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    reference_time_us: u64,
    buf: std.ArrayList(u8) = .empty,
    /// Latched on the first I/O or rendering failure; all later events
    /// are dropped silently (the callback cannot propagate errors).
    failed: bool = false,

    pub const Options = struct {
        vantage_point: VantagePoint,
        title: []const u8 = "quic-zig",
        /// Original DCID bytes for the trace header, if known.
        odcid: ?[]const u8 = null,
        reference_time_us: u64 = 0,
    };

    /// Writes the trace-header record immediately. The caller owns
    /// `file` (and closes it after `deinit`).
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        file: std.Io.File,
        opts: Options,
    ) !Writer {
        var writer: Writer = .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .reference_time_us = opts.reference_time_us,
        };
        errdefer writer.buf.deinit(allocator);
        try renderHeader(&writer.buf, allocator, opts.vantage_point, opts.title, opts.odcid, opts.reference_time_us);
        try file.writeStreamingAll(io, writer.buf.items);
        return writer;
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(self.allocator);
        self.* = undefined;
    }

    /// `conn_qlog.QlogCallback`-shaped adapter:
    /// `conn.setQlogCallback(Writer.callback, &writer)`.
    pub fn callback(user_data: ?*anyopaque, event: QlogEvent) void {
        const self: *Writer = @ptrCast(@alignCast(user_data.?));
        self.writeEvent(event);
    }

    pub fn writeEvent(self: *Writer, event: QlogEvent) void {
        if (self.failed) return;
        self.buf.clearRetainingCapacity();
        renderEvent(&self.buf, self.allocator, event, self.reference_time_us) catch {
            self.failed = true;
            return;
        };
        self.file.writeStreamingAll(self.io, self.buf.items) catch {
            self.failed = true;
        };
    }
};

// -- tests -------------------------------------------------------------------

const testing = std.testing;

fn renderToString(allocator: std.mem.Allocator, event: QlogEvent, reference_us: u64) !std.ArrayList(u8) {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try renderEvent(&out, allocator, event, reference_us);
    return out;
}

test "header record: golden string and JSON validity" {
    const allocator = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try renderHeader(&out, allocator, .server, "t", &[_]u8{ 0xab, 0xcd }, 2_000);

    try testing.expectEqual(record_separator, out.items[0]);
    try testing.expectEqualStrings(
        "{\"qlog_version\":\"0.4\",\"qlog_format\":\"JSON-SEQ\",\"title\":\"t\"," ++
            "\"trace\":{\"vantage_point\":{\"type\":\"server\"},\"common_fields\":{" ++
            "\"ODCID\":\"abcd\",\"reference_time\":2.000,\"time_format\":\"relative\"}}}\n",
        out.items[1..out.items.len],
    );
}

test "metrics_updated maps to recovery:metrics_updated with ms floats" {
    const allocator = testing.allocator;
    var out = try renderToString(allocator, .{
        .name = .metrics_updated,
        .at_us = 3_500,
        .cwnd = 14_720,
        .bytes_in_flight = 1_200,
        .smoothed_rtt_us = 25_250,
        .latest_rtt_us = 24_000,
    }, 1_000);
    defer out.deinit(allocator);

    try testing.expectEqualStrings(
        "{\"time\":2.500,\"name\":\"recovery:metrics_updated\",\"data\":{" ++
            "\"congestion_window\":14720,\"bytes_in_flight\":1200," ++
            "\"smoothed_rtt\":25.250,\"latest_rtt\":24.000}}\n",
        out.items[1..],
    );
}

test "packet_sent carries header/raw sub-objects" {
    const allocator = testing.allocator;
    var out = try renderToString(allocator, .{
        .name = .packet_sent,
        .at_us = 10,
        .packet_kind = .one_rtt,
        .packet_number = 7,
        .packet_size = 1200,
        .frames_summary = 3,
    }, 0);
    defer out.deinit(allocator);

    try testing.expectEqualStrings(
        "{\"time\":0.010,\"name\":\"quic:packet_sent\",\"data\":{" ++
            "\"header\":{\"packet_type\":\"1RTT\",\"packet_number\":7}," ++
            "\"raw\":{\"length\":1200},\"frame_count\":3}}\n",
        out.items[1..],
    );
}

test "every event name renders as parseable JSON" {
    const allocator = testing.allocator;
    for (std.enums.values(conn_qlog.QlogEventName)) |name| {
        // Populate broadly: irrelevant fields for a given variant are
        // ignored by the renderer's switch.
        var out = try renderToString(allocator, .{
            .name = name,
            .at_us = 1_234,
            .packet_kind = .initial,
            .packet_number = 1,
            .packet_size = 100,
            .drop_reason = .decryption_failure,
            .loss_reason = .time_threshold,
            .lost_count = 2,
            .bytes_lost = 2_400,
            .pn_space = .application,
            .path_id = 1,
            .migration_fail_reason = .timeout,
            .stream_id = 4,
            .stream_state = .open,
            .cwnd = 10_000,
            .congestion_state = .recovery,
            .key_epoch = 1,
            .discard_deadline_us = 9_000,
            .peer_initial_max_data = 65_536,
            .details = "x\"y",
        }, 0);
        defer out.deinit(allocator);

        try testing.expectEqual(record_separator, out.items[0]);
        try testing.expectEqual(@as(u8, '\n'), out.items[out.items.len - 1]);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, out.items[1..], .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        try testing.expect(obj.get("time") != null);
        try testing.expectEqualStrings(qlogName(name), obj.get("name").?.string);
        try testing.expect(obj.get("data").? == .object);
    }
}

test "negative relative time renders when events precede the reference" {
    const allocator = testing.allocator;
    var out = try renderToString(allocator, .{ .name = .key_updated, .at_us = 500 }, 1_500);
    defer out.deinit(allocator);
    try testing.expect(std.mem.startsWith(u8, out.items[1..], "{\"time\":-1.000,"));
}
