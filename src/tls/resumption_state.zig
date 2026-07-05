//! Versioned persisted client-side 0-RTT resumption state.
//!
//! BoringSSL serializes only the TLS `SSL_SESSION`. QUIC 0-RTT also
//! needs the peer's remembered transport parameters so the client can
//! bound early-data sends before the resumed handshake publishes fresh
//! parameters. This module freezes the quic_zig-owned envelope that
//! embedders persist between connections:
//!
//!   QZRS || version(1) || flags(1) || ticket_len(u32) ||
//!   transport_params_len(u32) || ticket || transport_params
//!
//! Integers are big-endian. Version 1 has no flags; non-zero flags
//! and unknown versions are rejected.

const std = @import("std");

const transport_params = @import("transport_params.zig");

pub const TransportParams = transport_params.Params;

pub const Error = error{
    BufferTooSmall,
    InvalidFormat,
    UnsupportedVersion,
    InvalidFlags,
    ValueTooLarge,
    TrailingBytes,
} || transport_params.Error;

pub const Decoded = struct {
    /// Raw BoringSSL `Session.toBytes` payload. Borrows from the
    /// envelope passed to `decode`.
    session_ticket: []const u8,
    /// Peer transport parameters remembered from the connection that
    /// issued `session_ticket`.
    transport_params: TransportParams,
};

pub const magic = "QZRS".*;
pub const version: u8 = 1;
pub const flags: u8 = 0;
pub const header_len: usize = 4 + 1 + 1 + 4 + 4;

pub fn encodedLen(session_ticket: []const u8, params: TransportParams) Error!usize {
    if (session_ticket.len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    const params_len = try params.encodedLen();
    if (params_len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    return header_len + session_ticket.len + params_len;
}

pub fn encode(dst: []u8, session_ticket: []const u8, params: TransportParams) Error!usize {
    const params_len = try params.encodedLen();
    if (session_ticket.len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    if (params_len > std.math.maxInt(u32)) return Error.ValueTooLarge;
    const needed = header_len + session_ticket.len + params_len;
    if (dst.len < needed) return Error.BufferTooSmall;

    @memcpy(dst[0..4], &magic);
    dst[4] = version;
    dst[5] = flags;
    std.mem.writeInt(u32, dst[6..10], @intCast(session_ticket.len), .big);
    std.mem.writeInt(u32, dst[10..14], @intCast(params_len), .big);

    const ticket_start = header_len;
    const ticket_end = ticket_start + session_ticket.len;
    @memcpy(dst[ticket_start..ticket_end], session_ticket);
    const written_params = try params.encode(dst[ticket_end..needed]);
    std.debug.assert(written_params == params_len);
    return needed;
}

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    session_ticket: []const u8,
    params: TransportParams,
) (std.mem.Allocator.Error || Error)![]u8 {
    const len = try encodedLen(session_ticket, params);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    const written = try encode(out, session_ticket, params);
    std.debug.assert(written == len);
    return out;
}

pub fn decode(src: []const u8) Error!Decoded {
    if (src.len < header_len) return Error.InvalidFormat;
    if (!std.mem.eql(u8, src[0..4], &magic)) return Error.InvalidFormat;
    if (src[4] != version) return Error.UnsupportedVersion;
    if (src[5] != flags) return Error.InvalidFlags;

    const ticket_len_u32 = std.mem.readInt(u32, src[6..10], .big);
    const params_len_u32 = std.mem.readInt(u32, src[10..14], .big);
    const ticket_len: usize = ticket_len_u32;
    const params_len: usize = params_len_u32;
    const total = std.math.add(
        usize,
        std.math.add(usize, header_len, ticket_len) catch return Error.InvalidFormat,
        params_len,
    ) catch return Error.InvalidFormat;
    if (src.len < total) return Error.InvalidFormat;
    if (src.len > total) return Error.TrailingBytes;

    const ticket_start = header_len;
    const ticket_end = ticket_start + ticket_len;
    const params_end = ticket_end + params_len;
    const params = try TransportParams.decode(src[ticket_end..params_end]);
    return .{
        .session_ticket = src[ticket_start..ticket_end],
        .transport_params = params,
    };
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn sampleParams() TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .max_udp_payload_size = 1400,
        .initial_max_data = 65536,
        .initial_max_stream_data_bidi_local = 4096,
        .initial_max_streams_bidi = 8,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = transport_params.ConnectionId.fromSlice(&.{ 1, 2, 3, 4 }),
        .max_datagram_frame_size = 1200,
    };
}

test "resumption state envelope round-trips ticket and transport params" {
    const ticket = "boringssl-session";
    const params = sampleParams();
    const len = try encodedLen(ticket, params);
    var buf: [256]u8 = undefined;
    const written = try encode(&buf, ticket, params);
    try testing.expectEqual(len, written);

    const got = try decode(buf[0..written]);
    try testing.expectEqualSlices(u8, ticket, got.session_ticket);
    try testing.expectEqual(params.initial_max_data, got.transport_params.initial_max_data);
    try testing.expectEqual(params.initial_max_streams_bidi, got.transport_params.initial_max_streams_bidi);
    try testing.expectEqual(params.initial_source_connection_id.?.len, got.transport_params.initial_source_connection_id.?.len);
    try testing.expectEqualSlices(
        u8,
        params.initial_source_connection_id.?.slice(),
        got.transport_params.initial_source_connection_id.?.slice(),
    );
}

test "resumption state encodeAlloc returns an exact envelope" {
    const ticket = "ticket";
    const params = sampleParams();
    const bytes = try encodeAlloc(testing.allocator, ticket, params);
    defer testing.allocator.free(bytes);

    try testing.expectEqual(try encodedLen(ticket, params), bytes.len);
    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, ticket, got.session_ticket);
}

test "resumption state rejects unknown version and nonzero flags" {
    const ticket = "ticket";
    const params = sampleParams();
    var buf: [256]u8 = undefined;
    const written = try encode(&buf, ticket, params);

    buf[4] = version + 1;
    try testing.expectError(Error.UnsupportedVersion, decode(buf[0..written]));
    buf[4] = version;
    buf[5] = 0x80;
    try testing.expectError(Error.InvalidFlags, decode(buf[0..written]));
}

test "resumption state rejects raw legacy session bytes and malformed lengths" {
    try testing.expectError(Error.InvalidFormat, decode("raw-boringssl-session"));

    const ticket = "ticket";
    const params = sampleParams();
    var buf: [256]u8 = undefined;
    const written = try encode(&buf, ticket, params);
    std.mem.writeInt(u32, buf[6..10], @as(u32, 200), .big);
    try testing.expectError(Error.InvalidFormat, decode(buf[0..written]));
}

test "resumption state rejects trailing bytes" {
    const ticket = "ticket";
    const params = sampleParams();
    var buf: [256]u8 = undefined;
    const written = try encode(&buf, ticket, params);
    buf[written] = 0xff;
    try testing.expectError(Error.TrailingBytes, decode(buf[0 .. written + 1]));
}
