//! qlog serialization: turns the typed `QlogEvent` callback stream
//! (`Connection.setQlogCallback`) into a standard qlog file that qvis
//! and other qlog tooling load directly.
//!
//! Format: JSON Text Sequences (`JSON-SEQ`, RFC 7464 record separators),
//! the streaming-friendly qlog serialization — one `0x1E`-prefixed JSON
//! record per line, `.sqlog` extension. Pinned to **qlog_version
//! "0.4"** (draft-ietf-quic-qlog-main-schema-04 /
//! draft-ietf-quic-qlog-quic-events-04); events that have no standard
//! qlog equivalent (aggregate loss detection, path-migration outcomes,
//! AEAD-limit warnings) are emitted under the `quic-zig:` custom
//! namespace, which the schema explicitly permits and tools ignore
//! gracefully.
//!
//! ```zig
//! var writer = try quic.qlog.Writer.init(allocator, io, file, .{
//!     .vantage_point = .server,
//!     .title = "my-server",
//!     .odcid = original_dcid,
//!     .reference_time_us = now_us,
//! });
//! defer writer.deinit();
//! conn.setQlogCallback(quic.qlog.Writer.callback, &writer);
//! conn.setQlogPacketEvents(true); // opt into per-packet events
//! ```
//!
//! Serialization failures latch `Writer.failed` and stop further
//! writes; they are never surfaced into the connection (the callback
//! contract returns void). This surface sits in the **Unstable** tier
//! alongside the qlog event model it serializes (docs/API_STABILITY.md).

pub const Writer = @import("writer.zig").Writer;

/// The qlog schema version every emitted trace declares.
pub const qlog_version = "0.4";

test {
    _ = @import("writer.zig");
}
