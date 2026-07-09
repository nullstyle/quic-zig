//! Shared fixtures for the echo example pair (`echo_server.zig` /
//! `echo_client.zig`) and the one-process smoke harness
//! (`echo_smoke.zig`).
//!
//! The certificate/key are the repo's self-signed *test* fixtures,
//! copied from `tests/data/` so the examples module (rooted at
//! `examples/`) can `@embedFile` them without importing across
//! package roots. They are for localhost demos only — a real
//! deployment supplies its own PEM pair and clients drop
//! `insecure_skip_verify`.

const quic_zig = @import("quic_zig");

/// Self-signed localhost certificate (PEM). Test fixture — do not
/// deploy.
pub const cert_pem = @embedFile("support/test_cert.pem");

/// Matching private key for `cert_pem`.
pub const key_pem = @embedFile("support/test_key.pem");

/// ALPN the echo pair negotiates. Client and server must agree —
/// QUIC mandates ALPN (RFC 9001 §8.1).
pub const alpn = "echo/1";

/// Default address the pair rendezvous on when argv doesn't say
/// otherwise.
pub const default_addr = "127.0.0.1:4433";

/// Transport parameters both sides advertise. Modest stream windows
/// (plenty for an echo demo) plus a non-zero
/// `max_datagram_frame_size` so the RFC 9221 DATAGRAM echo leg works
/// — leave that field at its 0 default and `sendDatagram` fails with
/// `DatagramUnavailable`.
pub fn transportParams() quic_zig.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
        .active_connection_id_limit = 4,
        .max_datagram_frame_size = 1200,
    };
}
