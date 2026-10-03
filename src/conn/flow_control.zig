//! Flow-control error names (RFC 9000 §4).
//!
//! This module used to hold bookkeeping types for the three limits of
//! §4 (`DataWindow` / `ConnectionData` / `StreamData` for MAX_DATA and
//! MAX_STREAM_DATA, `StreamCount` for MAX_STREAMS), with unit tests, a
//! fuzz harness, a microbenchmark, and ten RFC conformance tests.
//! `Connection` never used any of them. It keeps its own counters
//! (`peer_max_data`, `Stream.send_max_data`, the `StreamIdSpace`
//! values, `creditPeerStreamHighWater` in `Connection/flow.zig`), so
//! all of that evidence was about code that does not run on any
//! connection. The types were removed in 0.24.0, and the conformance
//! tests now drive a real `Connection` pair
//! (`tests/conformance/rfc9000_streams_flow.zig`).
//!
//! What is left is the error set, because it is merged into
//! `Connection.Error` and an embedder's `switch` may name its members.
//! Nothing returns them today. Remove them at the next breaking change
//! to the error set, not before.

/// Flow-control errors. Part of `Connection.Error`; see the module doc.
pub const Error = error{
    /// We tried to send beyond the peer's flow-control limit.
    FlowControlExceeded,
    /// Peer tried to send beyond our advertised limit. RFC 9000 §4.1
    /// says to close with FLOW_CONTROL_ERROR.
    PeerExceededLimit,
};
