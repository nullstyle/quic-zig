# Security policy

quic-zig is a transport-protocol library that parses untrusted bytes
from peers over UDP: QUIC long/short-header packets, transport
parameters, every frame type (CRYPTO, STREAM, ACK, RESET_STREAM,
CONNECTION_CLOSE, DATAGRAM, path-validation, connection-id, …), tokens,
and the coalesced Initial/Handshake/1-RTT datagrams of the handshake. It
also drives the TLS handshake across an FFI boundary into BoringSSL. We
treat memory-safety issues, panics on adversarial inputs, and
resource-exhaustion vectors as security-relevant.

## Reporting a vulnerability

**Do not file public GitHub issues for vulnerabilities.** Send a
private report to `nullstyle+quic-zig-security@gmail.com` with:

- A clear description of the issue.
- Steps to reproduce (a minimal hand-crafted packet or byte sequence is
  ideal).
- The affected revision (commit SHA or tag).
- Optionally, your suggested mitigation.

I'll acknowledge receipt within 7 days. The intended disclosure
timeline is **90 days** from acknowledgement to coordinated public
disclosure. If a fix lands earlier, public disclosure follows.

## Scope

In scope:
- Memory-safety bugs (use-after-free, out-of-bounds, double-free,
  data races) reachable from peer-controlled input, including across the
  BoringSSL FFI boundary.
- Panics or unreachable-reached on adversarial wire-format inputs
  (malformed packets, frames, transport parameters, tokens).
- Algorithmic complexity attacks (e.g. quadratic blowup on a malicious
  ACK range set, CRYPTO reassembly, or connection-id churn).
- Unbounded resource consumption (memory, allocator pressure, internal
  state map growth — reassembly buffers, send queues, path/CID tables,
  datagram queues) attributable to peer-controlled input beyond the
  documented `Config` / `max_connection_memory` caps.
- Anti-amplification (RFC 9000 §8.1), Retry/token, stateless-reset, and
  key-update oversights specific to this library's implementation.

Out of scope:
- Issues reachable only with a misconfigured `Config` that disables one
  of the production defaults (e.g. an unbounded `max_connection_memory`).
- Issues that depend on a malicious / modified Zig compiler or build
  environment.
- Cryptographic vulnerabilities in BoringSSL itself — report those
  upstream; the [`boringssl-zig`](https://github.com/nullstyle/boringssl-zig)
  binding belongs in that repo, and application/HTTP-layer issues belong
  in sister project [`http3-zig`](https://github.com/nullstyle/http3-zig).
