//! PEM-from-memory TLS credential installation.
//!
//! `boringssl.tls.Context` covers file-path trust anchors
//! (`VerifyMode.ca_file` / `.ca_dir`) and server-side certificate
//! loading (`loadCertChainAndKey`), but embedders configuring the
//! wrappers hand us PEM *bytes*, not paths — a config file, a secrets
//! manager, an @embedFile. This module fills the two gaps through the
//! exported raw surface, without requiring the embedder to name any
//! BoringSSL type:
//!  - `installTrustAnchors` — parse a PEM CA bundle from memory into
//!    the context's X509 store and require peer verification. Backs
//!    `Client.Config.ca_pem` (private-CA pinning) and
//!    `Server.Config.client_ca_pem` (mTLS).
//!  - `installClientIdentity` — client-side counterpart of the
//!    server-only `loadCertChainAndKey`: leaf + intermediates + key
//!    for the certificate the client presents when the server
//!    requests one (mTLS). Backs `Client.Config.client_cert_pem` /
//!    `client_key_pem`.
//!
//! Both helpers copy what they need during the call — BoringSSL
//! parses the PEM into its own objects — so the byte slices only
//! need to outlive the call itself.

const std = @import("std");
const boringssl = @import("boringssl");

const raw = boringssl.raw;

pub const Error = boringssl.tls.Error;

/// True when the pending BoringSSL error queue says the last
/// `PEM_read_bio_X509` null was clean end-of-input
/// (`PEM_R_NO_START_LINE`) rather than a malformed block — the same
/// distinction BoringSSL's own file loader makes, so a bundle
/// truncated mid-certificate fails loudly instead of silently
/// installing a prefix of the roots. Clears the queue on clean EOF.
fn pemReaderHitCleanEof() bool {
    const err = raw.zbssl_ERR_peek_last_error();
    if (raw.ERR_GET_REASON(err) != raw.PEM_R_NO_START_LINE) return false;
    raw.zbssl_ERR_clear_error();
    return true;
}

/// How `installTrustAnchors` treats a peer that presents no
/// certificate at all.
pub const PeerCertRequirement = enum {
    /// Verify the peer certificate when one is presented. This is the
    /// client posture: TLS servers always send a certificate, so the
    /// distinction never arises there.
    verify_peer,
    /// Additionally fail the handshake when the peer presents no
    /// certificate (`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`). This is the
    /// server mTLS posture — without it a client that simply omits
    /// its certificate would pass.
    require_peer_cert,
};

/// Parse a PEM bundle of trusted root certificates from memory, add
/// each to `ctx`'s X509 store, and flip the context to
/// `SSL_VERIFY_PEER`. The bundle must contain at least one
/// certificate; trailing non-PEM bytes after the last block are
/// rejected the same way BoringSSL's own file loader treats them
/// (end-of-input is fine, a malformed block is `InvalidPem`).
///
/// Verification against these anchors replaces — not augments — the
/// system trust store: callers build the context with
/// `verify = .none` and then pin roots here, so the only roots the
/// context trusts are the ones in `ca_pem`.
pub fn installTrustAnchors(
    ctx: boringssl.tls.Context,
    ca_pem: []const u8,
    requirement: PeerCertRequirement,
) Error!void {
    const store = raw.zbssl_SSL_CTX_get_cert_store(ctx.inner) orelse
        return Error.LoadCAFileFailed;

    const bio = raw.zbssl_BIO_new_mem_buf(ca_pem.ptr, @intCast(ca_pem.len)) orelse
        return Error.OutOfMemory;
    defer _ = raw.zbssl_BIO_free(bio);

    var count: usize = 0;
    while (true) {
        const cert = raw.zbssl_PEM_read_bio_X509(bio, null, null, null);
        if (cert == null) {
            if (count == 0 or !pemReaderHitCleanEof()) return Error.InvalidPem;
            break;
        }
        const added = raw.zbssl_X509_STORE_add_cert(store, cert);
        // X509_STORE_add_cert up-refs internally; release ours either way.
        raw.zbssl_X509_free(cert);
        if (added != 1) return Error.LoadCAFileFailed;
        count += 1;
    }

    const mode: c_int = switch (requirement) {
        .verify_peer => raw.SSL_VERIFY_PEER,
        .require_peer_cert => raw.SSL_VERIFY_PEER | raw.SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    };
    raw.zbssl_SSL_CTX_set_verify(ctx.inner, mode, null);
}

/// Load a PEM-encoded certificate chain plus a PEM-encoded private
/// key into a CLIENT-mode context — the certificate the client
/// presents when a server requests one (mTLS). The first certificate
/// in `chain_pem` is the end-entity (leaf); any subsequent PEM certs
/// are added as intermediates. The private key is validated against
/// the leaf.
///
/// Mirrors `boringssl.tls.Context.loadCertChainAndKey`, which is
/// deliberately server-only upstream; this is the client half, gated
/// the same way in the opposite direction.
pub fn installClientIdentity(
    ctx: boringssl.tls.Context,
    chain_pem: []const u8,
    key_pem: []const u8,
) Error!void {
    if (ctx.mode != .client) return Error.NotClientContext;

    const cert_bio = raw.zbssl_BIO_new_mem_buf(chain_pem.ptr, @intCast(chain_pem.len)) orelse
        return Error.OutOfMemory;
    defer _ = raw.zbssl_BIO_free(cert_bio);

    var idx: usize = 0;
    while (true) {
        const cert = raw.zbssl_PEM_read_bio_X509(cert_bio, null, null, null);
        if (cert == null) {
            if (idx == 0 or !pemReaderHitCleanEof()) return Error.InvalidPem;
            break;
        }
        if (idx == 0) {
            if (raw.zbssl_SSL_CTX_use_certificate(ctx.inner, cert) != 1) {
                raw.zbssl_X509_free(cert);
                return Error.UseCertFailed;
            }
            // SSL_CTX_use_certificate up-refs internally; release ours.
            raw.zbssl_X509_free(cert);
        } else {
            if (raw.zbssl_SSL_CTX_add0_chain_cert(ctx.inner, cert) != 1) {
                raw.zbssl_X509_free(cert);
                return Error.UseCertFailed;
            }
            // add0 takes ownership; do not free.
        }
        idx += 1;
    }

    const key_bio = raw.zbssl_BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse
        return Error.OutOfMemory;
    defer _ = raw.zbssl_BIO_free(key_bio);

    const pkey = raw.zbssl_PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse
        return Error.InvalidPem;
    defer raw.zbssl_EVP_PKEY_free(pkey);

    if (raw.zbssl_SSL_CTX_use_PrivateKey(ctx.inner, pkey) != 1) {
        return Error.UsePrivateKeyFailed;
    }
    if (raw.zbssl_SSL_CTX_check_private_key(ctx.inner) != 1) {
        return Error.KeyMismatch;
    }
}

// -- tests --------------------------------------------------------------
//
// Happy paths (a real handshake pinned to a real CA, mTLS both ways)
// live in tests/e2e/tls_verify_e2e.zig where the PEM fixtures can be
// @embedFile'd. The tests here only need throwaway contexts and
// malformed input.

test "installTrustAnchors rejects a bundle with no certificates" {
    var ctx = try boringssl.tls.Context.initClient(.{ .verify = .none });
    defer ctx.deinit();
    try std.testing.expectError(
        Error.InvalidPem,
        installTrustAnchors(ctx, "not a pem bundle", .verify_peer),
    );
}

test "installTrustAnchors rejects a truncated PEM block" {
    var ctx = try boringssl.tls.Context.initClient(.{ .verify = .none });
    defer ctx.deinit();
    const truncated = "-----BEGIN CERTIFICATE-----\nAAAA\n";
    try std.testing.expectError(
        Error.InvalidPem,
        installTrustAnchors(ctx, truncated, .verify_peer),
    );
}

test "installClientIdentity refuses a server-mode context" {
    var ctx = try boringssl.tls.Context.initServer(.{ .verify = .none });
    defer ctx.deinit();
    try std.testing.expectError(
        Error.NotClientContext,
        installClientIdentity(ctx, "irrelevant", "irrelevant"),
    );
}

test "installClientIdentity rejects garbage chain PEM" {
    var ctx = try boringssl.tls.Context.initClient(.{ .verify = .none });
    defer ctx.deinit();
    try std.testing.expectError(
        Error.InvalidPem,
        installClientIdentity(ctx, "garbage", "garbage"),
    );
}
