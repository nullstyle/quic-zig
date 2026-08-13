//! Internal-surface pin coverage — the restyle gate.
//!
//! `public_api_smoke.zig` pins the Stable embedder tier. This file pins
//! the INTERNAL-tier paths that in-repo consumers (tests/, bench/,
//! examples/, tools/) and known downstreams actually reach today, so
//! that the zig-style restyle (file renames + file-as-struct
//! conversions) cannot silently break a name: every alias promise
//! becomes a compile error the moment it stops resolving.
//!
//! Every line below is a real usage found by grep on 2026-08-13 —
//! in-repo, or in http3-zig's checkout (their verified reach:
//! `conn.state.Error`, `conn.path.Address`,
//! `conn.path.ConnectionId.fromSlice`, plus wrapper-tier names).
//! Nothing here promises stability to embedders; it promises that
//! renames inside src/ keep the compat aliases wired. Prune entries
//! only when the consuming code is gone.

const std = @import("std");
const quic = @import("quic");

test "conn namespace: submodule and type paths keep resolving" {
    comptime {
        @setEvalBranchQuota(20_000);
        // Flat type re-exports on quic.conn.
        _ = quic.conn.Connection;
        _ = quic.conn.ConnectionIdProvision;
        _ = quic.conn.NewReno;
        _ = quic.conn.NewTokenBlob;
        _ = quic.conn.NewTokenKey;
        _ = quic.conn.PnSpace;
        _ = quic.conn.RttEstimator;
        _ = quic.conn.SentPacketTracker;
        // Submodule namespaces (snake aliases survive the restyle).
        _ = quic.conn.congestion;
        _ = quic.conn.congestion.Bbr;
        _ = quic.conn.congestion.Config;
        _ = quic.conn.congestion.Cubic;
        _ = quic.conn.delivery_rate;
        _ = quic.conn.delivery_rate.Estimator;
        _ = quic.conn.event_queue;
        _ = quic.conn.flow_control;
        _ = quic.conn.hystart;
        _ = quic.conn.lifecycle;
        _ = quic.conn.lifecycle.CloseErrorSpace.application;
        _ = quic.conn.lifecycle.CloseErrorSpace.transport;
        _ = quic.conn.lifecycle.CloseSource.local;
        _ = quic.conn.lifecycle.CloseSource.peer;
        _ = quic.conn.loss_recovery;
        _ = quic.conn.new_token;
        _ = quic.conn.new_token.max_token_len;
        _ = quic.conn.new_token.mint;
        _ = quic.conn.pacing;
        _ = quic.conn.path;
        _ = quic.conn.path.Address;
        _ = quic.conn.path.Address.context_max_len;
        _ = quic.conn.path.Address.eql;
        _ = quic.conn.path.ConnectionId;
        _ = quic.conn.path.ConnectionId.eql;
        _ = quic.conn.path.ConnectionId.fromSlice;
        _ = quic.conn.path.State.failed;
        _ = quic.conn.path.State.retiring;
        _ = quic.conn.path_validator;
        _ = quic.conn.path_validator.PathValidator;
        _ = quic.conn.path_validator.Status.validated;
        _ = quic.conn.pn_space;
        _ = quic.conn.recv_stream;
        _ = quic.conn.retry_token;
        _ = quic.conn.retry_token.max_token_len;
        _ = quic.conn.rtt;
        _ = quic.conn.rtt.RttEstimator;
        _ = quic.conn.send_stream;
        _ = quic.conn.send_stream.State.reset_recvd;
        _ = quic.conn.sent_packets;
        _ = quic.conn.sent_packets.SentPacketTracker;
        _ = quic.conn.sent_packets.max_tracked;
        _ = quic.conn.stateless_reset;
        _ = quic.conn.stateless_reset.Key;
        _ = quic.conn.stateless_reset.Token;
        _ = quic.conn.stateless_reset.derive;
        _ = quic.conn.stateless_reset.eql;
        // state: the hot one — becomes an alias for Connection.zig.
        // `state.Error` and `path.*` are http3-zig's verified reach.
        _ = quic.conn.state;
        _ = quic.conn.state.Connection;
        // Error-set members can't be bare-discarded; use the
        // comparison form (public_api_smoke precedent).
        if (@as(quic.conn.state.Error, error.KeyUpdateBlocked) != error.KeyUpdateBlocked) {
            @compileError("conn.state.Error.KeyUpdateBlocked drifted");
        }
        _ = quic.conn.state.PacketKeys;
        _ = quic.conn.state.Stream;
        _ = quic.conn.state.min_quic_udp_payload_size;
        _ = quic.conn.state.transport_error_excessive_load;
    }
}

test "frame / wire / tls / transport / qlog namespaces keep resolving" {
    comptime {
        @setEvalBranchQuota(20_000);
        _ = quic.frame.ack_range;
        _ = quic.frame.encode;
        _ = quic.frame.iter;
        _ = quic.frame.types;
        _ = quic.frame.types.Ack;

        _ = quic.wire.header;
        _ = quic.wire.header.parse;
        _ = quic.wire.header.VersionNegotiation;
        _ = quic.wire.initial;
        _ = quic.wire.initial.deriveInitialKeys;
        _ = quic.wire.long_packet;
        _ = quic.wire.long_packet.openHandshake;
        _ = quic.wire.long_packet.sealInitial;
        _ = quic.wire.protection;
        _ = quic.wire.short_packet;
        _ = quic.wire.short_packet.Suite;
        _ = quic.wire.short_packet.derivePacketKeys;
        _ = quic.wire.short_packet.open1Rtt;
        _ = quic.wire.short_packet.seal1Rtt;
        _ = quic.wire.varint;

        _ = quic.tls.AntiReplayTracker;
        _ = quic.tls.AntiReplayTracker.init;
        _ = quic.tls.TransportParams;
        _ = quic.tls.anti_replay;
        _ = quic.tls.anti_replay.Id;
        _ = quic.tls.anti_replay.Verdict.fresh;
        _ = quic.tls.anti_replay.Verdict.replay;
        _ = quic.tls.early_data_context;
        _ = quic.tls.level;
        _ = quic.tls.resumption_state.decode;
        _ = quic.tls.resumption_state.encodeAlloc;
        _ = quic.tls.transport_params;
        _ = quic.tls.transport_params.PreferredAddress;

        _ = quic.transport.EcnCodepoint;
        _ = quic.transport.RunError;
        _ = quic.transport.RunUdpClientError;
        _ = quic.transport.RunUdpClientOptions;
        _ = quic.transport.RunUdpOptions;
        _ = quic.transport.runUdpClient;
        _ = quic.transport.runUdpServer;
        _ = quic.transport.socket_opts;
        _ = quic.transport.udp_server.ipAddressToPathAddress;
        _ = quic.transport.udp_server.monotonicNowUs;
        _ = quic.transport.udp_server.pathAddressToIpAddress;

        _ = quic.qlog.Writer;
    }
}

test "lb namespace: flat and per-module paths keep resolving" {
    comptime {
        if (@as(quic.lb.DecodeError, error.UnroutableCid) != error.UnroutableCid or
            @as(quic.lb.Error, error.InvalidLbConfig) != error.InvalidLbConfig or
            @as(quic.lb.Error, error.NonceExhausted) != error.NonceExhausted or
            @as(quic.lb.config.Error, error.InvalidLbConfig) != error.InvalidLbConfig or
            @as(quic.lb.config.Error, error.InvalidServerId) != error.InvalidServerId)
        {
            @compileError("lb error-set members drifted");
        }
        _ = quic.lb.Factory;
        _ = quic.lb.Factory.init;
        _ = quic.lb.Key;
        _ = quic.lb.LbConfig;
        _ = quic.lb.Mode.aes_four_pass;
        _ = quic.lb.Mode.aes_single_pass;
        _ = quic.lb.ServerId.fromSlice;
        _ = quic.lb.cid.firstOctetConfigId;
        _ = quic.lb.cid.firstOctetLengthBits;
        _ = quic.lb.decode;
        _ = quic.lb.feistel.decrypt;
        _ = quic.lb.feistel.encrypt;
        _ = quic.lb.mintUnroutable;
    }
}
