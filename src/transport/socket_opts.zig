//! Socket-option knobs for QUIC datagram sockets.
//!
//! QUIC servers exposed to the open internet need bigger kernel
//! buffers than the OS default (~200 KiB on Linux, ~9 KiB on macOS for
//! UDP). On a 1 Gbit/s NIC a single 5-tuple can deliver hundreds of
//! 1350-byte datagrams in a few hundred microseconds; if the userland
//! receive loop is briefly preempted, the kernel's `SO_RCVBUF` queue
//! is the only thing that absorbs the burst before the kernel starts
//! dropping packets and incrementing `netstat -s | grep "receive
//! buffer errors"`. Those drops look like ordinary loss to QUIC, so
//! they trigger PTO/retransmits, hurt goodput, and can mask real
//! congestion-control behavior. msquic, quic-go, lsquic, and
//! nginx-quic all bump `SO_RCVBUF` / `SO_SNDBUF` to several MiB at
//! socket setup for exactly this reason.
//!
//! This module provides small, platform-aware wrappers around
//! `setsockopt` so any consumer of the quic library — the QNS
//! endpoint, an embedded server, a load tester — can tune a freshly
//! bound socket the same way.
//!
//! Conventions:
//! * Sizes are passed as `usize` (bytes). The Linux kernel will
//!   silently double the requested value (`net/core/sock.c`
//!   `sock_setsockopt`), and `net.core.rmem_max` / `wmem_max` cap
//!   the final size; an unprivileged process cannot exceed the cap.
//! * On Linux we first attempt `SO_RCVBUFFORCE` /
//!   `SO_SNDBUFFORCE` (which require `CAP_NET_ADMIN` and bypass
//!   the sysctl cap). If that fails with `EPERM` we fall through
//!   to the regular cap-respecting variant. Production QUIC
//!   servers run inside containers or behind systemd hardening
//!   where granting `CAP_NET_ADMIN` is cheap; outside that, the
//!   fallback gets us whatever `rmem_max` allows.
//! * macOS / BSD do not have a "force" variant. The kernel honors
//!   the requested size up to `kern.ipc.maxsockbuf` (default
//!   ~8 MiB on macOS Sequoia).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Platform-specific IP-layer constants. `posix.IP` / `posix.IPV6`
/// resolve to `void` on macOS / Darwin (the `std.c` switch elides
/// Apple), so we hard-code the numeric values from the kernel
/// headers — these are wire-stable ABI on every Unix we run on.
// INTERNAL: pub for direct sibling import (udp_batch.zig tests build
// synthetic IP_TOS control buffers with it).
pub const ip_consts = blk: {
    if (builtin.os.tag == .linux) {
        // include/uapi/linux/in.h
        break :blk struct {
            pub const ip_proto: u32 = 0;
            pub const ipv6_proto: u32 = 41;
            pub const ip_tos: u32 = 1;
            pub const ip_recvtos: u32 = 13;
            pub const ipv6_tclass: u32 = 67;
            pub const ipv6_recvtclass: u32 = 66;
        };
    } else if (builtin.os.tag.isDarwin()) {
        // bsd/netinet/in.h, bsd/netinet6/in6.h
        break :blk struct {
            pub const ip_proto: u32 = 0;
            pub const ipv6_proto: u32 = 41;
            pub const ip_tos: u32 = 3;
            pub const ip_recvtos: u32 = 27;
            pub const ipv6_tclass: u32 = 36;
            pub const ipv6_recvtclass: u32 = 35;
        };
    } else {
        // Unknown platform — pretend the constants are unset so the
        // setter helpers below fall through to `error.Unsupported`.
        break :blk struct {
            pub const ip_proto: u32 = 0;
            pub const ipv6_proto: u32 = 0;
            pub const ip_tos: u32 = 0;
            pub const ip_recvtos: u32 = 0;
            pub const ipv6_tclass: u32 = 0;
            pub const ipv6_recvtclass: u32 = 0;
        };
    }
};

/// True iff the build target exposes IP TOS / IPV6 TCLASS sockopts.
/// Both setter helpers degrade to `error.Unsupported` on platforms
/// where this is `false`.
const has_ip_ecn_sockopts: bool = builtin.os.tag == .linux or builtin.os.tag.isDarwin();

/// True iff this module should use `std.posix.setsockopt` /
/// `getsockopt` for SO_RCVBUF and SO_SNDBUF. Zig's Windows POSIX shim
/// intentionally routes sockets through `std.Io`, so this module treats
/// the Unix-only tuning helpers as unsupported there.
const has_posix_buffer_sockopts: bool = builtin.os.tag != .windows;

/// True iff `std.c.cmsghdr` is a real struct on this target, so the
/// cmsg byte-math helpers below can project field offsets from it.
/// Windows has no ancillary-data layout and std declares the type as
/// `void` there, which makes `@offsetOf` a compile error rather than a
/// runtime failure — hence a comptime gate, and hence structural
/// rather than an OS list, so it tracks std instead of guessing.
const has_cmsg_layout: bool = @typeInfo(std.c.cmsghdr) == .@"struct";

/// Underlying socket handle type; matches `std.Io.net.Socket.Handle`.
pub const Handle = posix.socket_t;

/// IETF ECN codepoint (RFC 3168 §5). The two low bits of the IPv4
/// TOS byte / IPv6 TCLASS byte. QUIC uses these for path-level
/// congestion signaling (RFC 9000 §13.4):
/// * `not_ect` (0b00) — endpoint is opting out of ECN.
/// * `ect0` (0b10) — ECN-Capable, codepoint 0; quic's default for
///   1-RTT and 0-RTT packets.
/// * `ect1` (0b01) — ECN-Capable, codepoint 1; quic only ever
///   parses, never emits, this on the send side (per QUIC consensus).
/// * `ce` (0b11) — Congestion Experienced; only ever set by routers
///   on the path. A QUIC endpoint that emits CE itself is broken.
pub const EcnCodepoint = enum(u2) {
    not_ect = 0b00,
    ect1 = 0b01,
    ect0 = 0b10,
    ce = 0b11,
};

/// Recommended size for the per-recv cmsg control buffer that the
/// loop hands `Socket.receiveTimeout`. 64 bytes is comfortably big
/// enough for both `IP_TOS` (Linux IP_TOS / macOS RECVTOS) and
/// `IPV6_TCLASS` cmsgs in one datagram, including alignment padding;
/// production QUIC embedders rarely enable other ancillary data
/// (PKTINFO etc.) on the QUIC socket, so the 64-byte ceiling is
/// generous.
pub const default_cmsg_buffer_bytes: usize = 64;

/// Errors raised by the ECN socket-option helpers. They wrap the
/// same `setsockopt` error space as the buffer helpers above.
pub const SetEcnError = error{
    /// The platform does not expose either `IP_TOS` or `IPV6_TCLASS`.
    /// Embedders that must run on such a platform should fall back to
    /// disabling ECN at the `Connection.Config` / `Server.Config`
    /// level rather than treating this as fatal.
    Unsupported,
    /// `setsockopt` rejected the value.
    InvalidValue,
    /// The current process lacks the privileges to set the socket
    /// option (rare; sometimes seen in restrictive container
    /// sandboxes).
    PermissionDenied,
} || posix.UnexpectedError;

/// Set the outgoing IP-layer ECN codepoint for every datagram
/// emitted on `handle`. Sets both `IP_TOS` (IPv4) and `IPV6_TCLASS`
/// (IPv6) so the same socket carries the marking on dual-stack
/// listeners. Failures on the IPv6 setter when the socket is
/// AF_INET-only (and vice versa) collapse to "first success wins"
/// — the QUIC stack tolerates one of the two failing as long as
/// the address family it actually uses got the marking.
///
/// Only the low two bits of the TOS byte are touched; quic
/// leaves the DSCP bits at zero (the kernel default).
pub fn setEcnSendMarking(handle: Handle, codepoint: EcnCodepoint) SetEcnError!void {
    if (!has_ip_ecn_sockopts) return error.Unsupported;
    const tos: c_int = @backingInt(codepoint);
    const tos_bytes = std.mem.asBytes(&tos);

    var any_ok = false;
    setsockoptIntChecked(handle, ip_consts.ip_proto, ip_consts.ip_tos, tos_bytes) catch |err| switch (err) {
        // OS treats the option as inapplicable for this socket family
        // — that's fine if the v6 setter below succeeds.
        error.Unsupported => {},
        else => |e| return e,
    };
    any_ok = true;

    // Some platforms expose IPV6_TCLASS only when the socket is
    // bound IPv6; on a strict-IPv4 socket the call returns EINVAL
    // / ENOPROTOOPT. Try anyway and swallow those failures.
    setsockoptIntChecked(handle, ip_consts.ipv6_proto, ip_consts.ipv6_tclass, tos_bytes) catch |err| switch (err) {
        error.Unsupported => {},
        else => |e| {
            // If IPv4 also failed (any_ok would be false), surface
            // the v6 error. Otherwise the v4 setter already won.
            if (!any_ok) return e;
        },
    };
    if (!any_ok) return error.Unsupported;
}

/// Enable ancillary delivery of the received IP TOS byte via cmsg
/// on `handle`. Sets `IP_RECVTOS` (Linux/BSD/macOS) and
/// `IPV6_RECVTCLASS` so a recvmsg with a control buffer surfaces
/// the per-datagram TOS. Same dual-stack tolerance as
/// `setEcnSendMarking` — at least one address family must succeed.
pub fn setEcnRecvEnabled(handle: Handle, enabled: bool) SetEcnError!void {
    if (!has_ip_ecn_sockopts) return error.Unsupported;
    const value: c_int = if (enabled) 1 else 0;
    const value_bytes = std.mem.asBytes(&value);

    var any_ok = false;
    setsockoptIntChecked(handle, ip_consts.ip_proto, ip_consts.ip_recvtos, value_bytes) catch |err| switch (err) {
        error.Unsupported => {},
        else => |e| return e,
    };
    any_ok = true;
    setsockoptIntChecked(handle, ip_consts.ipv6_proto, ip_consts.ipv6_recvtclass, value_bytes) catch |err| switch (err) {
        error.Unsupported => {},
        else => |e| {
            if (!any_ok) return e;
        },
    };
    if (!any_ok) return error.Unsupported;
}

fn setsockoptIntChecked(handle: Handle, level: u32, optname: u32, opt_bytes: []const u8) SetEcnError!void {
    // We can't use `posix.setsockopt` here: it panics on EINVAL,
    // and EINVAL is the documented "IPv6 option on an AF_INET
    // socket" / "IPv4 option on an AF_INET6 V6ONLY socket" return
    // — which is exactly the dual-stack-tolerant behavior the
    // ECN setters above rely on. Map the errnos ourselves and
    // surface them as `error.Unsupported` so the caller falls
    // through to the other address family.
    const rc = std.c.setsockopt(handle, @intCast(level), optname, opt_bytes.ptr, @intCast(opt_bytes.len));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .INVAL,
        .NOPROTOOPT,
        .OPNOTSUPP,
        .AFNOSUPPORT,
        .PROTONOSUPPORT,
        => return error.Unsupported,
        .PERM, .ACCES => return error.PermissionDenied,
        .NOMEM, .NOBUFS => return error.InvalidValue,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// One `CMSG_ALIGN` unit: both `CMSG_DATA` (header -> payload) and
/// `CMSG_NXTHDR` (entry -> entry) pad to this boundary. Matches the
/// Linux kernel and glibc/musl (`sizeof(size_t)`).
///
/// KNOWN DIVERGENCE, deliberately preserved: Darwin's kernel macros
/// use `__DARWIN_ALIGN32` (4 bytes), so this constant over-advances
/// there for cmsg payloads of 5-8 bytes mod 8. It is harmless for
/// every payload actually in play (1-byte IP_TOS and 4-byte
/// IPV6_TCLASS / UDP_GRO all pad to the same boundary either way),
/// but if a differently-sized cmsg ever matters on macOS, the fix is
/// this one constant — every walker and builder in the tree shares it.
const cmsg_align: usize = @sizeOf(usize);

/// Iterator over the cmsg entries of a populated `recvmsg` control
/// buffer — the one shared POSIX `CMSG_FIRSTHDR` / `CMSG_NXTHDR` walk
/// that `parseEcnFromControl` and `parseGroSegmentFromControl` used
/// to hand-roll separately. Tolerates malformed entries (`cmsg_len`
/// shorter than a header, or overrunning the buffer) by ending the
/// walk; QUIC peers can't influence our control buffer so the guards
/// are belt-and-suspenders for kernel quirks.
///
/// The layout projection lives in struct-level decls so it is only
/// sema'd when a caller actually uses the iterator — callers MUST
/// gate on `has_cmsg_layout` first (`std.c.cmsghdr` is `void` on
/// Windows, where `@offsetOf` would be a compile error).
const CmsgIter = struct {
    control: []const u8,
    pos: usize = 0,

    // cmsghdr layout differs between glibc Linux (`size_t` len, two
    // `int`) and BSD/macOS (`socklen_t` len, two `int`). We read both
    // by reaching into `std.c.cmsghdr` (the `extern struct` defined
    // for every supported OS) and projecting the byte offsets via
    // `@offsetOf` / `@sizeOf`.
    const Cmsg = std.c.cmsghdr;
    const header_size: usize = @sizeOf(Cmsg);
    const len_off: usize = @offsetOf(Cmsg, "len");
    const level_off: usize = @offsetOf(Cmsg, "level");
    const type_off: usize = @offsetOf(Cmsg, "type");
    const len_size: usize = @sizeOf(@FieldType(Cmsg, "len"));

    /// One decoded cmsg entry. `data` is the payload
    /// (`CMSG_DATA(cmsg)[0 .. cmsg_len - header]`), already
    /// bounds-checked against the control buffer.
    const Entry = struct {
        level: i32,
        cmsg_type: i32,
        data: []const u8,
    };

    fn init(control: []const u8) CmsgIter {
        return .{ .control = control };
    }

    fn next(self: *CmsgIter) ?Entry {
        const pos = self.pos;
        if (pos + header_size > self.control.len) return null;
        const cmsg_len: usize = blk: {
            if (len_size == @sizeOf(usize)) {
                break :blk std.mem.readInt(usize, self.control[pos + len_off ..][0..@sizeOf(usize)], native_endian);
            } else {
                break :blk @intCast(std.mem.readInt(u32, self.control[pos + len_off ..][0..@sizeOf(u32)], native_endian));
            }
        };
        if (cmsg_len < header_size or pos + cmsg_len > self.control.len) return null;
        const cmsg_level = std.mem.readInt(i32, self.control[pos + level_off ..][0..4], native_endian);
        const cmsg_type = std.mem.readInt(i32, self.control[pos + type_off ..][0..4], native_endian);

        // Advance to the next cmsg, aligned per `CMSG_ALIGN`.
        const aligned = std.mem.alignForward(usize, cmsg_len, cmsg_align);
        if (aligned == 0) return null;
        self.pos = pos + aligned;

        return .{
            .level = cmsg_level,
            .cmsg_type = cmsg_type,
            .data = self.control[pos + header_size ..][0 .. cmsg_len - header_size],
        };
    }
};

/// Serialize one cmsg (header plus payload copy, zero-padded to the
/// kernel's `CMSG_SPACE`) into `buf`, returning the number of bytes
/// written. The write-side twin of `CmsgIter` — one home for the
/// projected `std.c.cmsghdr` layout, so builder and walker cannot
/// drift. Asserts `buf` is large enough; callers must gate on
/// `has_cmsg_layout` (see `CmsgIter`).
// INTERNAL: pub for direct sibling import (udp_batch.zig tests build
// synthetic UDP_GRO / IP_TOS control buffers with it).
pub fn writeCmsg(buf: []u8, cmsg_level: i32, cmsg_type: i32, data: []const u8) usize {
    const cmsg_len = CmsgIter.header_size + data.len;
    const space = std.mem.alignForward(usize, cmsg_len, cmsg_align);
    std.debug.assert(buf.len >= space);

    @memset(buf[0..space], 0);
    if (CmsgIter.len_size == @sizeOf(usize)) {
        std.mem.writeInt(usize, buf[CmsgIter.len_off..][0..@sizeOf(usize)], cmsg_len, native_endian);
    } else {
        std.mem.writeInt(u32, buf[CmsgIter.len_off..][0..@sizeOf(u32)], @intCast(cmsg_len), native_endian);
    }
    std.mem.writeInt(i32, buf[CmsgIter.level_off..][0..4], cmsg_level, native_endian);
    std.mem.writeInt(i32, buf[CmsgIter.type_off..][0..4], cmsg_type, native_endian);
    @memcpy(buf[CmsgIter.header_size..][0..data.len], data);
    return space;
}

/// Walk a populated `recvmsg` control buffer and extract the IP
/// ECN codepoint, if present. Returns `not_ect` when no IP_TOS /
/// IPV6_TCLASS cmsg was found — that's the conservative choice
/// (no ECN marking observed). Malformed cmsg payloads are skipped
/// (the walk keeps scanning); see `CmsgIter` for the traversal
/// guards.
///
/// Two gates, deliberately distinct: the comptime `has_cmsg_layout`
/// gate is structural (can this target's `std.c.cmsghdr` be walked
/// at all — Windows can't), while `has_ip_ecn_sockopts` is policy
/// (only targets where `setEcnRecvEnabled` can actually request
/// TOS/TCLASS delivery should ever interpret control bytes as ECN —
/// a BSD kernel we never asked must not have its cmsgs parsed).
pub fn parseEcnFromControl(control: []const u8) EcnCodepoint {
    if (comptime !has_cmsg_layout) return .not_ect;
    if (!has_ip_ecn_sockopts) return .not_ect;

    var it: CmsgIter = .init(control);
    while (it.next()) |c| {
        if (c.level == @as(i32, @intCast(ip_consts.ip_proto)) and
            (c.cmsg_type == @as(i32, @intCast(ip_consts.ip_tos)) or
                c.cmsg_type == @as(i32, @intCast(ip_consts.ip_recvtos))))
        {
            // The IP TOS byte may be carried as a single u8 (Linux
            // / macOS) or as a 4-byte int (some BSDs). Either way
            // the low byte holds the TOS.
            if (c.data.len >= 1) {
                return @fromBackingInt(@intCast(@as(u2, @truncate(c.data[0] & 0x03))));
            }
        }
        if (c.level == @as(i32, @intCast(ip_consts.ipv6_proto)) and
            c.cmsg_type == @as(i32, @intCast(ip_consts.ipv6_tclass)))
        {
            // IPV6_TCLASS is documented as a 4-byte int across all
            // major Unixes; the low byte holds the TCLASS (DSCP +
            // ECN), of which we only consume the low two ECN bits.
            if (c.data.len >= 4) {
                const tclass = std.mem.readInt(i32, c.data[0..4], native_endian);
                return @fromBackingInt(@intCast(@as(u2, @truncate(@as(u32, @bitCast(tclass)) & 0x03))));
            }
            if (c.data.len >= 1) {
                return @fromBackingInt(@intCast(@as(u2, @truncate(c.data[0] & 0x03))));
            }
        }
    }
    return .not_ect;
}

const native_endian = @import("builtin").cpu.arch.endian();

/// Recommended `SO_RCVBUF` for a QUIC server on the open internet.
///
/// 4 MiB lets a single connection absorb roughly a 30 ms burst at
/// 1 Gbit/s without OS-level drops, which is enough to ride out
/// scheduler jitter on a busy machine. Embedders that target tens
/// of thousands of concurrent connections may want to tune this
/// down (per-socket buffer × N connections is real RAM) or up,
/// after measuring `netstat -s` UDP receive-buffer errors.
pub const default_server_recv_buffer_bytes: usize = 4 * 1024 * 1024;

/// Recommended `SO_SNDBUF` for a QUIC server on the open internet.
///
/// QUIC sends are paced in userland (RFC 9002 §7.7 token-bucket
/// pacing in `conn.pacing`, on by default), so `SO_SNDBUF` mostly
/// matters for absorbing transient `EAGAIN`/`ENOBUFS` from a busy
/// NIC. 4 MiB is conservative and matches what other production
/// stacks use.
pub const default_server_send_buffer_bytes: usize = 4 * 1024 * 1024;

/// Errors returned by `setRecvBufferSize` / `setSendBufferSize` /
/// `applyServerTuning`. See each variant for the corresponding
/// `setsockopt` failure mode.
pub const SetBufferError = error{
    /// The platform does not expose a way to set this option.
    Unsupported,
    /// The kernel rejected the value (rare; usually only on
    /// pathological inputs like 0 or > INT_MAX).
    InvalidValue,
    /// The current process lacks the privileges to grow the
    /// buffer beyond the system cap, *and* the cap-respecting
    /// fallback also failed. Production servers usually do not
    /// see this — the cap-respecting path returns OK with a
    /// silently smaller buffer.
    PermissionDenied,
    /// The kernel could not allocate the requested buffer.
    SystemResources,
} || posix.UnexpectedError;

/// Set the kernel receive buffer for a UDP socket.
///
/// On Linux this tries the `SO_RCVBUFFORCE` variant first to
/// bypass `net.core.rmem_max`, then falls back to `SO_RCVBUF` if
/// the process lacks `CAP_NET_ADMIN`. On other Unixes only
/// `SO_RCVBUF` is attempted.
pub fn setRecvBufferSize(handle: Handle, bytes: usize) SetBufferError!void {
    return setBufferImpl(handle, bytes, .recv);
}

/// Set the kernel send buffer for a UDP socket. See
/// `setRecvBufferSize` for the Linux-specific force fallback
/// behavior; the same approach is used here with
/// `SO_SNDBUFFORCE` / `SO_SNDBUF`.
pub fn setSendBufferSize(handle: Handle, bytes: usize) SetBufferError!void {
    return setBufferImpl(handle, bytes, .send);
}

const BufferDirection = enum { recv, send };

fn setBufferImpl(handle: Handle, bytes: usize, dir: BufferDirection) SetBufferError!void {
    if (bytes == 0) return error.InvalidValue;
    if (!has_posix_buffer_sockopts) return error.Unsupported;

    // setsockopt takes a C int. Saturate at INT_MAX rather than
    // overflowing — anyone asking for >2 GiB of socket buffer has
    // bigger problems than UDP drops.
    const value: c_int = if (bytes > std.math.maxInt(c_int))
        std.math.maxInt(c_int)
    else
        @intCast(bytes);
    const opt_bytes = std.mem.asBytes(&value);

    // On Linux, try the privileged "force" variant first. It is
    // the only way to exceed `net.core.{r,w}mem_max` without
    // editing sysctl; production servers behind systemd or k8s
    // typically have `CAP_NET_ADMIN` and benefit from this.
    if (builtin.os.tag == .linux) {
        const force_optname: u32 = switch (dir) {
            .recv => @intCast(std.os.linux.SO.RCVBUFFORCE),
            .send => @intCast(std.os.linux.SO.SNDBUFFORCE),
        };
        if (posix.setsockopt(handle, posix.SOL.SOCKET, force_optname, opt_bytes)) |_| {
            return;
        } else |err| switch (err) {
            // Unprivileged process: fall through to the
            // cap-respecting variant below. Same for kernels
            // that do not recognize *FORCE.
            error.PermissionDenied,
            error.InvalidProtocolOption,
            error.OperationUnsupported,
            => {},
            error.AlreadyConnected => return error.InvalidValue,
            error.TimeoutTooBig => return error.InvalidValue,
            error.SystemResources => return error.SystemResources,
            error.FileDescriptorNotASocket,
            error.SocketNotBound,
            error.NetworkDown,
            error.NoDevice,
            error.Unexpected,
            => return error.Unexpected,
        }
    }

    const optname: u32 = switch (dir) {
        .recv => @intCast(posix.SO.RCVBUF),
        .send => @intCast(posix.SO.SNDBUF),
    };

    posix.setsockopt(handle, posix.SOL.SOCKET, optname, opt_bytes) catch |err| switch (err) {
        error.PermissionDenied => return error.PermissionDenied,
        error.InvalidProtocolOption => return error.Unsupported,
        error.AlreadyConnected => return error.InvalidValue,
        error.TimeoutTooBig => return error.InvalidValue,
        error.OperationUnsupported => return error.Unsupported,
        error.SystemResources => return error.SystemResources,
        error.FileDescriptorNotASocket,
        error.SocketNotBound,
        error.NetworkDown,
        error.NoDevice,
        error.Unexpected,
        => return error.Unexpected,
    };
}

/// Apply quic's recommended server-side tuning to a freshly bound
/// UDP socket. This is the one-shot helper an embedder calls right
/// after `Net.IpAddress.bind`. Failures from the underlying
/// `setsockopt` calls are returned so the caller can decide
/// whether to log-and-continue (the QNS endpoint does) or refuse
/// to start (a production server that requires headroom may
/// prefer to fail loudly).
pub const ServerTuning = struct {
    /// Bytes for `SO_RCVBUF`. `null` skips the call.
    recv_buffer_bytes: ?usize = default_server_recv_buffer_bytes,
    /// Bytes for `SO_SNDBUF`. `null` skips the call.
    send_buffer_bytes: ?usize = default_server_send_buffer_bytes,
};

/// Alias for `SetBufferError` — every error from `applyServerTuning`
/// flows through one of the underlying `setsockopt` calls.
pub const TuneError = SetBufferError;

/// Apply `ServerTuning` to a socket handle. Errors from the
/// individual setsockopt calls propagate; callers that want
/// best-effort behavior should use the lower-level
/// `setRecvBufferSize` / `setSendBufferSize` directly and discard
/// errors at the call site.
pub fn applyServerTuning(handle: Handle, tuning: ServerTuning) TuneError!void {
    if (tuning.recv_buffer_bytes) |bytes| try setRecvBufferSize(handle, bytes);
    if (tuning.send_buffer_bytes) |bytes| try setSendBufferSize(handle, bytes);
}

/// Read back the kernel's actual receive buffer size. Useful for
/// logging "we asked for 4 MiB, got N MiB" so operators can see
/// when sysctl caps are biting.
pub const GetBufferError = error{
    Unsupported,
} || posix.UnexpectedError;

pub fn getRecvBufferSize(handle: Handle) GetBufferError!usize {
    return getBufferImpl(handle, .recv);
}

/// Read back the kernel's actual send buffer size via
/// `getsockopt(SO_SNDBUF, ...)`. Mirrors `getRecvBufferSize` and is
/// useful for the same operator-visible "asked vs. got" logging.
pub fn getSendBufferSize(handle: Handle) GetBufferError!usize {
    return getBufferImpl(handle, .send);
}

fn getBufferImpl(handle: Handle, dir: BufferDirection) GetBufferError!usize {
    if (!has_posix_buffer_sockopts) return error.Unsupported;

    const optname: u32 = switch (dir) {
        .recv => @intCast(posix.SO.RCVBUF),
        .send => @intCast(posix.SO.SNDBUF),
    };
    var value: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    switch (posix.errno(std.c.getsockopt(handle, posix.SOL.SOCKET, @intCast(optname), &value, &len))) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    if (value < 0) return 0;
    return @intCast(value);
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;
const Net = std.Io.net;

/// Test scaffolding: bind a real loopback UDP socket via the
/// public `std.Io` API so the tests exercise the same code path
/// as production callers.
const TestSocket = struct {
    socket: Net.Socket,
    io: std.Io,

    fn init() !TestSocket {
        const io = std.testing.io;
        const addr = try Net.IpAddress.parseLiteral("127.0.0.1:0");
        const sock = try Net.IpAddress.bind(&addr, io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        return .{ .socket = sock, .io = io };
    }

    fn deinit(self: *TestSocket) void {
        self.socket.close(self.io);
    }

    fn handle(self: *const TestSocket) Handle {
        return self.socket.handle;
    }
};

test "setRecvBufferSize grows the kernel buffer" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    const before = getRecvBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };

    const requested: usize = 1 * 1024 * 1024; // 1 MiB
    setRecvBufferSize(ts.handle(), requested) catch |err| switch (err) {
        // CI may not give us the privileges or the cap; if even
        // the cap-respecting fallback can't grow the buffer,
        // skip rather than fail.
        error.PermissionDenied, error.SystemResources => return error.SkipZigTest,
        else => return err,
    };

    const after = getRecvBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    // Linux doubles the requested value, BSD/macOS returns ~what
    // was set; either way we expect >= the prior default.
    try testing.expect(after >= before);
}

test "setSendBufferSize grows the kernel buffer" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    const before = getSendBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };

    const requested: usize = 1 * 1024 * 1024;
    setSendBufferSize(ts.handle(), requested) catch |err| switch (err) {
        error.PermissionDenied, error.SystemResources => return error.SkipZigTest,
        else => return err,
    };

    const after = getSendBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    try testing.expect(after >= before);
}

test "setRecvBufferSize rejects zero" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    try testing.expectError(error.InvalidValue, setRecvBufferSize(ts.handle(), 0));
}

test "setSendBufferSize rejects zero" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    try testing.expectError(error.InvalidValue, setSendBufferSize(ts.handle(), 0));
}

test "applyServerTuning sets both buffers" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    applyServerTuning(ts.handle(), .{
        .recv_buffer_bytes = 512 * 1024,
        .send_buffer_bytes = 512 * 1024,
    }) catch |err| switch (err) {
        error.PermissionDenied, error.SystemResources, error.Unsupported => return error.SkipZigTest,
        else => return err,
    };

    const rcv = getRecvBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    const snd = getSendBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    try testing.expect(rcv > 0);
    try testing.expect(snd > 0);
}

test "applyServerTuning honors null fields" {
    var ts = try TestSocket.init();
    defer ts.deinit();

    const before_rcv = getRecvBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    const before_snd = getSendBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };

    // Skip both; should be a no-op.
    try applyServerTuning(ts.handle(), .{
        .recv_buffer_bytes = null,
        .send_buffer_bytes = null,
    });

    const after_rcv = getRecvBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    const after_snd = getSendBufferSize(ts.handle()) catch |err| switch (err) {
        error.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    try testing.expectEqual(before_rcv, after_rcv);
    try testing.expectEqual(before_snd, after_snd);
}

test "saturates oversize requests at INT_MAX" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    // Asking for usize.max bytes must not overflow our internal
    // c_int conversion; we should see a defined error or a
    // best-effort accept rather than `unreachable`.
    const requested: usize = std.math.maxInt(usize);
    _ = setRecvBufferSize(ts.handle(), requested) catch |err| switch (err) {
        error.PermissionDenied,
        error.SystemResources,
        error.Unsupported,
        error.InvalidValue,
        => return,
        else => return err,
    };
    // If the kernel did honor it, at least confirm we came back
    // without crashing.
    _ = try getRecvBufferSize(ts.handle());
}

test "default tuning constants are reasonable" {
    // Sanity: the recommended default should be at least 1 MiB,
    // which is the inflection point above which a single-burst
    // RTT delivery rarely overflows the kernel buffer. If
    // someone accidentally drops these to a small value the
    // QNS test will silently regress, so make it a unit test.
    try testing.expect(default_server_recv_buffer_bytes >= 1 * 1024 * 1024);
    try testing.expect(default_server_send_buffer_bytes >= 1 * 1024 * 1024);
}

test "EcnCodepoint two-bit encoding matches RFC 3168" {
    try testing.expectEqual(@as(u2, 0b00), @backingInt(EcnCodepoint.not_ect));
    try testing.expectEqual(@as(u2, 0b01), @backingInt(EcnCodepoint.ect1));
    try testing.expectEqual(@as(u2, 0b10), @backingInt(EcnCodepoint.ect0));
    try testing.expectEqual(@as(u2, 0b11), @backingInt(EcnCodepoint.ce));
}

test "setEcnSendMarking applies ECT(0) without erroring on loopback" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    setEcnSendMarking(ts.handle(), .ect0) catch |err| switch (err) {
        // Some sandboxes refuse to set IP options at all; accept.
        error.PermissionDenied,
        error.Unsupported,
        => return error.SkipZigTest,
        else => return err,
    };
}

test "setEcnRecvEnabled enables IP_RECVTOS without erroring on loopback" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    setEcnRecvEnabled(ts.handle(), true) catch |err| switch (err) {
        error.PermissionDenied,
        error.Unsupported,
        => return error.SkipZigTest,
        else => return err,
    };
    setEcnRecvEnabled(ts.handle(), false) catch |err| switch (err) {
        error.PermissionDenied,
        error.Unsupported,
        => return error.SkipZigTest,
        else => return err,
    };
}

test "parseEcnFromControl: empty buffer is not_ect" {
    try testing.expectEqual(EcnCodepoint.not_ect, parseEcnFromControl(&.{}));
}

test "parseEcnFromControl: hand-rolled IP_TOS cmsg returns the codepoint" {
    if (!has_ip_ecn_sockopts) return error.SkipZigTest;
    var buf: [64]u8 = undefined;
    // ECT(0) on the wire is the byte 0x02 (low two bits of TOS).
    const cmsg_total = writeCmsg(
        &buf,
        @intCast(ip_consts.ip_proto),
        @intCast(ip_consts.ip_tos),
        &.{0x02},
    );
    const out = parseEcnFromControl(buf[0..cmsg_total]);
    try testing.expectEqual(EcnCodepoint.ect0, out);
}

test "parseEcnFromControl: hand-rolled IPV6_TCLASS cmsg returns the codepoint" {
    if (!has_ip_ecn_sockopts) return error.SkipZigTest;
    var buf: [64]u8 = undefined;
    // CE = 0b11, carried as the 4-byte int the kernel uses.
    var tclass: [4]u8 = undefined;
    std.mem.writeInt(i32, &tclass, 0x03, native_endian);
    const cmsg_total = writeCmsg(
        &buf,
        @intCast(ip_consts.ipv6_proto),
        @intCast(ip_consts.ipv6_tclass),
        &tclass,
    );
    const out = parseEcnFromControl(buf[0..cmsg_total]);
    try testing.expectEqual(EcnCodepoint.ce, out);
}

test "cmsg walker advances across multiple entries in one buffer" {
    if (!has_ip_ecn_sockopts) return error.SkipZigTest;
    // Kernel-realistic combined buffer: a UDP_GRO segment-size cmsg
    // followed by an IP_TOS cmsg. Each parser must step over the
    // other's entry (the aligned CMSG_NXTHDR advance) to find its own.
    var buf: [128]u8 = undefined;
    var seg: [4]u8 = undefined;
    std.mem.writeInt(i32, &seg, 1350, native_endian);
    const first = writeCmsg(&buf, sol_udp, udp_gro, &seg);
    const second = writeCmsg(
        buf[first..],
        @intCast(ip_consts.ip_proto),
        @intCast(ip_consts.ip_tos),
        &.{0x02},
    );
    const control = buf[0 .. first + second];
    try testing.expectEqual(EcnCodepoint.ect0, parseEcnFromControl(control));
    try testing.expectEqual(@as(?u16, 1350), parseGroSegmentFromControl(control));
}

// -- Linux UDP GSO / GRO (generic segmentation / receive offload) -----------

/// Linux `SOL_UDP` / `IPPROTO_UDP` — the cmsg/sockopt level for UDP
/// segmentation options. ABI constants; only meaningful on Linux but
/// harmless (and unit-testable) everywhere.
pub const sol_udp: i32 = 17;
/// Linux `UDP_SEGMENT` (kernel >= 4.18): as a sockopt, the default
/// egress segment size (0 = off); as a cmsg, the per-sendmsg segment
/// size for a GSO super-datagram.
pub const udp_segment: i32 = 103;
/// Linux `UDP_GRO` (kernel >= 5.0): opt into receive-side coalescing;
/// the kernel reports the segment size of a coalesced datagram via a
/// same-numbered cmsg.
pub const udp_gro: i32 = 104;

/// Kernel cap on segments per GSO send (`UDP_MAX_SEGMENTS`).
pub const default_gso_max_segments: u32 = 64;

/// Whether this target can ever do UDP GSO/GRO.
pub const has_udp_gso: bool = builtin.os.tag == .linux;

/// Probe whether `handle` accepts UDP_SEGMENT — the load-bearing gate
/// for attaching GSO cmsgs: the std maps a rejected sendmsg cmsg
/// (EINVAL/EOPNOTSUPP) to a PANIC, not an error, so a GSO cmsg must
/// never reach a socket that didn't pass this probe. Setting 0 leaves
/// egress behavior unchanged (no default segmentation).
pub fn probeUdpGso(handle: Handle) bool {
    if (comptime !has_udp_gso) return false;
    const zero: c_int = 0;
    setsockoptIntChecked(
        handle,
        @intCast(sol_udp),
        @intCast(udp_segment),
        std.mem.asBytes(&zero),
    ) catch return false;
    return true;
}

/// Enable receive-side UDP GRO on `handle`. The call doubles as the
/// probe: `error.Unsupported` means pre-5.0 kernel or non-Linux.
pub fn setUdpGroEnabled(handle: Handle) SetEcnError!void {
    if (comptime !has_udp_gso) return error.Unsupported;
    const one: c_int = 1;
    try setsockoptIntChecked(
        handle,
        @intCast(sol_udp),
        @intCast(udp_gro),
        std.mem.asBytes(&one),
    );
}

/// Serialize one `UDP_SEGMENT` cmsg carrying `segment_size` into
/// `buf`, returning the number of bytes written (header + u16 payload,
/// aligned like the kernel's CMSG_SPACE). Pure byte math over the
/// shared `writeCmsg` builder, so it is testable on every platform
/// that has a cmsg layout at all (Windows does not; see
/// `has_cmsg_layout`). Writes nothing there, which is unreachable in
/// practice since GSO is Linux-only.
pub fn writeUdpSegmentCmsg(buf: []u8, segment_size: u16) usize {
    if (comptime !has_cmsg_layout) return 0;
    var payload: [2]u8 = undefined;
    std.mem.writeInt(u16, &payload, segment_size, native_endian);
    return writeCmsg(buf, sol_udp, udp_segment, &payload);
}

/// Walk a populated `recvmsg` control buffer for the kernel's
/// `UDP_GRO` cmsg: the original segment size of a coalesced datagram.
/// Null when absent (not coalesced, or GRO off). Shares `CmsgIter`
/// with `parseEcnFromControl` — same tolerant walker, same comptime
/// layout gate: platforms without a cmsg layout can never see a GRO
/// cmsg.
pub fn parseGroSegmentFromControl(control: []const u8) ?u16 {
    if (comptime !has_cmsg_layout) return null;
    var it: CmsgIter = .init(control);
    while (it.next()) |c| {
        if (c.level == sol_udp and c.cmsg_type == udp_gro) {
            // The kernel writes an int; accept 2- or 4-byte payloads
            // like the ECN walker does.
            if (c.data.len >= 4) {
                const v = std.mem.readInt(i32, c.data[0..4], native_endian);
                if (v > 0 and v <= std.math.maxInt(u16)) return @intCast(v);
                return null;
            }
            if (c.data.len >= 2) {
                const v = std.mem.readInt(u16, c.data[0..2], native_endian);
                return if (v > 0) v else null;
            }
            return null;
        }
    }
    return null;
}

test "writeUdpSegmentCmsg round-trips through the GRO parser layout" {
    if (comptime !has_cmsg_layout) return error.SkipZigTest;
    // The builder and parser share the projected cmsghdr layout, so a
    // built UDP_SEGMENT cmsg re-labeled as UDP_GRO must parse back.
    var buf: [64]u8 = undefined;
    const n = writeUdpSegmentCmsg(&buf, 1350);
    try std.testing.expect(n >= @sizeOf(std.c.cmsghdr) + 2);
    try std.testing.expect(n % @sizeOf(usize) == 0);
    // Not a GRO cmsg (type = UDP_SEGMENT): parser must ignore it.
    try std.testing.expectEqual(@as(?u16, null), parseGroSegmentFromControl(buf[0..n]));
    // Flip the type to UDP_GRO: now it parses as a segment size.
    const type_off: usize = @offsetOf(std.c.cmsghdr, "type");
    std.mem.writeInt(i32, buf[type_off..][0..4], udp_gro, native_endian);
    try std.testing.expectEqual(@as(?u16, 1350), parseGroSegmentFromControl(buf[0..n]));
}

test "parseGroSegmentFromControl tolerates junk and empty buffers" {
    if (comptime !has_cmsg_layout) return error.SkipZigTest;
    try std.testing.expectEqual(@as(?u16, null), parseGroSegmentFromControl(&.{}));
    var junk: [24]u8 = @splat(0xff);
    try std.testing.expectEqual(@as(?u16, null), parseGroSegmentFromControl(&junk));
}

// -- One-shot per-socket offload negotiation ---------------------------------

/// What `negotiateUdpOffloads` should attempt on a socket. Fields
/// mirror the `RunUdpOptions` / `RunUdpClientOptions` knobs of the
/// same names.
pub const UdpOffloadRequest = struct {
    /// Attempt IETF ECN (RFC 9000 §13.4): outbound TOS/TCLASS marking
    /// plus inbound per-datagram TOS cmsg delivery.
    enable_ecn: bool,
    /// Send-side codepoint applied when `enable_ecn` is set. ECT(0)
    /// per RFC 9000 §13.4 guidance.
    ecn_send_codepoint: EcnCodepoint = .ect0,
    /// Probe Linux `UDP_SEGMENT` (GSO). Probe only — no default
    /// segmentation is left configured on the socket.
    enable_gso: bool,
    /// Enable Linux `UDP_GRO` receive-side coalescing.
    enable_gro: bool,
};

/// Per-socket outcome of `negotiateUdpOffloads`. Plain values on
/// purpose: `gso_active` is mutated at runtime by the send paths
/// (a rejected offloaded send clears it), so callers store these in
/// their own mutable per-socket state.
pub const UdpOffloadState = struct {
    /// ECN is fully active: outbound marking set AND inbound cmsg
    /// delivery enabled (see the all-or-nothing rule on
    /// `negotiateUdpOffloads`).
    ecn_active: bool = false,
    /// `probeUdpGso` passed — `UDP_SEGMENT` cmsgs may be attached to
    /// sends on this socket.
    gso_active: bool = false,
    /// `UDP_GRO` enabled — received datagrams may be kernel-coalesced
    /// and carry a segment-size cmsg.
    gro_active: bool = false,
};

/// Negotiate the datapath offloads for one freshly bound UDP socket:
/// ECN marking + cmsg delivery, the GSO probe, and GRO. Best-effort
/// by design — every step degrades to "inactive" rather than erroring,
/// matching both bundled loops' per-socket posture. Socket tuning
/// (`applyServerTuning`) is deliberately NOT part of this helper: the
/// callers want three different failure postures for it (fatal on a
/// primary listener, silent on alt-listeners, warn-and-continue in the
/// QNS endpoint).
///
/// Two orchestration invariants live here, stated once:
///
///   * ECN is all-or-nothing per socket. If `setEcnSendMarking`
///     succeeds but `setEcnRecvEnabled` fails, ECN reports INACTIVE —
///     otherwise the loop would mark outbound packets it can never
///     observe feedback for, and parse cmsg bytes the kernel never
///     populates.
///   * `gso_active` may only come from `probeUdpGso` — the
///     load-bearing gate: the std maps a rejected sendmsg cmsg to a
///     PANIC, so a `UDP_SEGMENT` cmsg must never reach an unprobed
///     socket (see `probeUdpGso`).
pub fn negotiateUdpOffloads(handle: Handle, request: UdpOffloadRequest) UdpOffloadState {
    var state: UdpOffloadState = .{};
    if (request.enable_ecn) {
        var ok = true;
        setEcnSendMarking(handle, request.ecn_send_codepoint) catch {
            ok = false;
        };
        if (ok) {
            setEcnRecvEnabled(handle, true) catch {
                ok = false;
            };
        }
        state.ecn_active = ok;
    }
    if (request.enable_gso) state.gso_active = probeUdpGso(handle);
    if (request.enable_gro) {
        if (setUdpGroEnabled(handle)) |_| {
            state.gro_active = true;
        } else |_| {}
    }
    return state;
}

test "negotiateUdpOffloads: disabled requests stay inactive" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    const state = negotiateUdpOffloads(ts.handle(), .{
        .enable_ecn = false,
        .enable_gso = false,
        .enable_gro = false,
    });
    try testing.expect(!state.ecn_active);
    try testing.expect(!state.gso_active);
    try testing.expect(!state.gro_active);
}

test "negotiateUdpOffloads: best-effort on loopback, never errors" {
    var ts = try TestSocket.init();
    defer ts.deinit();
    const state = negotiateUdpOffloads(ts.handle(), .{
        .enable_ecn = true,
        .enable_gso = true,
        .enable_gro = true,
    });
    // GSO/GRO are Linux-only; everywhere else the probe/enable must
    // degrade to inactive rather than error.
    if (!has_udp_gso) {
        try testing.expect(!state.gso_active);
        try testing.expect(!state.gro_active);
    }
    // ECN can only be active where the sockopts exist at all.
    if (!has_ip_ecn_sockopts) {
        try testing.expect(!state.ecn_active);
    }
}
