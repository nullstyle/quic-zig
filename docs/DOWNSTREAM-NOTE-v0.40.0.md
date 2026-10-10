# quic-zig v0.40.0: less tick work, and memory-window warnings

STATUS: RELEASED. All five CI gates verified. Ready for owner relay.

Tag v0.40.0 = 5796be0f8989a081bb563b96fcc6a856f43eb11d, 2026-10-10.
Package hash: quic-0.40.0-DnSYvSs1QADqzgHFcxff2HzBAezXWXpCJD2BCKJEemBu.

## What changed

- Tick skips the full stream cleanup walk when no stream has cleanup work.
  Debug keeps the walk and checks that no reclaim was missed. The send
  scheduler already used the sendable list; that was not the tick cost.
- Three quiet runs against v0.39.0, median us per stream:

| window | poll before / after | tick before / after |
|---|---:|---:|
| 4096 (3750 peak live) | 5.799 / 5.840 | 9.045 / 4.474 |
| 1024 (928 peak live) | 2.101 / 2.104 | 3.480 / 1.585 |

Tick falls about 51% and 54%. Poll stays within noise. All 31 impairment,
fairness, and churn virtual-time lines match the base tag byte-for-byte.
Connection memory stays about 21.2 KB per connection.

- Server.init and Client.connect warn when initial_max_data exceeds half
  max_connection_memory. Above half, the receive reserve reduces write
  capacity; at or above the whole budget, stream writes have zero space.
  Raise the budget or lower the announced window. Client adds optional
  Config.log_callback / log_user_data and Client.LogEvent / LogCallback.
  The Server uses its existing config_warning event. Warnings do not
  reject the config or change the transport parameters.
- isClosed documentation now matches its existing behavior: true from
  CONNECTION_CLOSE send or receive, including closing and draining. Use
  closeState to distinguish those states from terminal closure.
- The v0.39.0 changelog now uses the clean poll baseline (6.82 -> 5.73 us,
  16% less). The churn benchmark prints poll and tick us per stream.

## Pin and option map

    zig fetch --save https://github.com/nullstyle/quic-zig/archive/refs/tags/v0.40.0.tar.gz

Every embedder must use the same coordinated option map:

    b.dependency("quic", .{
        .target = target,
        .release = optimize != .debug,
        .@"sanitize-c" = @as([]const u8, "trap"),
    })

Take both quic and boringssl modules from that dependency. The map and
existing API signatures are unchanged. There is no forced move. Downstream
sessions move their own cluster when the owner chooses; no consumer checkout
or pin was changed by this sprint.

## Validation

Local: full Debug 2053/2069 tests and ReleaseSafe 2013/2029 (16 skipped in
each); final fast gates 36/36, Windows 15/15, x86-linux-musl 15/15. Named
steps pass. Stock Zig's I/O benchmark uses its documented
-Dbench-io-threaded-only switch; the fork's evented backends are not verified.
Four compiling mutants were rejected by their intended tests, including
missing cleanup in a busy connection over real TLS. Wide local interop was
not repeated: no scheduling, wire, congestion, or flow-control rule changed,
and the 31 virtual-time cells match exactly. The regular interop CI applies.

All five CI gates verified on the tag commit by 2026-10-10 18:38:21 UTC,
within 21 minutes of release. Evidence:

- [test 38075222309](https://github.com/nullstyle/quic-zig/actions/runs/38075222309):
  seven jobs succeeded. Unix Debug 2068/2084 and ReleaseSafe 2028/2044
  (16 skipped each); Windows Debug and ReleaseSafe each 2005/2044
  (39 skipped). Full sanitizer and 32-bit Linux musl suites passed.
  consumer-smoke ok: quic-zig 0.40.0; check-modes: 6 of 6 as expected.
- [rc-fuzz 38075224074](https://github.com/nullstyle/quic-zig/actions/runs/38075224074):
  2,637,540 instrumented executions across 43 sites, above the 1,935,000
  floor; pcs_len=47345, unique_runs=10,277. No failing inputs.
- [quic-go-interop 38075222415](https://github.com/nullstyle/quic-zig/actions/runs/38075222415):
  pairs=1 cells=2 succeeded=2; zero failed, known_failed, unsupported,
  skipped, or flaky cells.
- [QNS Image 38075222433](https://github.com/nullstyle/quic-zig/actions/runs/38075222433):
  image build succeeded. Publication is disabled (publish_image:false,
  push:false); this gate proves the build only.
- [pin-lint 38075222408](https://github.com/nullstyle/quic-zig/actions/runs/38075222408):
  pin-lint OK; Zig pins agree at 0.17.0.

## Delivery

The capnp-zig, http3-zig, mruby-quic, and cluster-A sessions identified in the
Claude handoff are not available through this chat's session-message tools.
This verified note is ready for the owner to relay to those sessions.

## Working location correction

The owner corrected the prior handoff: quic-zig work belongs in
/Users/nullstyle/prj/zig/quic-zig on main. Use a worktree only for parallel
efforts that can conflict, and merge back to main and the main working
directory after each sprint. This release was completed in the main checkout.
