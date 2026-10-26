# Mixed BBR/CUBIC coexistence repair

This local change targets broader coexistence rather than reproducing the two
Sprint 4 release-control Jain scores. It retains stock Zig 0.17.0, Threaded,
the BBR default, public APIs, package version and all dependency pins. It is
an unpublished congestion-policy extension, with individual regressions below.

## Diagnosis

The first changed two-flow result is commit
`b0d7d7892690da62e259815226903a8c92c08328`, which corrected microsecond ACK timing.
Reverting ACK-delay encoding and scheduling precision together restores both
release-control byte counts. Encoding-only and scheduling-only controls do not
both reproduce that result. Release v0.42.2 and the intervening hardening commit
are identical on those cells. The BBR controller itself was unchanged.

The precision correction is valid: the old encoding could overreport elapsed ACK
delay by less than a millisecond. Correct timing changes congestion feedback;
matching the old scores by restoring that error would be the wrong repair.
Raw versus adjusted RTT semantics are described by
[RFC 9002 section 5.3](https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3).
Observer-only runs retain exact baseline per-flow bytes. At one second, the first
sampled differences are RTT and CUBIC pacing; later BBR model/phases diverge.
This observation does not establish an exact subsecond causal sequence.

Rejected controls include RTT eligibility, handshake clamping, pending-frame
scrubbing, receiver controller selection and CUBIC epoch preservation. Alternate
ACK policies, ProbeRTT app-limited marking and round-clock changes fail the
predeclared broader mean/worst controls. Using ordinary smoothed RTT as a window
floor improves mixed fairness but fills homogeneous BBR queues and adds drops.
Those candidates are retained as diagnostics and are not bundled into this fix.

## Policy

A completed ProbeRTT dwell can supply a fresh RTT budget for coexistence. Sampling
starts only after local flight has drained to ProbeRTT size. It excludes the
entry ACK and packets stamped before that point, requires positive new delivery
and a current finite RTT, and publishes only after the dwell and a new packet
round complete. Missing RTT clears the optional stash. Saturated delivery anchors
cannot prove freshness. Idle exits cannot publish an incomplete measurement.

In ProbeBW, a full-pipe, non-app-limited sender that filled its window at the most
recent transmit (which must be nonempty) can budget at least one bandwidth-delay product using
that completed RTT. Growth remains limited to newly ACKed bytes; existing
short-term, long-term, headroom and ProbeRTT caps still apply. The observation is
stable across ACK growth until another transmit. A new probe or persistent
congestion invalidates the old budget. Controller initialization clears it.

This is an explicit deviation from
[draft-ietf-ccwg-bbr-06](https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html),
not a claim of exact draft conformance. The RTT can include residual competing
queue and ACK delay even while our own flight is small. It is not proof of an
empty bottleneck or a new propagation-delay estimate. Pacing gains, minimum-RTT
filters and ACK policy remain unchanged.

## Bounded fairness acceptance

The fixed topology/order/start/window matrix has 14 cells: ten mixed, three
homogeneous BBR and one homogeneous CUBIC. Controls stated before the experiments
require improved mixed mean Jain, nonregressing worst mixed Jain, utilization at
least 0.95, progress in every flow, and homogeneous BBR Jain at least 0.98.
Homogeneous queue/drop costs are reviewed separately. Zero-loss fixed seeds are
not independent random-link trials. Jain is calculated from exact measured bytes.

Selected isolated policy result, compared with Sprint 4:

| Metric | Sprint 4 | Selected policy |
|---|---:|---:|
| Mixed mean Jain | 0.881883 | 0.909381 |
| Worst mixed Jain | 0.711944 | 0.804314 |
| Minimum utilization, all 14 | 0.966712 | 0.966712 |
| Minimum homogeneous BBR Jain | 0.995096 | 0.995096 |

Four mixed cases improve, four regress and two are unchanged. Material regressions
remain: the original deep-buffer case (0.823268 to 0.804314), reversed shallow
order (0.961104 to 0.957235), 10 ms base delay (0.905401 to 0.836396), and the
60-second window (0.984770 to 0.949459). The original shallow case improves from
0.923630 to 0.962496. These tradeoffs prevent a claim of universal fairness repair.
Two- and four-flow homogeneous BBR results are identical; the staggered case
retains Jain 0.998840. Their peak queues stay equal or decrease, with zero new
queue drops. All-run peaks do not establish steady-state tail latency.

The final-source qualification reruns the same matrix, compares every cell with
the held baseline, and preserves regressions rather than hiding them behind an
aggregate pass. The original six-cell benchmark and the broader matrix remain
distinct from real-network qualification. Local evidence is under
`benchmark-reports/fairness-repair-2026-10-26/`; the final index records source,
compiler, archive and raw-log hashes, actual gate outcomes and existing skips.

## Reproduction and downstream boundary

Use `tools/check-fairness.py --help` for the maintained 14-cell runner. Run it with
`mise exec -- python3 -B`, a fresh output directory, the exact baseline source,
and the local `ZIG_LOCAL_PKG_DIR`. The ordinary original-six check remains:

```sh
mise exec -- zig build bench-e2e -j2 -- --scenario fairness --samples 1 --json report.json
```

The qmsg and qmesh public QUIC pins still select v0.37.2, with its independently
known idle-cache assertion. Full-stack qualification selects a fresh local QUIC
archive by SHA256, checks every extracted source byte, and runs Sprint 2/3/4
composition in Debug and ReleaseSafe. Passing that selection does not change the
pins. The archive's retained version string does not identify its source.

This work authorizes no push, release, tag, publication or dependency-pin move.
Hosted CI, native Windows/Linux x86-64 execution and physical-network coexistence
remain separate blockers. The remaining per-workload fairness regressions need
broader network/latency evidence before any release decision.
