# wanopt v0.2.0 release acceptance

Source: `ce3c7ce3207a21c918e0c50209b7693710a51006`. 240 fresh matrix transfers,32 separately attributed functional cases from the preceding cohort on identical binaries,12 fresh mixed cycles. Successful data transfers have complete length/SHA/status checks; expected rejections are recorded separately.

GET: pr5 -> pr4. POST: pr4 -> pr5. Added delay is calibrated from the native reused HTTP RTT. Loss/jitter/rate affect dedicated interfaces only. TCP in each namespace uses the original host congestion controller.

Native reused HTTP RTT: 24.84ms; additional delay 37.581ms on each dedicated egress. Native retains physical RTT with50Mbit/s capacity. Latency-only adds no loss/jitter and uses the same50Mbit/s capacity. Moderate uses50Mbit/s,0.1% loss and5ms jitter in each direction; severe adds20Mbit/s,1% loss and5ms jitter. Netem queue limit10000 packets; GSO disabled only for lab processes/interfaces. Each node's aggregate lab budget is one CPU/128MiB, no extra swap; one active matrix client mode at a time.

`tcp` is direct kernel TCP (BBR on both original hosts); `reno_raw` is the released default; `reno_adaptive` enables compression; `bbr_raw`/`bbr_adaptive` use the separate experimental package with compression off/on. Mbit/s is logical delivered goodput, so compressible text can exceed the wire rate. Random data is the incompressible control.

| Profile | Payload | Direction | Mode | Median Mbit/s | Min | Max | Ratio to TCP |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| native | text | GET | tcp | 47.11 | 47.07 | 47.13 | 1.00x |
| native | text | GET | reno_raw | 47.50 | 47.49 | 47.52 | 1.01x |
| native | text | GET | reno_adaptive | 288.67 | 287.89 | 288.87 | 6.13x |
| native | text | GET | bbr_raw | 46.88 | 46.46 | 46.90 | 1.00x |
| native | text | GET | bbr_adaptive | 263.91 | 261.80 | 264.31 | 5.60x |
| native | text | POST | tcp | 47.04 | 46.69 | 47.11 | 1.00x |
| native | text | POST | reno_raw | 47.30 | 47.30 | 47.31 | 1.01x |
| native | text | POST | reno_adaptive | 277.32 | 257.83 | 277.79 | 5.90x |
| native | text | POST | bbr_raw | 46.70 | 46.67 | 46.71 | 0.99x |
| native | text | POST | bbr_adaptive | 272.63 | 267.68 | 273.37 | 5.80x |
| native | random | GET | tcp | 47.06 | 47.05 | 47.06 | 1.00x |
| native | random | GET | reno_raw | 47.49 | 47.28 | 47.52 | 1.01x |
| native | random | GET | reno_adaptive | 47.31 | 47.29 | 47.51 | 1.01x |
| native | random | GET | bbr_raw | 46.80 | 46.78 | 46.83 | 0.99x |
| native | random | GET | bbr_adaptive | 46.76 | 46.35 | 46.84 | 0.99x |
| native | random | POST | tcp | 47.11 | 46.95 | 47.11 | 1.00x |
| native | random | POST | reno_raw | 47.31 | 47.27 | 47.31 | 1.00x |
| native | random | POST | reno_adaptive | 47.30 | 47.30 | 47.30 | 1.00x |
| native | random | POST | bbr_raw | 46.69 | 46.66 | 46.70 | 0.99x |
| native | random | POST | bbr_adaptive | 46.70 | 46.68 | 46.70 | 0.99x |
| latency | text | GET | tcp | 46.66 | 46.38 | 46.71 | 1.00x |
| latency | text | GET | reno_raw | 47.32 | 47.31 | 47.32 | 1.01x |
| latency | text | GET | reno_adaptive | 285.32 | 280.67 | 285.33 | 6.11x |
| latency | text | GET | bbr_raw | 46.44 | 45.96 | 46.46 | 1.00x |
| latency | text | GET | bbr_adaptive | 253.07 | 247.05 | 256.87 | 5.42x |
| latency | text | POST | tcp | 46.72 | 46.70 | 46.72 | 1.00x |
| latency | text | POST | reno_raw | 47.10 | 47.10 | 47.11 | 1.01x |
| latency | text | POST | reno_adaptive | 236.23 | 233.81 | 259.17 | 5.06x |
| latency | text | POST | bbr_raw | 46.25 | 46.25 | 46.27 | 0.99x |
| latency | text | POST | bbr_adaptive | 265.77 | 258.48 | 266.79 | 5.69x |
| latency | random | GET | tcp | 46.68 | 46.68 | 46.70 | 1.00x |
| latency | random | GET | reno_raw | 47.30 | 47.30 | 47.31 | 1.01x |
| latency | random | GET | reno_adaptive | 47.29 | 47.26 | 47.31 | 1.01x |
| latency | random | GET | bbr_raw | 46.23 | 46.19 | 46.49 | 0.99x |
| latency | random | GET | bbr_adaptive | 46.40 | 45.69 | 46.43 | 0.99x |
| latency | random | POST | tcp | 46.57 | 46.43 | 46.59 | 1.00x |
| latency | random | POST | reno_raw | 47.10 | 47.10 | 47.11 | 1.01x |
| latency | random | POST | reno_adaptive | 47.08 | 47.08 | 47.08 | 1.01x |
| latency | random | POST | bbr_raw | 46.27 | 46.26 | 46.28 | 0.99x |
| latency | random | POST | bbr_adaptive | 46.26 | 46.25 | 46.27 | 0.99x |
| moderate | text | GET | tcp | 46.54 | 46.24 | 46.63 | 1.00x |
| moderate | text | GET | reno_raw | 6.50 | 5.11 | 8.19 | 0.14x |
| moderate | text | GET | reno_adaptive | 61.37 | 55.36 | 65.75 | 1.32x |
| moderate | text | GET | bbr_raw | 46.36 | 46.07 | 46.37 | 1.00x |
| moderate | text | GET | bbr_adaptive | 264.89 | 256.70 | 265.80 | 5.69x |
| moderate | text | POST | tcp | 46.63 | 46.34 | 46.68 | 1.00x |
| moderate | text | POST | reno_raw | 5.64 | 5.36 | 8.19 | 0.12x |
| moderate | text | POST | reno_adaptive | 38.77 | 33.30 | 58.84 | 0.83x |
| moderate | text | POST | bbr_raw | 45.99 | 45.87 | 46.13 | 0.99x |
| moderate | text | POST | bbr_adaptive | 256.12 | 253.89 | 258.51 | 5.49x |
| moderate | random | GET | tcp | 46.57 | 46.45 | 46.65 | 1.00x |
| moderate | random | GET | reno_raw | 6.35 | 6.00 | 7.62 | 0.14x |
| moderate | random | GET | reno_adaptive | 7.68 | 5.68 | 10.41 | 0.16x |
| moderate | random | GET | bbr_raw | 46.12 | 45.85 | 46.33 | 0.99x |
| moderate | random | GET | bbr_adaptive | 45.76 | 45.05 | 46.28 | 0.98x |
| moderate | random | POST | tcp | 46.69 | 46.68 | 46.73 | 1.00x |
| moderate | random | POST | reno_raw | 6.63 | 6.59 | 7.82 | 0.14x |
| moderate | random | POST | reno_adaptive | 6.87 | 6.14 | 9.72 | 0.15x |
| moderate | random | POST | bbr_raw | 45.78 | 45.59 | 46.11 | 0.98x |
| moderate | random | POST | bbr_adaptive | 45.91 | 45.76 | 46.17 | 0.98x |
| severe | text | GET | tcp | 18.33 | 18.04 | 18.35 | 1.00x |
| severe | text | GET | reno_raw | 1.83 | 1.79 | 1.86 | 0.10x |
| severe | text | GET | reno_adaptive | 12.25 | 10.63 | 14.77 | 0.67x |
| severe | text | GET | bbr_raw | 18.22 | 17.99 | 18.24 | 0.99x |
| severe | text | GET | bbr_adaptive | 111.19 | 109.44 | 112.61 | 6.07x |
| severe | text | POST | tcp | 18.09 | 18.08 | 18.14 | 1.00x |
| severe | text | POST | reno_raw | 1.74 | 1.64 | 1.81 | 0.10x |
| severe | text | POST | reno_adaptive | 9.56 | 8.95 | 13.46 | 0.53x |
| severe | text | POST | bbr_raw | 18.15 | 18.09 | 18.19 | 1.00x |
| severe | text | POST | bbr_adaptive | 107.94 | 103.73 | 108.05 | 5.97x |
| severe | random | GET | tcp | 18.32 | 17.54 | 18.36 | 1.00x |
| severe | random | GET | reno_raw | 1.80 | 1.54 | 1.82 | 0.10x |
| severe | random | GET | reno_adaptive | 1.82 | 1.52 | 1.90 | 0.10x |
| severe | random | GET | bbr_raw | 18.15 | 17.82 | 18.25 | 0.99x |
| severe | random | GET | bbr_adaptive | 18.27 | 18.26 | 18.33 | 1.00x |
| severe | random | POST | tcp | 18.17 | 18.15 | 18.30 | 1.00x |
| severe | random | POST | reno_raw | 1.78 | 1.73 | 1.98 | 0.10x |
| severe | random | POST | reno_adaptive | 1.73 | 1.67 | 1.92 | 0.10x |
| severe | random | POST | bbr_raw | 18.16 | 18.10 | 18.25 | 1.00x |
| severe | random | POST | bbr_adaptive | 18.16 | 17.90 | 18.18 | 1.00x |

## Mixed load observations

Random payloads, simultaneous direct TCP and BBR/adaptive; medians across six cycles per profile/direction. Both share the same node execution envelope. These are observations, not a general fairness guarantee.

| Profile | Direction | Competing TCP Mbit/s | Competing BBR/adaptive Mbit/s |
| --- | --- | ---: | ---: |
| moderate | GET | 23.96 | 19.15 |
| moderate | POST | 24.80 | 17.48 |
| severe | GET | 9.14 | 8.27 |
| severe | POST | 9.05 | 8.43 |

Each latency cell is the median of six per-run quantiles, not a pooled quantile. Idle generators run5s and loaded generators10s. Results describe this path/CPU envelope, not universal fairness or priority.

| Profile | Direction | Idle p95 ms | Loaded p95 ms | Loaded p99 ms | p95 ratio |
| --- | --- | ---: | ---: | ---: | ---: |
| moderate | GET | 107.87 | 210.01 | 323.36 | 1.95x |
| moderate | POST | 108.80 | 222.68 | 361.00 | 2.05x |
| severe | GET | 108.99 | 190.88 | 250.25 | 1.75x |
| severe | POST | 108.56 | 166.20 | 238.28 | 1.53x |

## CI queue calibration

Expanded validation CI39441638174 retained strict zero critical UDP errors across positive suites, including endpoint shutdown. An earlier unbounded veth no-loss-delay profile overflowed its10000-packet netem queue: the reproduced interactive GET failure had738 drops exactly matching738 SndbufErrors. The original1137 cumulative events lacked queue/phase snapshots and are not retroactively claimed as traced.

CI now defines its no-loss control as100Mbit/s without loss/jitter, with the same10000-packet limit and an additional zero-qdisc-drop assertion. The final physical pr4/pr5 native, latency-only and moderate profiles use50Mbit/s; severe uses20Mbit/s. Earlier100Mbit/s and uncapped cohorts were stopped by strict shared-host allowance guards and are retained separately. A separate warmed raw UDP probe deliberately uses a one-packet queue and requires matching drops/SndbufErrors; its counters and cleanup are separate from the positive/runtime baseline. Failed probes, the local999/999 calibration and final successful runner evidence are retained in the acceptance archive and ci-sndbuf-resolution.json. No runtime, host sysctl, socket buffer or larger-queue workaround was introduced.


Each matrix invocation uses one finite1MiB warmup and a new HTTP benchmark transport. Each proxy invocation also starts a fresh client process/QUIC tunnel; only that mode runs. Server processes persist. Mixed cycles retain one client, with a second client only for explicit overload. Planned transitions and each retired client reconnect check are recorded. This is an end-to-end proxy comparison, not an isolated congestion-controller microbenchmark.
Goodput uses complete delivered bytes divided by full generation-plus-drain time; warmup reported separately.
Matrix wall time: 8230.1s, including control/drain gaps; the180 native/latency/moderate invocations requested16s generation and60 severe invocations requested8s. The12 mixed cycles span 1016.6s, with24 groups requesting10s generation each plus overload/control gaps. These are bounded runs, not claims of continuous multi-hour traffic.

From fresh namespace creation through final idle and observer collection, all observed namespace buffer/input/checksum/memory error deltas were zero, including planned client replacements. Final server teardown follows observer collection; CI separately asserts counters through endpoint shutdown. NoPorts across planned client replacements/functional closes are retained separately in acceptance.json; they are not socket buffer errors. Memory stayed within128MiB, with no cgroup max/OOM events; idle leases and goroutines recovered. Every retired matrix client was alive and had zero unexpected reconnects; server PIDs and the persistent mixed client stayed unchanged. See summary.json and raw data for exact bounds.

The128MiB limit and peaks describe the execution cgroup. They are not a total host-memory accounting; setup/SSH/tmpfs/cache charges can be outside that group. Host MemAvailable and root-disk reserve were observed independently, with minimum values in summary.json.

An earlier attempt kept four proxy copies in the same128MiB group and hit a lab memcg OOM after104 successful matrix transfers. Its complete negative data, kernel cause and successful cleanup audit were retained. The final repeat used one active matrix mode within the unchanged128MiB budget; binaries were not rebuilt and failed data were not counted as passes.

Both original Docker identities/start times, monitoring/VPN PIDs, host qdisc and host TCP CC were preserved. Owned processes,namespace,veth,exact rules,units,timer,slice and runtime credentials were removed and independently audited.

BBR remains opt-in. Incompressible/clean/CPU-bound paths can regress. Physical mobile migration,provider conditions outside this bounded campaign and multi-day stability are not proven.

The32 functional cases are completed evidence from capped-acceptance-20261020-v2 on the identical release binaries, at100Mbit/s, before its later shared-host allowance guard. They were not rerun in this50Mbit/s cohort; per-row provenance and original SHA256 are retained. Matrix/mixed/overload results are fresh. An earlier100Mbit/s moderate-profile experimental BBR GET did not complete within120s; later bounded repeats and CI passed, but its precise cause remains unresolved. This limits experimental BBR qualification and is not represented as a runtime fix.


## Reproduction and complete case records

- [Complete planned and executed cases](benchmark-data/release-v0.2.0-20261020/case-plan.json), including named Actions subtests, expected failures and explicitly deferred physical conditions.
- [Real-channel-only cases](benchmark-data/release-v0.2.0-20261020/real-channel-case-plan.json).
- [Full summary](benchmark-data/release-v0.2.0-20261020/summary.json), [all medians/min/max](benchmark-data/release-v0.2.0-20261020/throughput.csv), [exact package/binary source manifest](benchmark-data/release-v0.2.0-20261020/source-manifest.json), [cleanup decisions](benchmark-data/release-v0.2.0-20261020/cleanup-audit.json).
- [Mixed competition](benchmark-data/release-v0.2.0-20261020/mixed-fairness.csv), [interactive latency](benchmark-data/release-v0.2.0-20261020/interactive-latency.csv), [runtime-source equivalence](benchmark-data/release-v0.2.0-20261020/runtime-source-equivalence.json), [CI queue-error cause and validation](benchmark-data/release-v0.2.0-20261020/ci-sndbuf-resolution.json).
- Immutable release archives, raw measurements, resource observations and evidence checksums are attached to [v0.2.0](https://github.com/nd4y/wanopt-proxy/releases/tag/v0.2.0). The acceptance archive includes every raw measurement and the complete executed-case ledger; original binary SHA256SUMS are retained separately.

The first lab setup failed before load because the helper had assigned only the private key, not the0600 certificate, to the test UID. It was automatically removed and independently audited, then only the helper ownership was corrected. The same release files were used throughout; no failed data were relabeled as successful. Earlier CI harness failures and their correction remain in [the plan ledger](test-plan.md).
