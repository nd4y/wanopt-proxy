# QUIC BBR on pr4/pr5, 2026-10-18

These are historical measurements from the earlier implementation. The [global-limit/adaptive-compression campaign](hardening-pr4-pr5.md) uses prebuilt fixtures, longer flows and updated failure/cleanup checks. Its results and explicit configuration supersede this report for the current branch.

BBR with the existing optional block compression improved useful throughput in both directions on the two lossy profiles. It did not achieve universal acceleration: uncapped uploads with no configured loss remained slower than direct TCP, and raw BBR had regressions. Keep the normal Reno build as the default; BBR is an isolated, opt-in experiment.

## Implementation

The [reproducible experiment](../experiments/bbr/README.md) applies Hysteria's standard BBR controller to upstream quic-go 0.64.0 through a small ACK/loss adapter and a per-connection factory. It preserves upstream transport fixes, creates new state on path migration, and does not replace a live controller concurrently. Both endpoints used the standard profile. No codec or wire-format change was retained. A faster DEFLATE decoder improved a local benchmark but not the WAN pilot materially, so it was reverted.

## Method

- Public WAN between pr4 (client) and pr5 (origin/server), separate network namespaces and peer-restricted firewall entries. Direct TCP already uses kernel BBR on both hosts.
- Dedicated veth interfaces only: 38 ms added delay at each sender, giving a measured small HTTP round trip of **100.51 ms**. No host qdisc was changed. GSO/GRO/TSO disabled on the test interfaces and QUIC GSO disabled to avoid netem segmentation artifacts.
- Profiles: `latency` has no configured loss or rate limit; `moderate` adds 5 ms jitter, 0.1% independent loss and 100 Mbit/s in each direction; `severe` adds 5 ms jitter, 1% loss and 20 Mbit/s. Jitter may reorder packets, so these are combined impairment tests, not pure loss sensitivity.
- Equal test slice limits: one CPU core on each two-core host, low CPU weight 10, 128 MiB memory, no swap. GOMAXPROCS=1. Nonroot processes with no capabilities and a read-only host filesystem. The host memory guard checked for at least 96 MiB available before each test unit launch.
- Four modes: direct TCP BBR; QUIC Reno with compression; QUIC BBR raw; QUIC BBR with compression. The BBR profile includes its own initial 32-packet window. This is not an equal-initial-window algorithm comparison.
- `main`: three repeats, both directions, varied JSON log text, deterministic random data, and gzip of that text. Input is 4 MiB for latency/moderate and 1 MiB for severe; gzip transfers fewer actual bytes. Modes reverse order on alternating repeats. No samples were discarded.
- `warm`: a complete same-size transfer runs before the measured text transfer. HTTP connection reuse and absence of response-close were explicitly checked. Each benchmark process starts a new TCP connection; QUIC tunnels persist within each profile. Main results therefore must not be interpreted as identical cold-start comparisons.
- An additional, separately labelled 8 MiB warm-text control tests the uncapped profile. It does not replace the primary 4 MiB results.
- Numbers are median **application payload Mbit/s**, three observations per cell. GET includes origin fixture generation and hashing; POST prepares the client fixture before timing. Compare modes within a direction, not GET vs POST as pure link capacity. SHA-256, byte count and HTTP status validate every transfer. Compression can give useful throughput above the configured wire rate.
- `wire_tx_bytes` / `wire_rx_bytes` cover the full benchmark invocation, including ping and any warmup. CPU counters cover the entire test slice during that invocation. They are not timed-payload-only metrics.

## Warm text: decision table

| Profile | Direction | TCP BBR | BBR + compression | Ratio to TCP |
| --- | --- | ---: | ---: | ---: |
| ~100 ms, uncapped, no added loss, 4 MiB | pr4 -> pr5 | 195.31 | 154.27 | 0.79x |
| same | pr5 -> pr4 | 88.01 | 140.75 | 1.60x |
| ~100 ms, 100 Mbit/s, 0.1% loss, 4 MiB | pr4 -> pr5 | 73.27 | 136.87 | 1.87x |
| same | pr5 -> pr4 | 63.63 | 106.02 | 1.67x |
| ~100 ms, 20 Mbit/s, 1% loss, 1 MiB | pr4 -> pr5 | 15.44 | 30.67 | 1.99x |
| same | pr5 -> pr4 | 13.50 | 30.38 | 2.25x |

The severe-profile Reno-with-compression medians were 7.77 Mbit/s pr4 -> pr5 and 18.54 Mbit/s pr5 -> pr4. BBR improved this measured case in both directions, but the three random-loss repetitions are too few to establish a confidence interval. Moderate-profile improvements over Reno were smaller (131.79 -> 136.87 and 97.58 -> 106.02), so do not overstate those differences.

The 8 MiB control still lost on upload: TCP 382.16 vs BBR+compression 230.98 Mbit/s. Download was 173.20 vs 180.81. Five of its 24 invocations encountered client-slice CPU throttling (maximum 88.8 ms across the entire invocation); none of the 288 primary invocations did. The common CPU cap was kept to protect the other services. These results are resource-constrained application measurements, not maximum unconstrained transport rates.

## Stability, cleanup and limits

- 312 measured matrix transfers passed integrity, HTTP reuse and response checks. Another 12 checksum-validated transfers passed in three four-transfer concurrent groups under the severe profile.
- Five controlled restarts of only the test BBR server were followed by one GET and one POST each under the moderate profile. All ten checks succeeded on the first probe attempt, within 0.90 seconds including data transfer after service start. This does not promise preservation of in-flight application sessions.
- Final peak test-slice memory: 87,252,992 bytes on pr4 and 90,157,056 on pr5 (about 83.2/86.0 MiB). No memory-limit, OOM or OOM-kill events. UDP receive/send-buffer and checksum error counters stayed zero. UDP `NoPorts` was nonzero across the full experiment, including intentional server stops; it is not hidden as zero packet loss.
- The exact packaged patch recipe passed transport/application race tests, application vet and govulncheck. The vulnerability scan reported zero reachable vulnerabilities; it also reported ten findings in required modules that are not in the application call graph. Windows application tests passed. CI separately tests the normal build and the experimental recipe.
- Deleted the test units, slice overrides, timer, namespaces, veth interfaces, exact test firewall entries, binaries, certificates, keys and configs from both hosts. Verified production container IDs and start timestamps, host qdiscs, Alloy and NetBird PIDs against baseline; all unchanged. No production wanopt replacement or PR merge occurred.
- Independent capacity warning: pr4 ended with 390,860,800 bytes free on its unchanged 8 GiB EBS. Its existing monitoring storage check reports free space below reserve and explicitly does not delete data. The lab was stored in `/run` and removed; monitoring queue/retention and other services were not modified. Prior context already records an unresolved monitoring delivery problem; its current cause was not re-diagnosed by this benchmark.

This is a bounded functional and performance test. Long production soak, fairness under competing traffic, mobile path migration and physical MTU changes remain unverified. BBR alone is not a general solution for encrypted or incompressible traffic. Keep compression opt-in and use the measurements for the actual workload before selecting this build.

[Raw stability checks](benchmark-data/bbr-stability.json).

## Complete results

### latency-main.jsonl

| Payload | Direction | TCP BBR | Reno + compression | QUIC BBR raw | BBR + compression |
| --- | --- | ---: | ---: | ---: | ---: |
| gzip | pr5 -> pr4 | 5.79 | 24.85 | 17.77 | 16.48 |
| gzip | pr4 -> pr5 | 7.76 | 42.88 | 16.03 | 22.21 |
| random | pr5 -> pr4 | 24.55 | 131.45 | 79.99 | 73.59 |
| random | pr4 -> pr5 | 35.50 | 127.01 | 92.31 | 89.50 |
| text | pr5 -> pr4 | 23.65 | 147.74 | 61.24 | 153.77 |
| text | pr4 -> pr5 | 35.79 | 130.55 | 90.25 | 86.14 |

[Raw measurements](benchmark-data/bbr-latency-main.jsonl).

### latency-warm.jsonl

| Payload | Direction | TCP BBR | Reno + compression | QUIC BBR raw | BBR + compression |
| --- | --- | ---: | ---: | ---: | ---: |
| text | pr5 -> pr4 | 88.01 | 144.60 | 129.09 | 140.75 |
| text | pr4 -> pr5 | 195.31 | 149.65 | 132.21 | 154.27 |

[Raw measurements](benchmark-data/bbr-latency-warm.jsonl).

### moderate-main.jsonl

| Payload | Direction | TCP BBR | Reno + compression | QUIC BBR raw | BBR + compression |
| --- | --- | ---: | ---: | ---: | ---: |
| gzip | pr5 -> pr4 | 5.52 | 4.35 | 20.44 | 17.03 |
| gzip | pr4 -> pr5 | 7.55 | 4.70 | 20.97 | 31.90 |
| random | pr5 -> pr4 | 23.57 | 7.75 | 57.62 | 45.95 |
| random | pr4 -> pr5 | 31.23 | 5.26 | 71.41 | 61.42 |
| text | pr5 -> pr4 | 22.40 | 39.60 | 53.20 | 133.07 |
| text | pr4 -> pr5 | 31.72 | 26.86 | 61.03 | 121.32 |

[Raw measurements](benchmark-data/bbr-moderate-main.jsonl).

### moderate-warm.jsonl

| Payload | Direction | TCP BBR | Reno + compression | QUIC BBR raw | BBR + compression |
| --- | --- | ---: | ---: | ---: | ---: |
| text | pr5 -> pr4 | 63.63 | 97.58 | 59.35 | 106.02 |
| text | pr4 -> pr5 | 73.27 | 131.79 | 66.35 | 136.87 |

[Raw measurements](benchmark-data/bbr-moderate-warm.jsonl).

### severe-main.jsonl

| Payload | Direction | TCP BBR | Reno + compression | QUIC BBR raw | BBR + compression |
| --- | --- | ---: | ---: | ---: | ---: |
| gzip | pr5 -> pr4 | 2.27 | 1.36 | 4.78 | 4.27 |
| gzip | pr4 -> pr5 | 2.73 | 1.84 | 5.25 | 6.25 |
| random | pr5 -> pr4 | 7.44 | 1.63 | 13.09 | 12.56 |
| random | pr4 -> pr5 | 7.13 | 2.80 | 14.20 | 11.21 |
| text | pr5 -> pr4 | 6.65 | 9.74 | 10.89 | 25.80 |
| text | pr4 -> pr5 | 8.46 | 19.47 | 12.38 | 31.57 |

[Raw measurements](benchmark-data/bbr-severe-main.jsonl).

### severe-warm.jsonl

| Payload | Direction | TCP BBR | Reno + compression | QUIC BBR raw | BBR + compression |
| --- | --- | ---: | ---: | ---: | ---: |
| text | pr5 -> pr4 | 13.50 | 18.54 | 14.31 | 30.38 |
| text | pr4 -> pr5 | 15.44 | 7.77 | 13.78 | 30.67 |

[Raw measurements](benchmark-data/bbr-severe-warm.jsonl).

### latency-8mib-warm.jsonl

| Payload | Direction | TCP BBR | Reno + compression | QUIC BBR raw | BBR + compression |
| --- | --- | ---: | ---: | ---: | ---: |
| text | pr5 -> pr4 | 173.20 | 175.62 | 156.70 | 180.81 |
| text | pr4 -> pr5 | 382.16 | 276.80 | 168.36 | 230.98 |

[Raw measurements](benchmark-data/bbr-latency-8mib-warm.jsonl).
