# Global limits and adaptive compression on pr4/pr5

The isolated campaign covered 6.004 elapsed hours, including fault injection, idle periods and mixed load. All 354 persisted benchmark invocations completed their integrity checks; expected overload and revoked-credential failures are recorded separately in the 32 functional checks. There were 90 warmed batches of ten requests and 108 continuous 60-second flows (three per cell). Persisted observations are retained; a generator session without a recorded completion is not counted as a measured sample.

The local controller sessions were interrupted 2 times, for about 79 minutes in total. Test processes stayed running with unchanged PIDs and no cumulative OOM events; most of these intervals were idle. The controller resumed from saved measurements without restarting the lab; its final launch uses a temporary hidden Windows task that removes itself after completion. Host guard observations and detailed heap samples are missing during these intervals, while cgroup limits and the independent cleanup timer remained active. This is a six-hour campaign, not six uninterrupted hours of generated load. [Timeline and interruptions](benchmark-data/hardening-20261018/campaign.json). The two intervals between guard samples span 80.4 minutes including normal polling margins; [exact observations](benchmark-data/hardening-20261018/guard-observation-gaps.json) are retained.

## Scope and method

Source base `88fbe38901713ff2975870f89b33e20de86c258d` includes global active/codec budgets, adaptive compression, bounded telemetry, PSK/pin overlap and server credential reload, fail-fast HTTP 503 admission and accept-based authentication expiry. The optional BBR recipe adds the outstanding-history and MTU-decrease fixes. Stable default remains upstream quic-go 0.64.0 with Reno; compression stays opt-in. See [operations](operations.md) and [BBR recipe](../experiments/bbr/README.md).

Public WAN pr4/client to pr5/origin, dedicated namespaces/veth and peer-restricted test firewall rules only. Direct TCP uses kernel BBR. Each sender adds 38 ms on its test veth, for about 100 ms RTT including the native link. `latency`: no configured loss/rate; `moderate`: 100 Mbit/s, 5 ms jitter and 0.1% independent loss; `severe`: 20 Mbit/s, 5 ms jitter and 1% loss. Jitter can reorder packets. GSO/GRO/TSO disabled on test veth only; QUIC GSO disabled. Production qdiscs and network services were not changed.

Both test slices have one CPU, low CPU weight 10, 128 MiB memory and no extra swap. Each Go process has GOMAXPROCS=1 and a 64 MiB soft heap target. Admission is eight active streams and two compressed streams, in addition to per-connection/pending limits; HTTP idle timeout 15 seconds. Executable files in /run can consume host memory outside the measured slice, so the connected controller checks host available memory >96 MiB and root free space >128 MiB every 30 seconds. The unchanged pr4 disk remains 8 GiB. Limits protect the shared nodes and can constrain achievable throughput.

Fixtures are prepared and hashed before requests. Text is varied synthetic JSON logs with random request IDs; random data is deterministic and incompressible; gzip is the compressed text and transfers fewer actual bytes than its logical source size. Each request validates HTTP status, SHA256 and actual byte count. No HTTPS plaintext is exposed. Each measured invocation uses a new benchmark client; HTTP connections are warmed and reused inside it. QUIC control tunnels persist, so setup times are not an equal cold-start transport comparison.

The warmed matrix compares direct TCP, previous Reno baseline `5c3d1ff`, new Reno, new raw BBR and new BBR with adaptive compression. It performs ten 1 MiB-source requests per batch. The continuous matrix compares direct TCP, new Reno and compressed BBR using text/random in both directions, three randomized 60-second flows per cell. Bodies repeat a prebuilt block without growing memory; GET verifies final trailers, POST verifies origin count/hash and upload EOF. Reported application Mbit/s includes final delivery and verification and can exceed wire rate through compression.

Namespace wire counters and slice CPU deltas include setup, warmup and small background lab heartbeats, not only the timed body. Raw data retain throttling, latency samples and all regressions. Request p95/p99 use a bounded 4096-sample reservoir per worker and are approximate after that limit; ten-request batches cannot establish reliable population tails.

## Continuous useful throughput

Median application Mbit/s, three flows per cell. Full ranges and individual outcomes remain in the [raw measurements](benchmark-data/hardening-20261018/measurements.jsonl).

| Profile | Payload | Direction | TCP BBR | Reno + adaptive | QUIC BBR + adaptive | BBR/TCP |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| latency | text | pr4 -> pr5 | 748.77 | 199.04 | 349.52 | 0.47x |
| latency | text | pr5 -> pr4 | 709.63 | 198.40 | 383.81 | 0.54x |
| latency | random | pr4 -> pr5 | 743.02 | 80.33 | 250.07 | 0.34x |
| latency | random | pr5 -> pr4 | 700.29 | 35.86 | 273.33 | 0.39x |
| moderate | text | pr4 -> pr5 | 92.76 | 36.77 | 338.34 | 3.65x |
| moderate | text | pr5 -> pr4 | 92.49 | 38.35 | 340.32 | 3.68x |
| moderate | random | pr4 -> pr5 | 92.82 | 5.66 | 88.22 | 0.95x |
| moderate | random | pr5 -> pr4 | 92.61 | 5.46 | 90.40 | 0.98x |
| severe | text | pr4 -> pr5 | 18.53 | 11.41 | 106.30 | 5.74x |
| severe | text | pr5 -> pr4 | 18.48 | 10.14 | 112.51 | 6.09x |
| severe | random | pr4 -> pr5 | 18.54 | 1.84 | 18.12 | 0.98x |
| severe | random | pr5 -> pr4 | 18.47 | 1.79 | 18.04 | 0.98x |

## Stability and recovery

All 32 functional cases passed: malformed/FIFO/runtime-changing SIGHUP rejected without changing the live server; live certificate replacement and old/new PSK overlap; next pin on a new handshake; explicit old-key revocation and expiry closing existing sessions; primary session survival; slow GET/POST; cancellation and full transfer recovery; global overload rejection and recovery; fresh MTU 1280 GET/POST; four seconds of complete test-link loss and subsequent POST; five test-server restarts with GET/POST recovery after each. Application sessions are not promised to survive a tunnel restart.

The imported BBR initially panicked on a legitimate Initial-datagram reduction 1280 -> 1200 after EMSGSIZE. That failure is retained in the local audit; the fix rescales/clamps windows and updates pacing for positive MTU decreases, with a regression test and the successful WAN checks above. Authentication expiry also gained a regression against transport keepalives and unauthenticated HTTP/3 requests holding a connection slot indefinitely. Codec fallback, half-close lease retention, quota release, cross-connection admission, bounded labels and adaptive incompressible-to-text resumption have automated tests.

The initial continuous Reno/random download at 1% loss hit a 90 s benchmark deadline. A diagnostic repeat kept making progress and delivered 22 MiB with valid SHA256 in 98.63 s; socket samples showed more than 6 MiB still queued on the loopback origin after generation. This was a drain-time budget error, not an established wanopt deadlock. The final matrix retains complete delivery time and uses a bounded 5-minute request deadline. The fixture server's former 120-second body deadline also incorrectly coincided with its allowed maximum 120-second generation duration; that test-driver limit is now five minutes. [Initial failed observation](benchmark-data/hardening-20261018/initial-timeout.json), [successful diagnosis](benchmark-data/hardening-20261018/drain-diagnosis.json).

Mixed cycles exercise concurrent bulk/one-byte requests, competing direct TCP/QUIC traffic, overload and recovery, in GET and POST. Interactive-alone baselines precede loaded measurements. These are finite application tests under shared resource limits, not proof of production-wide fairness. Idle snapshots follow 20 seconds of drain time. Every observed new-client/server stream and codec lease returned to zero; no unexpected test-process restart or OOM was detected during the mixed soak.

Transport counters were not completely error-free: pr4 recorded 366 UDP `SndbufErrors` in one observation interval ending with a severe-profile compressed BBR text upload, then the counter remained unchanged. Neither node recorded receive-buffer or checksum errors, and pr5 recorded no send-buffer errors. All measured transfers completed integrity checks despite these events. Their exact kernel cause was not traced; do not reinterpret successful application delivery as zero transport errors or an unconditional stability guarantee.

The [send-discard follow-up](sndbuf-pr4-pr5.md) preserves this historical result, reproduces queue overflow with a kernel trace, fixes pre-send flight accounting and idle-capacity validation, and records fresh bidirectional tests and cleanup. It also corrects missing loss-statistics accounting in the external adapter: older BBR `wanopt_lost_packets=0` readings are uninstrumented values, not evidence of no network loss.

| Node | Test-slice peak MiB | Idle observations | Final test-slice MiB |
| --- | ---: | ---: | ---: |
| pr4 | 76.05 | 120 | 35.30 |
| pr5 | 97.95 | 120 | 55.88 |

Filtered resource histories include goroutine counts, heap, compression attempts/skips, admission and failure counters. See [pr4](benchmark-data/hardening-20261018/client-resources.jsonl), [pr5](benchmark-data/hardening-20261018/server-resources.jsonl), [mixed results](benchmark-data/hardening-20261018/mixed.jsonl) and [functional outcomes](benchmark-data/hardening-20261018/functional.json).

## Profiles and limits

Local incompressible 1 MiB codec microbenchmark: old median 205756 ns versus adaptive 74036 ns, both 5 allocations / 82080 bytes. This is about 2.8x less codec time in that fixture, not a WAN acceleration guarantee. Linux one-worker relay profiles include real QUIC/codec stacks; most allocation space is the benchmark's io.ReadAll/bytes.Buffer fixture collection. No unsafe buffer reuse or extra dependency was added based on that fixture artifact. [CPU profile summary](benchmark-data/hardening-20261018/relay-linux-cpu-top.txt), [allocation summary](benchmark-data/hardening-20261018/relay-linux-alloc-top.txt).

Final recipe passes transport/application Linux race tests, vet, module verification and govulncheck; no reachable vulnerabilities, ten required-module findings outside the call graph. Windows all-package tests pass. CI also checks normal release builds, nonroot/read-only container restart and the optional small Compose envelope. Pin/key rotation preserves protocol v2 framing but new config fields require new binaries. Ordinary builds reject BBR config explicitly.

Removed test units, slice overrides, cleanup timer, namespaces, veth, exact firewall rules, binaries, configs, certificates and keys from both nodes. Production container IDs/start times, host qdisc, Alloy and NetBird PIDs match the baseline. [Continuity/cleanup evidence](benchmark-data/hardening-20261018/continuity.json), [source/patch/binary hashes](benchmark-data/hardening-20261018/provenance.json). No production deployment, EBS resize or PR merge occurred. Existing pr4 monitoring delivery/storage-reserve issues were not modified.

Physical mobile path migration remains untested; controller recreation is unit-tested. The imported BBR has no spurious-loss undo implementation. The finite six-hour isolated run does not establish production uptime, application-session recovery, universal acceleration or fairness across arbitrary competing traffic. Keep Reno as the default and choose compression/BBR using representative workload measurements.

## Concurrent application observations

Interactive values are medians of per-batch p95 latency, not a pooled percentile. Each quiet baseline lasts five seconds and each loaded observation ten seconds; samples and p99 remain in raw results. GET and POST both check integrity.

| Profile | Direction | Quiet p95 ms | Loaded p95 ms | Batches each |
| --- | --- | ---: | ---: | ---: |
| latency | GET | 103.56 | 106.45 | 20 |
| latency | POST | 103.69 | 111.80 | 20 |
| moderate | GET | 109.42 | 211.34 | 20 |
| moderate | POST | 110.10 | 214.03 | 20 |
| severe | GET | 110.05 | 479.50 | 20 |
| severe | POST | 111.02 | 461.40 | 20 |

Median useful throughput while direct TCP and compressed QUIC BBR compete, ten-second request batches. Both flows make verified progress; this does not assert equal shares or maximum wire utilization. Under concurrent bulk traffic, median per-batch interactive p95 rose from about 110 ms to 211-214 ms on the moderate profile and 461-480 ms on the severe profile. BBR does not provide application priority or a low-latency guarantee under competing bulk load.

| Profile | Direction | TCP Mbit/s | BBR Mbit/s | Pairs |
| --- | --- | ---: | ---: | ---: |
| latency | GET | 59.05 | 55.78 | 20 |
| latency | POST | 53.88 | 57.06 | 20 |
| moderate | GET | 37.98 | 26.35 | 20 |
| moderate | POST | 35.17 | 29.53 | 20 |
| severe | GET | 8.82 | 8.27 | 20 |
| severe | POST | 8.78 | 9.68 | 20 |

## Idle goroutine recovery

Medians of the first and last 20 idle observations, with the maximum over the mixed soak. Heap values are last 20 median allocated MiB and include normal GC variation.

| Node/metrics port | First goroutines | Last goroutines | Maximum | Last heap MiB |
| --- | ---: | ---: | ---: | ---: |
| pr4/19081 | 19 | 19 | 20 | 1.31 |
| pr4/19082 | 19 | 19 | 20 | 6.89 |
| pr4/19083 | 19 | 19 | 20 | 1.33 |
| pr5/19102 | 40 | 40 | 40 | 8.75 |
| pr5/19103 | 28 | 28 | 29 | 1.49 |

Kernel UDP receive/send-buffer and checksum counters, cumulative OOM and memory-limit events are preserved in [transport error evidence](benchmark-data/hardening-20261018/transport-errors.json). Intentional network loss, blackholes and server restarts are part of the test; successful delivery does not imply zero packet loss. The complete earlier pilot, including its timeout, remains in [pilot measurements](benchmark-data/hardening-20261018/pilot-timeout-matrix.jsonl).
