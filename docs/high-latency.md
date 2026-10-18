# High-latency transport notes

Reviewed on 2026-10-18. These are design comparisons, not claims that a protocol
will beat TCP on every workload. The direct TCP control in the cloud experiment
uses Linux BBR; wanopt keeps upstream quic-go 0.64.0 Reno (the pinned source calls NewCubicSender with useReno=true).

| Reference implementation | Useful idea | Decision for wanopt |
| --- | --- | --- |
| [QUIC flow control](https://quic-go.net/docs/quic/flowcontrol/) and [RFC 9002](https://datatracker.ietf.org/doc/html/rfc9002#section-7.7) | Size receive windows against bandwidth-delay product; pace packets and bound bursts. | Keep upstream auto-tuning and pacing. Set memory caps from measured BDP; do not raise windows blindly. |
| [Google BBR](https://github.com/google/bbr) / [QUICHE BBR2 sender](https://github.com/google/quiche/blob/main/quiche/quic/core/congestion_control/bbr2_sender.cc) | Model delivery rate and propagation delay instead of treating all loss as congestion. | A candidate for a separate controlled comparison. Linux TCP BBR does not configure QUIC. Upstream quic-go has no supported pluggable-controller API, so adding BBR currently implies a dependency/fork maintenance decision. |
| [KCP](https://github.com/skywind3000/kcp/blob/master/ikcp.c) / [kcp-go](https://github.com/xtaci/kcp-go) | Selective fast retransmission, bounded queues, buffer reuse; optional FEC. | Keep buffer reuse and measure recovery latency. Do not copy fixed short retransmission timers or disable congestion control; QUIC already implements its own loss recovery. |
| [SRT file/live modes](https://github.com/Haivision/srt/blob/master/docs/API/API.md) / [FEC](https://github.com/Haivision/srt/blob/master/docs/features/packet-filtering-and-fec.md) | Balance redundancy, recovery delay and bandwidth; distinguish file reliability from media deadlines. | Dropping late media packets is unsuitable for an arbitrary TCP byte stream. FEC requires an explicit traffic/CPU budget and a new measured experiment, not a default protocol change. |
| [Hysteria congestion configuration](https://v2.hysteria.network/docs/advanced/Full-Server-Config/) / [Brutal implementation](https://github.com/HyNetworks/hysteria/blob/master/core/internal/congestion/brutal/brutal.go) | Explicit bandwidth budgets and transport telemetry. | Keep congestion responsiveness. Fixed-rate loss compensation can overload a bottleneck and interfere with other services; it is inconsistent with the stability-first default. |
| [RFC 3135 performance-enhancing proxies](https://www.rfc-editor.org/rfc/rfc3135.html) | Split long transport paths and reuse established transport state. | Retain one authenticated QUIC connection with independent streams and bounded HTTP upstream reuse. Existing application sessions still fail if that tunnel is lost. |

## Practical sizing

BDP in bytes = link bits/s * RTT seconds / 8. At 100 ms, 100 Mbit/s requires
about 1.25 MB in flight; 1 Gbit/s requires about 12.5 MB. The current 16 MiB
stream and 24 MiB connection receive caps cover those examples, but are not
throughput guarantees: congestion window, CPU, packet loss and kernel socket
buffers impose separate limits. Initial receive windows are smaller and grow
with demand. Count both directions and concurrent tunnels when budgeting memory.

[quic-go's socket documentation](https://quic-go.net/docs/quic/transport/) also
explains why UDP buffers and access to native UDP socket optimizations matter.
On a real deployment retain GSO when supported. In a netem loss experiment,
set `QUIC_GO_DISABLE_GSO=1`, and disable TSO/GSO/GRO on both ends of the test veth:
otherwise loss may be applied to an aggregated skb instead of each wire packet.
Never change the production interface's qdisc for an isolated benchmark.

## Changes actually implemented

- Ordinary HTTP forwarding now requests the configured compression mode and
  decodes the negotiated framing. Previously this path always passed `false`,
  silently ignoring `compression: true`. Server refusal still falls back to raw.
- The HTTP compression bridge uses backpressure, two bounded codec workers per
  compressed connection, cancellation and joined shutdown. Clean EOF remains EOF
  for close-delimited bodies; malformed frames remain errors.
- Each compression frame is written in one call. A stream reuses its DEFLATE
  decoder between blocks, including compressed/raw transitions. There is no new
  wire format, third-party dependency, global sysctl or congestion-control fork.
- Compression stays opt-in. It cannot shrink the plaintext hidden inside HTTPS,
  already compressed video or archives. Prefer application compression when the
  application supports it; use that as another control in a benchmark.

`BenchmarkBlockCodec` measures allocations as well as throughput. For its
1.15 MB repetitive text fixture, decoder allocation dropped from approximately
1.53 MB / 184 allocations to 114 KB / 9 allocations per operation on Windows.
Timing samples were noisy; this is an allocation result, not a claimed universal
speedup. The encoder's combined frame buffer increases its per-stream buffer by
one allocator size class while removing per-block header allocations.

## Cloud experiment methodology

Two Linux x86_64 cloud nodes, 24 ms public-route RTT. Management uses a separate
VPN; the measured TCP/QUIC path uses public IPs. Each node has its own network
namespace/veth, source-restricted forwarding and a temporary TLS/PSK identity.
The origin accepts only test data; the tunnel ACL allows only that local origin.
Each test slice is capped at 0.5 CPU and 160 MiB. Host TCP is BBR, including in the
namespaces. GSO is disabled for test QUIC sockets and offloads for owned veths.

Compare direct HTTP/TCP, raw wanopt, and compressed wanopt, each with three
repetitions in alternating order, both upload and download. Each transfer checks
its length and SHA-256. Payloads: deterministic random bytes, synthetic JSON
records with changing timestamps/IDs/paths/counters, and gzip of those records.
Use 4 MiB logical payloads, reduced to 1 MiB in the 1% loss profile to bound cost.
The gzip fixture has fewer application bytes; compare its elapsed time for the
same logical records, not its compressed-byte Mbps against uncompressed Mbps.

Each benchmark process warms an HTTP connection with a small ping before the
measured request. The wanopt tunnel and its congestion state persist across
requests within each profile. Tunnels are restarted between profiles so loss history does not carry into another scenario; direct TCP does not retain the preceding process's bulk-transfer state.
This deliberately measures short transfers through a persistent proxy, **not
steady-state bulk throughput or equivalent warmed congestion windows**. Server
fixture generation is included in GET timing; client fixture generation is
outside POST timing, identically for all three transport choices. CPU contention
and three-sample variation limit generalization. Do not infer performance for
Windows, long transfers, hundreds of sessions, media latency or arbitrary WANs.

Profiles add 38 ms per direction to the native ~24 ms RTT. The two impaired
profiles additionally use uniform 5 ms jitter per direction, loss 0.1% / 1% and
100 / 20 Mbit/s rate limits. Jitter can reorder packets. Report observed qdisc
counters as well as configured percentages. Interface byte counters include
headers, retransmissions, warm-up and small idle-tunnel traffic; they are not
just compressed payload bytes. Preliminary runs with UDP GSO and the unfixed
HTTP path are excluded from final comparisons.

The bounded fixture driver is `go run ./tools/wanbench`. Start its origin with
`-serve` (loopback by default), then use `-kind random|text|gzip`,
`-direction GET|POST`, `-bytes 4194304`, and optionally `-proxy http://127.0.0.1:8080`.
`-warm` performs and verifies one full-size transfer on the same HTTP connection
before timing the second. This is the additional control for TCP slow-start.
The default server bind is local; expose it only inside an isolated, peer-filtered
test namespace. Do not run a public unfiltered benchmark origin.

## Measured results (2026-10-18)

All 216 main transfers and 54 measured warm-control transfers passed SHA-256 and length verification. Each warm-control sample additionally verified one full-size transfer before timing the second. Each cell below is a median of three runs; the linked raw records retain individual timings. GET is download to the client node and POST is upload to the server node. Values are application Mbit/s.

[Main samples](benchmark-data/pr4-pr5-20261018-results.jsonl) | [Warm TCP control](benchmark-data/pr4-pr5-20261018-warm-results.jsonl).

Four records were absent from the initial local moderate-profile capture despite the runner completing. That entire profile was repeated, with complete stdout captured before extracting its 54 records. The incomplete capture is excluded rather than selectively filling individual samples.

| Profile | Data | Direction | TCP BBR | wanopt raw | wanopt compressed | Compressed / TCP |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| public | random | GET | 92.38 | 96.70 | 120.01 | 1.30x |
| public | random | POST | 131.11 | 72.62 | 87.47 | 0.67x |
| public | text | GET | 75.28 | 75.09 | 122.54 | 1.63x |
| public | text | POST | 143.40 | 93.86 | 141.89 | 0.99x |
| public | gzip | GET | 15.27 | 21.09 | 21.64 | 1.42x |
| public | gzip | POST | 33.53 | 72.89 | 52.71 | 1.57x |
| latency | random | GET | 24.29 | 72.93 | 86.62 | 3.57x |
| latency | random | POST | 35.53 | 63.11 | 49.79 | 1.40x |
| latency | text | GET | 22.85 | 68.21 | 101.21 | 4.43x |
| latency | text | POST | 35.84 | 65.37 | 112.77 | 3.15x |
| latency | gzip | GET | 5.48 | 19.06 | 18.53 | 3.38x |
| latency | gzip | POST | 8.30 | 36.49 | 31.13 | 3.75x |
| moderate | random | GET | 22.72 | 11.63 | 8.52 | 0.38x |
| moderate | random | POST | 31.64 | 8.58 | 13.51 | 0.43x |
| moderate | text | GET | 21.56 | 6.62 | 30.45 | 1.41x |
| moderate | text | POST | 31.66 | 7.09 | 50.83 | 1.61x |
| moderate | gzip | GET | 5.34 | 4.57 | 5.12 | 0.96x |
| moderate | gzip | POST | 8.00 | 5.92 | 8.71 | 1.09x |
| severe | random | GET | 7.09 | 1.68 | 5.14 | 0.72x |
| severe | random | POST | 8.02 | 2.09 | 1.61 | 0.20x |
| severe | text | GET | 7.31 | 1.48 | 14.51 | 1.98x |
| severe | text | POST | 8.04 | 1.59 | 9.44 | 1.17x |
| severe | gzip | GET | 2.45 | 1.55 | 2.06 | 0.84x |
| severe | gzip | POST | 2.90 | 1.34 | 1.23 | 0.43x |

### Full-size warm TCP control (text)

| Profile | Direction | TCP BBR | wanopt raw | wanopt compressed | Compressed / TCP |
| --- | --- | ---: | ---: | ---: | ---: |
| latency | GET | 84.98 | 63.21 | 103.59 | 1.22x |
| latency | POST | 195.38 | 61.59 | 85.25 | 0.44x |
| moderate | GET | 62.86 | 4.85 | 34.57 | 0.55x |
| moderate | POST | 73.50 | 4.11 | 56.83 | 0.77x |
| severe | GET | 13.16 | 1.57 | 9.79 | 0.74x |
| severe | POST | 15.43 | 1.64 | 31.22 | 2.02x |

The warm control substantially reduces or reverses several apparent gains. The severe-profile text upload still improves from 15.43 to 31.22 Mbit/s (2.02x); download falls from 13.16 to 9.79 Mbit/s. In the latency-only profile, warmed text download improves by 1.22x while upload is slower. This is evidence of conditional acceleration, not a universal advantage over BBR or a steady-state bandwidth claim.

Text wire-byte totals fall by approximately 83% versus direct TCP. The warm-control interface counters cover **both** full-size transfers, whereas its reported seconds/Mbit/s cover only the second. Already-gzipped and random data generally do not shrink. Compression cannot accelerate encrypted application payloads by compressing their plaintext.

Packet jitter in netem can itself reorder packets, as documented in the [upstream iproute2 manual](https://github.com/iproute2/iproute2/blob/main/man/man8/tc-netem.8). These impaired profiles therefore test jitter, loss and possible reordering together. They do not isolate random loss as the sole cause of reduced Reno throughput. A separate FIFO/no-reordering experiment and a maintained BBR-capable QUIC implementation are follow-up comparisons, not changes silently included in these numbers.

### Observed packet drops

Counters below are from the main profile, after all its transfers, on each owned namespace egress qdisc. They include data, acknowledgements and connection setup.

| Profile | Client egress | Server egress |
| --- | --- | --- |
| moderate | 57 dropped / 76010 sent packets | 70 dropped / 75367 sent packets |
| severe | 193 dropped / 20603 sent packets | 191 dropped / 21592 sent packets |

Tested binaries (Linux amd64, stripped):

- Client SHA-256: `15f9df96e9432a852c763174e580dbce90f308bb9a4fce8dc43f21ec51445279`.
- Server SHA-256: `5d8b3469cdcdf18ebc0bb72953be69e3f1912e5e24c0fadd76097688a5f28a04`.
