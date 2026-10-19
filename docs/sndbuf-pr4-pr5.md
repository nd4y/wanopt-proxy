# UDP send discard follow-up on pr4/pr5

This report records the two source/binary cohorts named below. The later [final PR review](final-review-pr2.md) fixes pacer MTU preservation and records its separate local/CI validation; the WAN throughput figures below predate that fix.

The local shaping queue overflowed while BBR reused an old high-bandwidth model. The integration adapter forwarded upstream quic-go's **post-send** bytes in flight to a controller that requires **pre-send** bytes. This hid zero-flight starts and prevented the controller and sampler from recognizing drained idle periods.

## Evidence and regression

The historical 366 events were not kernel-traced at the time. This follow-up reproduces the same failure class, rather than claiming a retroactive stack trace or an identical count:

- Exact previous binaries (SHA256 matches the prior campaign) passed 18 short text flows and four primed transitions with the original 10000-packet queue. Random traffic left a 12-13 MB congestion window; the queue reached 8269 packets after a bandwidth drop.
- A diagnostic variant of the severe profile reduced only the test queue to 4096 packets. It produced **4706 UDP SndbufErrors and 4706 IP OutDiscards**. The queue reached 4096 packets while sampled socket transmit memory peaked at **2304 bytes**, against a 14680064-byte socket buffer. The upload failed with HTTP 502 after 21.79 seconds.
- The filtered kernel trace shows `netem_enqueue` returning `NET_XMIT_DROP` (1), followed by `ip_send_skb` returning `ENOBUFS` (-105). Deliberately injected random loss is accounted separately by netem and normally returns success. See [trace](benchmark-data/sndbuf-20261019/kernel-trace-excerpt.txt), [negative transfer](benchmark-data/sndbuf-20261019/baseline-bounded.jsonl), [Linux UDP](https://github.com/torvalds/linux/blob/v6.17/net/ipv4/udp.c) and [netem](https://github.com/torvalds/linux/blob/v6.17/net/sched/sch_netem.c).
- An initial idle-validation-only candidate still recorded **573 send errors under the original 10000-packet profile**, although its transfer passed SHA256. This candidate failed validation and was cleaned up. Its counters remained visible at 5279 (4706 + 573); they were not cleared. [Failed candidate](benchmark-data/sndbuf-20261019/idle-only-fixed-target.jsonl).
- The missing adapter regression uses the **actual QUIC sent-packet handler**, including an ACK-only packet and ACK-driven drain. Before the fix it forwarded `[1200,1200,2200,1300]`; the required values are `[0,1200,1200,0]`. [Before](benchmark-data/sndbuf-20261019/adapter-flight-before.log), [after](benchmark-data/sndbuf-20261019/adapter-flight-after.log).

## Fix

The adapter now subtracts the current packet only when it was added to flight accounting. The normal Reno controller remains unchanged. BBR also validates idle capacity: after the last in-flight data drains and idle reaches max(1 second, 3 PTO), it restarts its bandwidth/window/sampler/pacer model, retaining RTT, MTU, profile and window limits. ACK-only traffic does not refresh capacity validity; a slow active flight is not idle. The pacer's callback is rebound to the live sender when replacing the model.

Unit regressions cover actual handler accounting, initial and post-drain zero flight, ACK-only packets, PTO/floor boundaries, active/slow-draining flights, preserved path settings and pacer binding. A long idle now incurs another startup phase. This is a conservative experimental BBR policy, not a promise of zero drops under arbitrary active path changes. [QUIC underutilization guidance](https://www.rfc-editor.org/rfc/rfc9002.html#section-7.8).

No new timer, goroutine, configuration field or dependency was added. BBR remains opt-in through the reproducible patches; upstream quic-go/Reno and compression-off remain the ordinary defaults.

## Network validation

The adapter + idle fix at commit `761e1c6d3d043247942ff3cfd19b21a5bc6e8fea` used a **fresh namespace after the failed candidate was fully removed**, with start/end counters published separately. No counter reset was used to conceal events. The final campaign lasted 1.800 hours, including functional tests, idle gaps and cleanup, not continuous saturation throughout.

- 32 functional scenarios, including credential reload/rotation/revocation/expiry, slow peers, overload/recovery, abort, MTU 1280, a four-second blackhole, and five restarts of only the test server.
- Six primed bandwidth-drop cycles: original 10000-packet queue in both directions, plus two stricter 4096-packet cycles in each direction. Each uses 60 seconds of random traffic, idle, direct moderate traffic and a 60-second compressed severe transfer.
- 72 continuous matrix flows: two repetitions of every profile/payload/direction/mode, 30 seconds of generation per flow. Full tail delivery time, SHA256 and length are included. Setup/warmup are separate; each invocation warms a 1 MiB transfer. QUIC tunnels persist across invocations and profile changes, while the direct TCP client creates a connection for each invocation. BBR now validates idle capacity and Reno retains its learned state. Randomized order is recorded with seed 20261019; the figures describe complete proxy behavior, not equal fresh-state controller isolation. Wire counters cover the whole invocation, including warmup.
- 18 gzip batches / 54 measured transfers; 25 mixed interactive/fair cycles and 3 explicit overload/recovery probes. All expected successful transfers passed integrity checks. Expected overload/revocation failures are separate.
- **Zero new UDP send-buffer, receive-buffer, checksum, input or memory errors on both nodes.** [Exact start/end counters](benchmark-data/sndbuf-20261019/fixed-total-udp.jsonl).
- No OOM/memory-limit events or unexpected test PID changes after the functional phase. Idle stream/codec leases returned to zero on 25/25 snapshots. Test-slice memory peaks: 97.31/102.11 MiB under 128 MiB. Host reserve guards remained safe; maximum interval between observations was 24.7 seconds.

Same public WAN and isolated namespace/veth method: about 100 ms RTT; latency-only uncapped, moderate 100 Mbit/s + 0.1% loss, severe 20 Mbit/s + 1% loss; 5 ms jitter in the limited profiles. Direct TCP uses kernel BBR. Test groups have one CPU, low CPU weight, 128 MiB and no extra swap; Go uses one processor and a 64 MiB soft heap target. High-frequency observers ran only in the targeted regression phase, not the comparison matrix.

## Throughput

Useful application Mbit/s, median of two 30-second-generation flows including complete delivery. POST is pr4 -> pr5; GET is pr5 -> pr4. BBR uses adaptive compression, so this is a complete proxy comparison, not an isolated congestion-controller comparison.

| Profile | Payload | Direction | Direct TCP | QUIC Reno | QUIC BBR + adaptive | BBR / TCP |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| latency | text | POST | 745.58 | 145.48 | 360.38 | 0.48x |
| latency | text | GET | 714.32 | 135.53 | 389.76 | 0.55x |
| latency | random | POST | 743.33 | 22.98 | 266.47 | 0.36x |
| latency | random | GET | 689.50 | 21.88 | 283.88 | 0.41x |
| moderate | text | POST | 92.31 | 35.06 | 324.06 | 3.51x |
| moderate | text | GET | 91.66 | 31.88 | 332.86 | 3.63x |
| moderate | random | POST | 92.15 | 5.99 | 91.28 | 0.99x |
| moderate | random | GET | 91.83 | 5.79 | 91.13 | 0.99x |
| severe | text | POST | 18.56 | 11.90 | 107.71 | 5.80x |
| severe | text | GET | 18.36 | 12.61 | 111.16 | 6.05x |
| severe | random | POST | 18.51 | 1.79 | 18.27 | 0.99x |
| severe | random | GET | 18.43 | 1.71 | 18.30 | 0.99x |


## Mixed load and latency

The 30-minute phase alternates one-byte interactive requests alongside random bulk traffic and concurrent direct TCP/QUIC transfers, with both GET and POST in each batch. Values below are medians of **per-batch** p95 latency or throughput, not pooled request percentiles. The samples are short and do not establish a general fairness guarantee. Idle lease checks follow every cycle.

| Profile | Direction | Interactive idle p95, ms | Interactive loaded p95, ms | Competing TCP, Mbit/s | Competing BBR, Mbit/s |
| --- | --- | ---: | ---: | ---: | ---: |
| latency | POST | 104.68 | 110.43 | 54.24 | 55.62 |
| latency | GET | 104.22 | 110.29 | 53.16 | 55.40 |
| moderate | POST | 110.82 | 212.12 | 33.74 | 28.43 |
| moderate | GET | 108.97 | 161.91 | 39.92 | 26.04 |
| severe | POST | 109.92 | 191.05 | 9.32 | 8.11 |
| severe | GET | 110.48 | 203.56 | 9.87 | 7.82 |

[Mixed summary and sample counts](benchmark-data/sndbuf-20261019/mixed-summary.json) retain both throughput and latency tradeoffs. Intentional overload failures are recorded separately from successful integrity-checked transfers.

## Final telemetry-only revision

The full matrix above uses commit `761e1c6d3d043247942ff3cfd19b21a5bc6e8fea`. During its run, a separate statistics omission was corrected at `f86d29b70c0b868615622c8878011a39ef66cd6f`: unlike the ordinary controller, the external adapter had not populated packet/byte loss counters. Therefore older BBR `wanopt_lost_packets` values of zero are **not evidence of a loss-free path**; kernel namespace UDP counters are the authoritative source for the send-error checks above.

The final revision updates existing declaration counters for positive lost-byte notifications, excludes ECN-only notifications, and corrects the metric help: loss declaration history is cumulative per connection and does not disappear after retransmission or a spurious-loss report; the active-tunnel sum can fall on disconnect. It adds no field, dependency or label and changes no congestion decisions.

Loss declarations are transport recovery history, not a measurement of permanently lost IP packets. They may also occur without injected netem loss; these checks do not distinguish physical loss from reordering or spurious declarations. Zero UDP send-buffer errors must not be read as zero QUIC retransmission activity. Per-invocation declared losses in the final BBR tests (including setup/warmup inside each invocation) were:

| Profile | Payload | Direction | Declared losses |
| --- | --- | --- | ---: |
| latency | text | POST | 26643 |
| latency | text | GET | 8292 |
| moderate | text | POST | 23721 |
| moderate | text | GET | 2983 |
| severe | text | POST | 285 |
| severe | text | GET | 295 |
| latency | random | POST | 363308 |
| severe-queue4096 | text | POST | 557 |
| latency | random | GET | 49920 |
| severe-queue4096 | text | GET | 650 |

After the full campaign and its cleanup, the final binary was checked in a fresh isolated stand: **18 additional streaming invocations**, TCP/BBR in every original profile and direction plus another primed 4096-packet queue transition in each direction. SHA256 passed, UDP send/receive/input/checksum/memory error deltas stayed zero, and the sender's declared-loss metric increased under the injected severe loss in both directions. The telemetry controller waited for the full campaign; its controller start timestamp includes that wait, not generated load. Both nodes were cleaned again. [Measurements](benchmark-data/sndbuf-20261019/telemetry-measurements.jsonl), [loss observations](benchmark-data/sndbuf-20261019/telemetry-loss-observations.jsonl), [unit before](benchmark-data/sndbuf-20261019/loss-stats-before.log), [unit after](benchmark-data/sndbuf-20261019/loss-stats-after.log), [final binary provenance](benchmark-data/sndbuf-20261019/telemetry-provenance.json).

Acceleration depends on payload and bottleneck. Encrypted/incompressible traffic does not gain the text compression benefit. Short mixed tests are not a universal fairness or latency guarantee. Physical/mobile path migration remains unverified; the imported controller still lacks spurious-loss undo.

## Isolation and cleanup

Both nodes' original container IDs/start times, host qdiscs, Alloy and NetBird identities match preflight, including across the failed-candidate cleanup and fresh rerun. Only owned lab interfaces/rules/services were changed. Test namespaces, veth, exact peer rules, units/timers/slice overrides, keys/configs/binaries and both temporary Windows controller tasks were removed. Kernel trace probes/instance were removed before final comparisons. pr4 remains on its existing 8 GiB disk; monitoring queues and retention were preserved. No production deployment or PR merge.

[Continuity and remote cleanup](benchmark-data/sndbuf-20261019/continuity.json) · [Final binary continuity](benchmark-data/sndbuf-20261019/telemetry-continuity.json) · [Final process/probe/controller audit](benchmark-data/sndbuf-20261019/final-cleanup-audit.json) · [Source/binary/harness provenance](benchmark-data/sndbuf-20261019/provenance.json) · [Earlier full campaign](hardening-pr4-pr5.md) · [Reproducible BBR build](../experiments/bbr/README.md).
