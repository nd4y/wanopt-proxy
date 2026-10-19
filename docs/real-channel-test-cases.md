# Tests that require real channels

This is the separate real-channel register for [the complete test plan](test-plan.md). Hosted runner netem checks exercise deterministic regressions; they do not establish provider-path throughput, host resource headroom or continuity of other services. Real-node measurements are observations, not universal speedup gates.

Strictly real-channel-only evidence here is the actual node/route identity (WAN-01), installed-release chain on those nodes (WAN-02), provider-path throughput and interactive distributions (WAN-03/05), real pr4 resource headroom alongside existing workloads (WAN-06), and continuity of the original services/settings (WAN-08). Physical migration, provider variation outside the bounded run and multi-day stability (WAN-09) also need real conditions. The hash-checking, rate-step, authentication/rotation, cancellation, MTU and outage logic in WAN-02/04/07 is portable and is also automated in Actions; this register records its additional real-path execution, not an exemption from CI.

CI's no-loss100ms control has a defined100Mbit/s capacity so a finite veth queue does not introduce unrequested overflow loss. The real latency-only profile keeps the physical pr4/pr5 path without an added rate cap. The deliberate one-packet overflow/Sndbuf calibration probe runs only in disposable runner namespaces, never on the user's nodes.

## pr4/pr5 release acceptance

| ID | Case | Required evidence and acceptance | Status |
| --- | --- | --- | --- |
| WAN-01 | Read-only preflight | Node identity; real route and RTT; memory/disk reserve; original container IDs/start times, monitoring/VPN PIDs and host qdisc; no conflicting lab/controller. | Initial preflight held: pr4 root had ~3 MiB free. Downloaded apt archives alone cleaned under prior cleanup authorization; ~201 MiB free afterwards. No service changed. |
| WAN-02 | Exact release installation | Verify manifest source/patch/archive and individual binary hashes. Use fresh test credentials in /run only; own namespace/veth and peer/port-restricted firewall rules. Aggregate lab budget: one CPU, 128 MiB, no additional swap; guard at least 96 MiB host available memory and 128 MiB root free. | Planned |
| WAN-03 | Both directions, interleaved comparison | Native real path, ~100 ms RTT/0.1%/100 Mbit/s and ~100 ms RTT/1%/20 Mbit/s profiles on dedicated interfaces only. TCP versus released Reno/raw, Reno/adaptive, BBR/raw and BBR/adaptive; text/random, GET/POST, at least three repeats. SHA/status/length must pass. Report full generation-plus-drain goodput and connection warm/cold semantics. | Planned |
| WAN-04 | Real-socket idle and reduced-rate transition | Prime fast profile, drain, idle, then decrease rate on owned interfaces. Observe namespace UDP Sndbuf/Rcvbuf/InErrors/Checksum/Memory/NoPorts, qdisc, actual controller and reconnects. Expected intentional failures must be identified separately. | Planned |
| WAN-05 | Competing traffic and interactive latency | Simultaneous direct/proxy bulk and small requests in both directions. Both competitors progress; retain latency distributions and resources. Do not infer general fairness from two nodes. | Planned |
| WAN-06 | Bounded mixed soak and host guard | Record precise active-load duration and any observation gaps, CPU/RSS/cgroup peak and limit events, leases/goroutines, disk reserve and UDP deltas. Guard breach stops the lab and triggers cleanup. | Planned |
| WAN-07 | Functional release smoke over the real path | Integrity, stream/finite transfers, cancel/recovery, slow reader/writer, ACL/auth rejection and valid recovery, rotation/expiry, reconnect, MTU and brief isolated blackhole where scheduled. Report each executed case, not only its parent group. | Planned |
| WAN-08 | Independent cleanup/continuity audit | No owned processes, units/timers, namespace/veth, exact firewall rules, runtime credentials or extracted lab files. Compare original container identities, monitoring/VPN PIDs and host qdisc. Preserve release reports and provenance locally/in GitHub. | Planned |

## Requires other physical conditions

| ID | Case | Why hosted Actions or pr4/pr5 netem is insufficient | Status |
| --- | --- | --- | --- |
| WAN-09a | Actual provider route/congestion variation | Requires time-separated measurements of the real path; emulated loss cannot reproduce all middleboxes or cross traffic. | Unproven beyond this bounded campaign |
| WAN-09b | Physical mobile/Wi-Fi migration and NAT rebinding | Requires actual address/route changes and real devices. The existing CI migration-related tests and namespace changes are only analogues. | Deferred, no suitable mobile endpoint in this task |
| WAN-09c | Multi-day production-like stability | A bounded soak cannot establish multi-day uptime, all traffic mixes or provider incidents. | Deferred; no production deployment authorized by this release task |

## Execution ledger

Results and raw-case IDs will be appended here and in the release acceptance report. A planned/deferred case is never counted as passed. No production interface, queue, retention, container, monitoring or VPN configuration is part of this lab.

The first full matrix attempt ran four client copies in one128MiB group and hit a lab memcg OOM after104 successful transfers. Cleanup and independent continuity audit passed. The full repeat uses one active matrix client mode at a time, a fresh client/QUIC connection for each invocation and a finite1MiB warmup, within the unchanged128MiB aggregate budget. Mixed cycles retain one persistent client and add a second only during explicit overload. Record all planned transitions; retain NoPorts from deliberate socket replacement separately from critical UDP buffer/input/checksum/memory errors. Do not reuse partial failed data as a successful final matrix.
