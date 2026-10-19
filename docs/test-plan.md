# Release validation plan

Status: in progress. Source: main 68c7bd6615db8005debfd921c8f48ceeda66af6b. Target: first GitHub release v0.2.0. Priorities: stability, performance, security, lightweight operation. Update this file before adding a new scenario and record each execution result. No other-service changes; all WAN workloads use an owned namespace, cgroup, addresses, ports and exact firewall rules. Preserve pr4 8 GiB disk and monitoring queues.

## Cases suitable for GitHub Actions

| ID | Scenario and acceptance | Execution |
| --- | --- | --- |
| CI-01 | Existing unit/integration/regression tests, Linux and Windows; all pass. Maintain an inventory of Test/Fuzz functions and their workflow mapping. | Planned |
| CI-02 | Race detector, vet, module verification, reachable vulnerability scan and bounded protocol/compression fuzzing. | Planned |
| CI-03 | Pinned BBR transport/application recipe; flight/idle/MTU regressions and all patched tests pass. | Planned |
| CI-04 | Release binaries run as separate processes; direct TCP and actual wanopt HTTP paths preserve SHA256/status/length for text/random and upload/download. Include compression disabled/enabled and default Reno/optional BBR. | Planned |
| CI-05 | Cold and reused requests, finite and continuous transfers, small/chunked bodies, partial uploads, cancellation/abort, idle reuse and graceful shutdown; intact data and bounded cleanup. | Planned |
| CI-06 | Invalid authentication/pin/ACL and unreachable targets fail as expected; valid requests recover afterwards. Existing tests cover config/credential rotation and TCP/UDP lifecycle. | Planned |
| CI-07 | Concurrent traffic and admission overload; expected rejections bounded, healthy recovery, active/codec leases drain. | Planned |
| CI-08 | Repeat the informational HTTP100/103/final200 regression on Linux and Windows; retain all assertions. | Planned |
| CI-09 | Nonroot read-only container, restart and Compose small-node envelope. | Planned |
| CI-10 | Synthetic impaired-link comparisons inside an owned runner namespace: native, ~100ms RTT/moderate loss, ~100ms RTT/severe loss, both directions; integrity/error/resource checks. No brittle speedup threshold on shared runners. | Planned |
| CI-11 | Release assets, checksums, source/toolchain/patch provenance, reproducible build, --help/invalid-config behavior, Windows/Linux build targets. | Planned |
| CI-12 | Harness failure paths, teardown and no owned resources left; artifacts retained even when a case fails. | Planned |

## Cases that require real channels (pr4/pr5)

These do not run on hosted GitHub Actions. CI analogues do not replace these observations.

| ID | Scenario and acceptance | Execution |
| --- | --- | --- |
| WAN-01 | Read-only preflight: correct nodes/route/host keys, free disk/memory, original container IDs/start times, service PIDs/state, host qdisc; no old lab/controller. | Planned |
| WAN-02 | Install exact verified release assets into a fresh isolated resource-limited lab; record source/patch/binary hashes and measured idle RTT/path. | Planned |
| WAN-03 | Matched direct TCP, release default Reno and optional BBR, compression off/adaptive, text/random, upload/download, native/moderate/severe profiles; at least 3 measured repeats per combination, deterministic integrity and interleaved baseline order. Record cold/reuse semantics explicitly. | Planned |
| WAN-04 | Rate/latency step and drained-idle restart after a fast profile; no unexpected UDP errors, corruption, spin or reconnect; record per-namespace UDP and qdisc counters. | Planned |
| WAN-05 | Mixed bulk/small requests and competing direct/proxy traffic in both directions; latency distributions, goodput, fairness observations without universal claims. | Planned |
| WAN-06 | Bounded mixed soak with host guard: CPU/RSS/cgroup memory/limit events, goroutines/leases, reconnects, disk reserve and UDP error deltas. Stop and clean on guard breach. | Planned |
| WAN-07 | Functional smoke on the exact release assets: integrity/cancel/recovery/auth/idle, with expected failures separate from unexpected failures. | Planned |
| WAN-08 | Full cleanup and independent final audit: owned processes/units/namespaces/veth/firewall rules/files absent; original container identities/service PIDs/host qdisc unchanged. | Planned |
| WAN-09 | Physical path migration, mobile radio transitions, provider congestion variation and multi-day stability need a separate real-channel campaign; explicitly not proven by emulation or this bounded run. | Deferred, requires different conditions |

## Execution log

- 2026-10-19: Read memory/Obsidian and current main. Main is 68c7bd6, prior four-job CI was successful. No tags/releases exist. Existing workflow has Linux/Windows, container and full BBR recipe, but no release workflow or actual binary end-to-end WAN-like CI. Initial broad local filename search hit unrelated inaccessible directories; narrowed all further reads to this repository and owned diagnostics. Infrastructure has not been changed.
- WAN-01 preflight: pr4 root free 3,244,032 bytes (100% used), MemAvailable 271,970,304 bytes; pr5 root free 32,468,049,920 bytes. Lab launch held. Read-only diagnosis found 207,572,992 bytes of downloaded apt archives and 214,478,848 bytes of apt indexes; active Docker images and monitoring binary/data retained. apt daily services inactive. Safe cache-only cleanup is covered by the user's earlier cleanup authorization; do not change running services or monitoring queues.
- CI-04/05/06/07/12 local attempt: initial expected ACL failure produced no wanbench JSON (setup stops at failed ping). Harness assumption fixed by strict raw proxy HTTP502 check; first failed attempt cleaned all processes/runtime. Subsequent 41-case Reno binary smoke PASS with 33 integrity measurements and cleanup PASS.
- CI-10 local WSL attempt: missing Linux ethtool prevented shaping setup; both created namespaces/processes cleaned, result FAIL retained (not counted as a pass). The disposable Actions runner will supply the required tools.
- CI-03: carry independent constructor/idle/grow/shrink residual-budget probes into the pinned recipe, in addition to existing flight/idle/16-MTU regressions. CI-05/10 now also include competing direct/proxy transfers and bounded blackhole recovery. CI-11 includes real CLI help, strict invalid-config rejection, keygen non-overwrite, package and per-binary hashes, negative asset/source/path checks. CI-12 includes an intentional failure after readiness and asserts cleanup plus credential-directory removal.
- CI-04/05/06/07/11 local expanded suite: 52 cases PASS, including CLI/config/keygen and competing direct/proxy GET+POST; temporary processes cleaned. Python observation/asset self-tests: 8 PASS. CI-12 intentional failure after authenticated readiness: expected nonzero exit, owned processes absent, runtime credentials directory removed, PASS. Static-check first shell invocation failed due PATH quoting; retried via a saved LF script, Python compile/inventory and bash syntax checks PASS. The generic Windows Python launcher was unavailable; use the bundled runtime instead, without installing software.

## Test inventory and reproduction

[docs/test-cases.json](test-cases.json) records all 128 named Go/Python root tests with workflow mappings. Actions JSON events retain the complete dynamically generated subtest names. Run `python tools/validation/inventory.py` whenever tests change and `--check` in CI. Actual binary case names and all executed matrix combinations are retained in `*e2e.json` artifacts. [Real-channel-only register](real-channel-test-cases.md) records WAN prerequisites, exact acceptance evidence and physical conditions that remain unproven.

The Release workflow requires successful CI for the exact main commit, creates new version assets and a draft only, compares rebuilt normal binaries, tests both Reno/BBR packages, verifies the packaged Windows executable on Windows, and supplies source/patch/archive/binary hashes. Publish the draft only after real-channel acceptance and cleanup; do not rebuild or silently replace binaries after measuring them.

- CI-04/05/06/07/11 native Windows Go1.27.2 + bundled Python: 52 binary cases PASS, cleanup and runtime credential removal PASS. Both workflow YAML files parsed successfully using existing yaml.v3. No package installation required.
