# Final review of PR 2

Review date: 2026-10-19. Starting head: `9af3f1458a25ed1b5ec80984aabd63f2b165eac9`; base main: `81a948cbe85c7b7cd93d9330e726b17be3434bf6`. Priorities: stability, performance, security, lightweight operation.

## Findings resolved

**P2 - BBR pacer MTU was lost at construction and after idle restart.** The sender uses its current datagram size for `HasPacingBudget`, while a fresh common pacer defaults to 1280 bytes. At MTU 1472 a residual budget such as 1392 therefore rejected a packet but returned an immediate send deadline. The QUIC loop converts that deadline into immediate wakeups, creating unnecessary hot iterations. At long RTT, a timer could also wake before enough budget had accumulated.

Commit `2cf91a1bf462b6e43284bed5c80b53d142f7f4ed` synchronizes the pacer size in both places. The idle rebind still captures the live sender; the existing RTT, window and profile preservation remains. This adds two setter calls and no fields, goroutines, timers, dependencies or wire-format change. Normal Reno is unchanged.

The regression checks constructor and drained-idle restart, MTU 1200/1472, RTT 100 ms/3 s, partial/full first packets, the burst budget, and a future wakeup that actually has a full current-MTU budget. All 16 cases fail before the fix and pass after it. A second independent overlay checks 39 residual-budget cases across construction, idle, growth and shrink, with race detection. See [before](benchmark-data/final-review-20261019/pacer-mtu-before.log), [after](benchmark-data/final-review-20261019/pacer-mtu-after-race.log), and [independent coherence](benchmark-data/final-review-20261019/coherence-after-race.log).

The Russian README also incorrectly said reclassification could decrease the accumulated loss history. It now matches the English README and metric HELP: declarations accumulate per connection; the active-tunnel sum falls on disconnect. Both entry points link to the current WAN follow-up while retaining the previous campaign.

## Review coverage

- Stability: TCP/SOCKS/CONNECT half-close, cancellation, HTTP pooling and early upload responses, reconnect waiters, admission lease lifetime, listener/shutdown joins, UDP queues and flow closure. Client/proxy/server/admission race tests passed three consecutive runs.
- Security: numeric/resolved ACL endpoints and DNS rebinding, TLS-exporter PSK authentication, pins on resumed sessions, disabled 0-RTT, pre-auth TCP/UDP gates and absolute authentication deadlines, atomic credential snapshots/revocation/reload, bounded regular-file reads, proxy loopback defaults, HTTP parsing and SOCKS UDP source checks. Targeted package and proxy security race tests passed.
- Performance and footprint: adaptive compression backoff, bounded encoder pool, global TCP/codec admission, fixed metric labels, BBR adapter flight/loss accounting, pacer deadlines and pinned recipe. No additional actionable defects were found in these paths.
- Operations: CLI error/shutdown behavior, validated examples, nonroot/read-only container and small-node envelope, protocol-v1/v2 migration and rollback, and CI/reproducible build requirements.

The final applied BBR sources were also exercised by a real local loopback test, with 16 verified text/random transfers in both directions before and after idle, plus four 4 MiB transfers in 1 KiB chunks. The first drain assertion was premature because the HTTP pool keeps connections for 15 seconds; the harness now waits up to 20 seconds for its normal drain, with no runtime change. The failed attempt also cleaned up successfully. Its measurements, selected BBR metrics and binary hashes are retained in the [sanitized summary](benchmark-data/final-review-20261019/loopback.json). The complete pinned transport/application race, vet, module verification, vulnerability scan and build recipe is required in CI on the reviewed head, alongside normal Linux/Windows and container/release checks.

## Measurement and merge limits

The [previous WAN measurements](sndbuf-pr4-pr5.md) name their exact source/binary cohorts and predate this MTU fix. They are not silently attributed to the new source. The new review uses deterministic pacing regressions and local BBR transfers; it does not claim a new pr4/pr5 campaign or physical-path migration test. No node, production service or persistent network setting was changed for this review.

BBR remains experimental and opt-in, with no spurious-loss undo. The existing limits are admission counts, not a global byte-level memory cap. Compression gains still depend on payload/bottleneck; default Reno and disabled compression are preserved.

Use a normal merge commit for this PR: the BBR recipe archives base `88fbe38901713ff2975870f89b33e20de86c258d`, which is inside the PR history. Keeping that ancestry makes the pinned source available in a fresh full clone of main. Merge is gated on the exact reviewed head, successful CI and no unresolved findings; deployments are separate.

## Post-merge Windows test follow-up

PR 2 merged as `7f3647bdadd744e8967071309cb4639385d3abc7` after all four jobs passed on its exact head in [CI 39187679944](https://github.com/nd4y/wanopt-proxy/actions/runs/39187679944). The subsequent [main CI 39187939195](https://github.com/nd4y/wanopt-proxy/actions/runs/39187939195) exposed a scheduling-dependent assumption in `TestHTTPExpectContinueAndEarlyResponse/continue`; Linux, build/container and the complete BBR recipe passed.

The raw test assumed that exactly one `100 Continue` preceded the final response. Go's server can send its own automatic `100` while `ReverseProxy` forwards an upstream `100`; a second informational response has no body. Instrumented native Windows Go 1.27.2 runs observed seven extra `100` responses in 1000 successful transfers, each followed by the final `200` and the complete `data` body. This was a test parser failure, not evidence of lost proxy payload. Handling multiple interim responses agrees with [RFC 9110 section 15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2) and the standard Go transport.

The test-only follow-up makes the origin explicitly send `100` and `103`, retains the first-`100`-before-upload check, consumes a bounded sequence of interim responses, and requires the forwarded `103`, final `200` and intact body. The early `417` branch and existing TCP deadline remain. The same test is added to the pinned BBR application patch; its previous 19 diff sections remain byte-identical, so no runtime code changes. The new patch hash is `f4b4fc7f570c51fc3d5c9ae621df20d2ca4627db5c258a356de0fbad5dc52f5a`; earlier binary and measurement provenance retains the original patch hash.

The deterministic fixture fails with the old parser. After the test correction, native Windows Go 1.27.2 passes 1000 targeted repeats plus three complete proxy-package runs; Linux Go 1.27.2 passes the same checks with the race detector. An independent review confirmed that the assertions were preserved or strengthened and that runtime code, dependencies and workflows were unchanged. Final follow-up and post-merge CI results are linked from the follow-up PR.
