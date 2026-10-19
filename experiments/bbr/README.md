# Experimental QUIC BBR

This opt-in experiment preserves the normal build and its upstream quic-go v0.64.0 dependency. It is not a production default. See [the pr4/pr5 measurements](../../docs/bbr-pr4-pr5.md) for both improvements and regressions.

## Reproduce

Use Linux, Go toolchain download access, Git, tar, and a C compiler for race tests. The repository must contain base commit `88fbe38901713ff2975870f89b33e20de86c258d` (use a full checkout of this PR). From the repository root:

```sh
bash experiments/bbr/build.sh /tmp/wanopt-bbr-bin
/tmp/wanopt-bbr-bin/wanopt-server -config /path/to/server.yaml
/tmp/wanopt-bbr-bin/wanopt-client -config /path/to/client.yaml
```

The output directory must not exist. The script builds in a temporary directory, applies the two checked-in patches, runs transport and application race tests, vet and govulncheck, then emits binaries and patch hashes. Temporary sources are removed on exit. It pins Go 1.27.2. The normal module is never edited. Remove the output directory after testing.

Set `congestion_control: bbr` in both YAML configs to test both directions. The only exposed BBR profile is standard. `reno` retains upstream Reno. Ordinary builds reject `bbr` at startup. Kernel TCP BBR does not select a userspace QUIC controller. See [operations](../../docs/operations.md) for resource sizing and rollback.

## Provenance and integration

- Wanopt base: `88fbe38901713ff2975870f89b33e20de86c258d`.
- Transport: upstream [quic-go v0.64.0](https://github.com/quic-go/quic-go/releases/tag/v0.64.0), with a small connection-creation hook and ACK/loss adapter. No downgrade to the older apernet transport.
- Controller: [Hysteria](https://github.com/HyNetworks/hysteria) BBR/common source at commit `ca8fbd874fd6ca82413948de6dc5924405e103e1`, copied from the HyNetworks repository with MIT license preserved in `wanopt.patch`.
- Public congestion interface and adapter shape: [apernet/quic-go](https://github.com/apernet/quic-go/tree/a10df75c260c). The implementation here is a minimal port to 0.64.0, with its own adapter tests and the original license retained.

A new controller is created before each connection starts and on path migration. There is no concurrent replacement of a live controller. The adapter converts upstream post-send bytes-in-flight into the pre-send value required by BBR, including zero for the first packet after drain; ACK-only packets do not add bytes. A regression test uses the actual QUIC sent-packet handler, not a direct adapter call. ACK/loss events are batched with the pre-event bytes-in-flight value and actual transport outstanding-history watermark; batches are cleared after delivery. Initial-packet EMSGSIZE fallback may reduce the datagram size, and packet-sized BBR windows are rescaled in both directions. Congestion-window statistics are updated after feedback and MTU changes. The adapter also maintains cumulative declared-packet/byte loss statistics for the external controller; ECN-only notifications do not invent lost packets. These statistics do not decrease when data is retransmitted or a loss is later found spurious. The active-tunnel metric can decrease when a connection disappears. Older experimental builds left the BBR loss fields at zero, so those values are not evidence of a loss-free path. Reno remains unchanged when no factory is configured. Tests cover factory isolation, loss-only events, batch replay prevention, RTT setup and migration reinitialization.

The standard BBR profile starts with 32 packets in its congestion window. This is part of the imported profile, not an isolated comparison of equal initial windows. Pacing remains enabled. After all in-flight data drains and the sender is idle for at least three PTOs (one second minimum), this port restarts bandwidth learning with the initial window. It retains RTT/MTU and the configured profile. ACK-only traffic does not extend idle capacity validity, and a slow active flight is not mistaken for idle. This bounds stale-window reuse after a bandwidth change during idle, at the cost of another startup phase after long pauses; it does not guarantee zero drops on arbitrary bottlenecks. The existing block format is retained; the base application now has adaptive compression and global admission. A faster DEFLATE decoder was rejected because the prior WAN pilot did not improve materially.

## Limits

The measurements do not establish universal acceleration, long-term stability, fairness to competing flows, mobile path migration, or MTU-change behavior in a real WAN. Path migration is unit-tested only. The imported BBR controller has no spurious-loss undo callback; the adapter forwards one only when a controller implements it. Upstream transport recovery fixes are retained, but this does not imply identical recovery behavior between Reno and BBR.

Keep this build isolated until representative long-running tests justify maintaining a transport patch. To roll back, stop the experimental process and run the ordinary build with the same compatible configuration. No protocol migration is needed.
