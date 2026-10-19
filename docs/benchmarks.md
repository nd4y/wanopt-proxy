# Relay benchmark

The benchmark compares direct TCP, a plain TCP relay, QUIC without compression,
and QUIC with block compression. Each operation uploads 256 KiB and validates an
identical echo. Throughput counts both directions (512 KiB/operation). Each
operation opens a new application connection/stream; QUIC reuses one authenticated
tunnel. One complete warmup exchange runs outside timing. Random and repetitive
payloads are separate. SOCKS/HTTP parsing and metrics are excluded.

This measures application exchange time and allocations, not link capacity or
wire savings. Compression throughput counts uncompressed payload. Short runs
have substantial noise, especially with random losses and TCP retransmission
backoff. Use repeated longer runs and CPU/RSS/wire measurements on your deployment
network before deciding that QUIC or compression improves your workload.

```sh
GOMAXPROCS=2 go test -run '^$' -bench '^BenchmarkRelay$' -benchtime=10x -count=3 ./internal/server
GOMAXPROCS=2 go test -run '^$' -bench . -benchmem ./internal/compress
```

## Isolated RTT/loss matrix (Linux)

Requires Go, iproute2 (`ip`, `tc`), util-linux (`unshare`) and permission to create
a network namespace. Build as the normal user; only the isolated namespace needs
root. No host interface or existing container network is modified. The script
refuses the initial network namespace.

```sh
GOMAXPROCS=2 go test -c -o /tmp/wanopt-relay.test ./internal/server
sudo unshare -n sh ./scripts/benchmark-netem.sh /tmp/wanopt-relay.test 10x
```

The matrix uses target RTT 0/50/150 ms and independent packet loss 0/0.1/1%.
A netem delay of RTT/2 applies in each direction. Only packets whose source AND
destination are 127.0.0.1 are shaped. The relay-to-origin leg uses 127.0.0.2 and is
not shaped, so relay modes do not accidentally traverse two simulated WANs.
Loopback/GSO, an unlimited bitrate and a shared CPU remain lab simplifications.
The three-iteration smoke matrix is a functional comparison, not a statistically
stable performance result. Real acceptance should add a bitrate cap, several
concurrent clients, realistic payloads, IPv6, changing MTU and long-duration runs.

## Local smoke results (2026-10-18)

Go 1.27.2, linux/amd64 in WSL2, AMD Ryzen 7 8845HS, GOMAXPROCS=2. Three timed
exchanges per cell after warmup. Table values are **milliseconds per complete
256 KiB upload + 256 KiB echo**, not sustained throughput. No bitrate cap.

| Payload | RTT / loss | Direct TCP | TCP relay | QUIC raw | QUIC compressed |
| --- | --- | ---: | ---: | ---: | ---: |
| Random | 0 ms / 0% | 1.29 | 1.23 | 3.65 | 3.70 |
| Random | 50 ms / 0% | 402.80 | 403.30 | 212.37 | 212.29 |
| Random | 150 ms / 0% | 1203.01 | 1203.52 | 634.39 | 633.90 |
| Random | 150 ms / 1% | 1203.63 | 1204.09 | 1888.54 | 2829.23 |
| Repetitive | 0 ms / 0% | 0.96 | 1.52 | 3.26 | 2.53 |
| Repetitive | 50 ms / 0% | 402.71 | 402.71 | 213.10 | 154.07 |
| Repetitive | 150 ms / 0% | 1203.24 | 1202.87 | 633.15 | 456.67 |
| Repetitive | 150 ms / 1% | 1203.07 | 1314.14 | 1466.26 | 515.20 |

All nine RTT/loss combinations completed and verified payloads in every mode.
The reused QUIC tunnel saves connection setup in the no-loss WAN cases. QUIC
costs more on zero-delay loopback. Compression helps repetitive data but is not
an improvement for random data. Loss samples vary widely; this small run is not
evidence of a reliable QUIC advantage under loss. TCP segmentation/offload on
loopback also affects how netem's per-packet loss compares with QUIC packets.

These results justify keeping compression opt-in and measuring the actual
workload. They do not establish production bandwidth, p99 latency, RSS ceilings,
network migration, fairness across many clients or long-run stability.
