# Operating limits, adaptive compression and credential rotation

These changes retain protocol v2 and its existing block format. A v2 peer with one PSK can authenticate against a new server using either active key during the configured overlap. New configuration fields require a new binary; older strict configuration loaders reject unknown fields.

## Process-wide admission

Both peers accept `max_active_streams` (default 128, range 1..4096) and `max_compressed_streams` (default min(16, active limit), range 1..128, at most the active limit). They apply across all authenticated TCP tunnels, in addition to existing per-connection limits. Control/auth streams are excluded so capacity exhaustion does not prevent tunnel maintenance.

Admission has no waiting queue. A full stream budget rejects immediately. The client preserves a typed capacity error; ordinary HTTP and CONNECT report 503 rather than a misleading upstream network error. SOCKS reports its standard general failure. Non-idempotent requests are never silently replayed. Existing bounded pending dial and UDP limits still apply separately.

An unauthenticated QUIC connection has one authentication deadline starting at server accept. Opening ordinary HTTP/3 requests or sending transport keepalives does not extend it. This also bounds the lifetime of unauthenticated cover-site connections; the cover site is not a general-purpose long-lived web hosting service. Authenticated connections retain their normal idle and heartbeat behavior.

A full codec budget negotiates raw data inside the authenticated, encrypted tunnel. It does not bypass TLS or destination ACL. A compressed-stream lease covers both encoder and decoder state. Half-close retains the client lease until the other half closes. Error, full close and tunnel cancellation release leases idempotently; server relay workers are joined before their leases return.

Idle HTTP streams retain codec state too. The HTTP pool therefore keeps at most half of the client's active-stream budget and, when compression is enabled, half of its codec budget. The smaller value applies. A budget of one disables upstream HTTP keepalive; choose at least two to retain an idle compressed connection while reserving room for a new destination. This prevents idle connections to old destinations from blocking unrelated new requests.

These are admission counts, not a hard aggregate memory-byte cap. QUIC receive windows, connection count, UDP sockets and application queues must also fit the host. Use a cgroup/container limit as the final host protection and size admission limits below it.

A small-node starting profile to validate against the actual workload:

```yaml
max_connections: 8
max_active_streams: 8
max_compressed_streams: 2
max_stream_recv_window_mb: 2
max_conn_recv_window_mb: 4
```

On the server also set `max_streams_per_connection: 8` and small UDP limits appropriate to the workload. On the client `max_connections` limits local proxy clients; `max_pending_requests` bounds pending dials. Explicitly validate actual workload memory before raising limits.

## Adaptive block compression

Compression stays opt-in. Encoders are allocated lazily. Reads shorter than 256 bytes are sent raw immediately. After three consecutive attempts saving less than 10%, the encoder skips the next 256 KiB, then probes again. A successful probe resumes compression. This costs no extra source buffering or application-level retry and preserves interactive flushing.

The backoff is local to the byte stream and adapts again if incompressible content changes to compressible content. Headers, TLS ciphertext, archives and images are not guessed from the destination. The existing raw/DEFLATE frames remain compatible. The encoder pool retains at most two idle encoders; active codec state is bounded by admission.

A short incompressible prefix still costs probing CPU, and the first portion of newly compressible data during backoff can be sent raw. Compression cannot expose or compress HTTPS plaintext; encrypted application traffic generally benefits only from skipping wasted encoding work.

## PSK and certificate rotation

The server accepts the primary `psk` plus optional `previous_psk` until `previous_psk_expires`. The client accepts its primary `pin` plus optional `next_pin` until `next_pin_expires`. Expiry uses RFC3339 with an explicit timezone, preferably UTC. An alternate credential requires an expiry no more than seven days ahead. Expired alternates are ignored; primary credentials stay active. Maintain synchronized clocks on the two peers.

Use versioned certificate/key files and atomically replace the config after both files are complete. Send SIGHUP to the Linux server process, or use `docker compose kill -s HUP wanopt-server`. The server validates a complete replacement before publishing one immutable credential snapshot. SIGHUP accepts credential material and certificate paths only; changing runtime settings at the same time is rejected. Bad YAML, invalid key/certificate pairs, oversized files and special files leave the current snapshot active. Unix opens special files nonblocking so a mistaken FIFO cannot hang reload/shutdown.

For rotation without stopping every client together:

1. Distribute the next certificate pin to clients using `next_pin` with a short expiry. Apply client configs in batches.
2. Configure the server's new primary PSK, previous PSK with a short overlap, and new versioned certificate paths. Send SIGHUP.
3. Old-key sessions continue during the overlap. Update clients in batches to the new primary PSK and primary pin, removing the temporary next-pin entry. Client config changes take effect on process restart.
4. Remove the previous PSK and send SIGHUP again. Removed-key sessions are closed immediately; expiry also closes existing old-key sessions within one second. New CONNECTs using an expired key are denied immediately.

Revocation closes TCP/UDP tunnel sessions authenticated with that key. It is intentionally disruptive to those sessions. Certificate replacement alone preserves existing authenticated sessions; subsequent TLS handshakes, including resumptions, still enforce the configured pin set. This does not preserve arbitrary application TCP sessions across a tunnel restart.

## QUIC congestion selection

`congestion_control: reno` is the normal default. `bbr` is available only in the [experimental recipe](../experiments/bbr/README.md); an ordinary build rejects it at startup. Configure each endpoint explicitly to select both directions. No environment variable or live concurrent controller replacement is used.

The port retains upstream quic-go 0.64.0, propagates the actual outstanding-packet watermark to BBR instead of guessing a fixed reordering threshold, and rescales packet-sized windows when quic-go falls back from a 1280-byte Initial packet to 1200 after EMSGSIZE. Regression tests cover both cases. Imported BBR still has no spurious-loss undo implementation; do not infer identical recovery behavior to Reno or universal acceleration.

To leave BBR, set the algorithm to `reno` and restart the experimental process, or use the ordinary binary with a compatible config. To roll back to an older v2 binary, remove the new configuration fields first while retaining the currently valid primary PSK/pin. No new wire migration is required by these changes.

## Bounded diagnostics

Existing RTT, congestion-window, loss snapshots, payload, reconnect and UDP-drop metrics remain. Added metrics include:

- `wanopt_admitted_streams`, `wanopt_admitted_codecs` and `wanopt_admission_rejected_total{resource}`.
- `wanopt_codec_capacity_fallback_total`.
- Compression input/output bytes (output includes framing), attempted/skipped/compressed block counts and wall time spent encoding.
- `wanopt_operation_failures_total{stage,reason}` and `wanopt_operation_seconds{stage}`. Reasons include timeout, cancellation, capacity and other errors. Histograms include successful and failed operations.
- `wanopt_congestion_controller{algorithm}` showing the configured userspace controller.

All application label values are selected from fixed lists. No peer address, destination, key identifier or payload becomes a metric label. Compression counters flush once per MiB or on stream completion; very small idle streams can delay their updates. Metrics scraping does not enable packet tracing or a profiling HTTP listener.

## Reproducible performance and failure tests

`tools/wanbench` prebuilds a bounded fixture set before serving. Unprepared GET sizes fail rather than silently adding fixture generation to the measurement. Setup, warmup and measured phases are separate. Worker concurrency uses independent HTTP transports; every complete transfer checks byte count, SHA256 and status. At most 4096 latency samples per worker are retained using reservoir sampling; reported p50/p95/p99 are approximate once the sample limit is reached.

```sh
go build -o /tmp/wanbench ./tools/wanbench
/tmp/wanbench -serve -fixture-sizes 1,1048576 -listen 127.0.0.1:25243
# In another terminal, using an explicitly configured local proxy:
/tmp/wanbench -url http://127.0.0.1:25243 -proxy http://127.0.0.1:8080 \
  -kind random -bytes 1048576 -direction POST -warm -duration 60s -concurrency 2 \
  -stream -request-timeout 90s
```

With `-stream`, each worker sends one continuous body for the duration, repeating its prebuilt fixture with bounded memory. GET checks final byte-count and SHA256 trailers; POST checks the origin's final byte count and SHA256 and rejects a response before upload EOF. Timing includes final delivery and integrity verification. Duration is at most two minutes, body length at most 16 GiB, and request timeout must exceed duration by at least five seconds. Without `-stream`, duration repeats complete finite requests, which measures application request goodput and latency rather than one sustained flow.

`-slow-read-delay`, `-slow-write-delay` and `-abort-after` exercise backpressure and cancellation. The abort probe runs outside timing and is followed by a complete integrity-checked transfer; it cannot be combined with `-stream`. `-cpuprofile` and `-memprofile` optionally write local profiles with restrictive permissions and refuse to overwrite an existing file. No profiling endpoint is opened. Codec and relay benchmarks can additionally use normal `go test -cpuprofile/-memprofile` flags to include the actual encoder/QUIC relay stack in profiles.

Steady application goodput, startup latency, payload savings, CPU, tail latency and memory stability answer different questions. Retain regressions and failures, randomize comparison order, use repeated runs, and test concurrent bulk/interactive/TCP traffic. Short synthetic gains do not establish production fairness or long-term stability.

An optional container override is available as `docker-compose.small.yaml`. It caps one server at one CPU, 128 MiB including swap allowance (no extra swap), and 128 tasks, with a 64 MiB Go soft heap target. Use it together with the small admission/window/UDP settings above; it is a starting profile, not a guarantee for arbitrary workloads. Apply it explicitly with `docker compose -f docker-compose.yaml -f docker-compose.small.yaml up -d` after preparing the normal config and readable certificate files. No running deployment is changed by adding this file.
