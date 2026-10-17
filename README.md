# wanopt-proxy

**English** | [Русский](README.ru.md)

An authenticated QUIC tunnel with local SOCKS5 and HTTP proxies. Each TCP
connection uses an independent HTTP/3 CONNECT stream; UDP uses QUIC DATAGRAM.
The client reconnects in the background and the server enforces destination ACLs.

Protocol v2 prioritizes bounded resource use, cancellation and correct forwarding.
It requires **Go 1.27.2** and **quic-go 0.64.0**. Client and server must both use v2.

## What to expect

- Independent streams avoid TCP-in-TCP retransmission coupling. Congestion control
  and the connection receive window remain shared, so flows still compete.
- QUIC is not automatically faster than direct TCP. CPU, RTT, loss, payload size
  and the host network stack determine the result. Use the included comparison.
- A lost tunnel terminates existing TCP connections. New requests wait within a
  deadline and recover after reconnect. There is no transparent TCP session replay
  or guarantee that a network/IP change preserves an active connection.
- UDP is unreliable and has an **850-byte payload limit** in both directions.
  Larger packets are rejected and counted; there is no fragmentation/reassembly.
  Applications requiring larger UDP packets need another transport.
- Compression is **off by default**. Enable it on both endpoints for compressible
  traffic only. Bounded 32 KiB blocks independently choose raw or DEFLATE encoding.
  Raw blocks still add a 5-byte header and incur a compression trial; TLS, video
  and archives usually gain nothing. Compressing mixed secrets and attacker-chosen
  plaintext can expose length information.

## Authentication and access

The client verifies the server's SHA-256 SPKI pin in the TLS 1.3 handshake. Both
peers then authenticate with HMAC over a shared PSK and the TLS exporter for that
connection. This also runs after TLS session resumption. Authentication and proxy
data are never sent as 0-RTT early data. Tickets improve reconnect handshakes;
`disable_session_resumption: true` disables the client ticket cache.

TCP and UDP egress require authentication. ACLs check ports, the requested name
and the actual resolved IP before opening a socket. DNS resolution is bounded;
the checked address is used directly so the dial cannot resolve it again. Deny
rules take precedence. A domain allow rule still cannot bypass an IP deny rule.
Empty allow lists permit all destinations, including private networks: configure
an egress policy appropriate to your server. The PSK grants shared access, with
no per-user isolation or credentials.

Local proxies have no user authentication and bind to loopback by default.
Non-loopback binds require `allow_remote_proxy: true`; use them only with an
external access policy. SOCKS UDP associations are bound to their TCP peer and
UDP source port. SOCKS authentication methods other than no-auth and fragmented
SOCKS datagrams are not supported.

The optional HTTP/3 site (`decoy.mode: builtin | proxy | dir | off`) is off by
default. It offers **no indistinguishability guarantee** against active probes or
traffic analysis. The tunnel uses recognizable HTTP/3 CONNECT authorities and a
version header. This is a custom protocol, not interoperable MASQUE CONNECT-UDP.

## Quick start

```sh
cp configs/server.example.yaml configs/server.yaml
cp configs/client.example.yaml configs/client.yaml
# Writes new cert.pem/key.pem in configs and prints a PSK and pin.
# Existing certificate/key files are never overwritten.
go run ./cmd/keygen -cert -out configs
```

Set `psk` in both files, `pin` and `server` in the client file. Keep the generated
server certificate and private key across restarts. Certificate/key/site paths
are relative to the configuration file. Store the PSK and private key securely;
never commit your filled configuration files. An ephemeral certificate requires
explicit `allow_ephemeral_cert: true` and changes the pin on every restart.

```sh
go run ./cmd/server -config configs/server.yaml
go run ./cmd/client -config configs/client.yaml
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

Plain HTTP supports keep-alive, streamed bodies, 100-continue, early responses
and protocol upgrade. CONNECT and SOCKS preserve TCP half-close, allowing a peer
to finish sending its response after the other side sends FIN. Application idle
timeouts still apply.

### Docker server

```sh
# Run once on Linux after generating the files. Preserve the private key mode.
sudo chown 10001:10001 configs/key.pem configs/cert.pem configs/server.yaml
sudo chmod 600 configs/key.pem configs/server.yaml
# The directory must be traversable by UID 10001.
docker compose up --build -d
```

The pinned multi-stage build produces a scratch image with CA certificates and
two static binaries. It runs as UID/GID 10001. Compose uses a read-only root
filesystem, drops capabilities, forbids privilege escalation and rotates logs.
It publishes UDP 4242. Metrics bound to container loopback are only accessible
inside its network namespace; intentionally configure and restrict access when
using an external collector. The key-generation helper can also run from the
image with a writable directory explicitly mounted and owned by UID 10001.

## Resource and failure controls

Examples list every supported operational limit. Unknown YAML keys, multiple
YAML documents, invalid pins, mismatched cert/key paths, invalid ports and
inconsistent receive windows fail at startup.

| Control | Default | Scope |
| --- | --- | --- |
| Handshake/auth deadline | 10 s | Each tunnel |
| TCP open/reply deadline | 15 s | Each request |
| Server connections | 256 | Whole server, including authentication |
| Proxy streams | 128 plus one control stream | Each server connection |
| Pending client requests | 256 | Whole client |
| Local proxy connections | 256 | Shared between HTTP and SOCKS |
| Local handshake / application idle | 10 s / 300 s | Each proxy connection |
| HTTP response headers | 120 s, 64 KiB | Each forwarded response |
| DNS | 5 s, 32 concurrent | Whole server resolver |
| UDP flows / new flows | 256 / 32 per second | Each tunnel |
| UDP queues / admission workers | 128 / 4 | Each tunnel; existing flows have a separate queue |
| UDP flow idle | 60 s | Each outbound socket |
| Client UDP sessions | 128 | Whole client |
| Maximum stream / connection receive window | 16 / 24 MiB | Each tunnel |

Windows grow on demand; these limits are not a total process memory budget.
Choose smaller connection/flow limits for a single-user or low-memory host and
measure RSS and CPU under the expected concurrency. For a high-bandwidth link,
size the receive window against bandwidth-delay product and available memory.
No BBR selection is exposed by this application.

Shutdown cancels listeners, pending opens, streams and UDP workers and waits for
them to exit. The server releases its UDP socket for immediate same-port restart.
Limits reject excess work instead of creating unbounded waiters. Existing UDP
flows continue while new-flow DNS work is saturated.

## Metrics

Set `metrics_listen` to expose Prometheus `/metrics` (empty disables it). Keep the
endpoint private. Labels have bounded cardinality; destinations are not labels.

- `wanopt_relay_bytes_total{dir}` counts successfully relayed payload continuously,
  including HTTP and UDP. It does not measure QUIC wire bytes or compression ratio.
- `wanopt_active_streams`, `wanopt_streams_total`, `wanopt_dial_errors_total`.
- `wanopt_tunnel_connections` and `wanopt_tls_resumptions_total` count authenticated tunnels.
- `wanopt_tunnel_reconnects_total` counts reconnect attempts, including after failed authentication.
- `wanopt_tunnel_rtt_seconds` is the maximum current smoothed RTT;
  `wanopt_congestion_window_bytes` is the sum over active tunnels.
- `wanopt_lost_packets` is a current gauge, not a cumulative counter. QUIC loss
  reclassification and disconnects can decrease it.
- `wanopt_udp_flows`, `wanopt_udp_datagrams_total{dir}` and
  `wanopt_udp_dropped_total{reason}` report UDP load and rejected/lost packets.

Connection statistics are sampled at scrape time without per-packet tracing.

## Build and verify

```sh
go mod verify
go vet ./...
go test ./...
go test -race ./... # Linux/CGO toolchain
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o bin/wanopt-server ./cmd/server
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o bin/wanopt-client.exe ./cmd/client
```

CI runs Linux and Windows tests, Linux race tests, fuzz smoke tests, govulncheck,
cross builds and the Docker build. Regression tests use real loopback QUIC/TLS,
TCP and UDP, including unauthenticated egress rejection and oversized QPACK
headers. They cover cancellation, capacity recovery, server restart, resumed
pin validation, HTTP edge cases, SOCKS source checks and malformed codecs.

See [benchmark instructions](docs/benchmarks.md) for direct TCP, TCP relay and
QUIC comparisons with reproducible RTT/loss injection. Measurements are local
experiments and do not replace a soak test on the deployment network.

## Upgrading from v1

1. Back up the existing binaries and configuration, including the persistent key.
2. Update both endpoints together. v2 replaces custom stream hijacking with
   standard HTTP/3 CONNECT and changes the compressed stream framing. v1 peers
   are incompatible; in-flight sessions cannot be migrated during upgrade.
3. Copy the new example settings and transfer your endpoint, PSK, pin and ACL.
   Generate a persistent cert/key only if you do not already have one, and update
   the pin when changing keys. Compression now defaults to off, as does the site.
4. `allow_0rtt` and `enable_0rtt` are accepted only as ignored legacy keys. Use
   `disable_session_resumption` for session tickets. ALPN must be `h3`.
5. Update dashboards for the new RTT/loss/resumption semantics and validate your
   required UDP packet sizes. Rollback requires restoring both v1 endpoints and
   their configuration together; do not mix protocol generations.
