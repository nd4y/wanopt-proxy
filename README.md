# wanopt-proxy

A WAN optimizer built on **QUIC**. The client (Windows) exposes a local
**SOCKS5 / HTTP** proxy; traffic is multiplexed over a single authenticated
QUIC tunnel and egresses from the server (Linux / Docker).

## Why QUIC

- **Forward secrecy for free** — QUIC mandates TLS 1.3 with ephemeral ECDHE.
- **No head-of-line blocking** — each proxied TCP connection is an independent
  QUIC stream, so one lossy flow does not stall the others (unlike TCP-in-TCP).
- **UDP relay** — UDP flows ride QUIC DATAGRAM frames (SOCKS5 UDP ASSOCIATE).
- **Connection migration & keepalive** — survives client IP/network changes.

## Security model (PSK + pinning, no PKI)

- The server presents a **self-signed certificate**; the client pins its
  **SPKI SHA-256** hash. No CA, no `InsecureSkipVerify` blind trust.
- On top of the pinned TLS 1.3 channel, both ends prove knowledge of a shared
  **PSK** via `HMAC(PSK, label ‖ TLS-exporter)`. The exporter is unique per
  session, so the proof is **replay-proof** and authenticates **both** peers.

## Layout

```
cmd/server    egress daemon (Linux/Docker)
cmd/client    ingress proxy (Windows)
cmd/keygen    generates PSK + server cert/pin
internal/protocol  address codec + stream/datagram framing
internal/tunnel    TLS (self-signed + pinning), PSK auth, tuned quic.Config
internal/server    QUIC listener, TCP relay, UDP NAT, ACL enforcement
internal/client    QUIC dial/auth + background reconnect + heartbeat
internal/proxy     SOCKS5 (+UDP ASSOCIATE) and HTTP (CONNECT/forward)
internal/acl       destination allow/deny policy (domain / IP-CIDR / port)
internal/compress  adaptive, probe-based stream compression
internal/metrics   Prometheus collectors + quic-go tracer (RTT/loss/cwnd)
```

## Optimizations & features

- **Access control (server)** — allow/deny destinations by domain suffix, IP/CIDR
  and port, for both TCP and UDP. Deny wins; a non-empty allow list is a whitelist.
- **Resilient tunnel (client)** — a background maintainer keeps one authenticated
  connection up, reconnecting with exponential backoff. A control-stream
  heartbeat detects dead tunnels within a few seconds. *In-flight TCP streams
  cannot survive a tunnel drop (the remote socket lives on the server); the
  maintainer instead makes new requests recover fast.*
- **High-BDP throughput** — large stream/connection receive windows (16/24 MiB
  default, tunable) keep long fat links full. *Note: quic-go v0.48 uses CUBIC
  internally and exposes no public BBR switch, so window sizing — not the CC
  algorithm — is the lever here.*
- **Adaptive compression** — each direction probes its first chunk and only
  applies DEFLATE when the sample is actually compressible, so TLS/video/archives
  pass through untouched (no wasted CPU, no expansion).
- **Metrics & 0-RTT** — Prometheus `/metrics` exposes per-tunnel RTT, congestion
  window, packet loss, byte counters and stream/reconnect stats. 0-RTT session
  resumption speeds reconnects; for replay safety, auth and proxy traffic are
  never sent as 0-RTT early data.
- **HTTP/3 camouflage** — ALPN defaults to `h3`; run the server on `:443` so the
  handshake is indistinguishable from HTTP/3. *(Lightweight: a determined prober
  that speaks HTTP/3 gets no decoy site — that would need a real h3 fallback.)*

## Quick start

```sh
# 1. Generate secrets (writes cert.pem/key.pem, prints psk + pin)
go run ./cmd/keygen -cert

# 2. Server config (configs/server.yaml): set psk, cert_file, key_file
go run ./cmd/server -config configs/server.yaml

# 3. Client config (configs/client.yaml): set server, psk, pin
go run ./cmd/client -config configs/client.yaml

# 4. Point your browser/app at socks5://127.0.0.1:1080 or http://127.0.0.1:8080
curl -x socks5h://127.0.0.1:1080 https://example.com
```

### Docker (server)

```sh
docker compose up --build -d
```

## Build native binaries

```sh
# Server (Linux)
GOOS=linux  GOARCH=amd64   go build -o bin/wanopt-server ./cmd/server
# Client (Windows)
GOOS=windows GOARCH=amd64  go build -o bin/wanopt-client.exe ./cmd/client
```

## Roadmap / possible improvements

- BBR congestion control once quic-go exposes a public selector.
- HTTP keep-alive on the plain-HTTP forward path (currently one request/conn).
- True HTTP/3 decoy site for full DPI camouflage.
- MASQUE / CONNECT-UDP (RFC 9298) compatibility mode.
- Per-destination ACL metrics and structured audit logging.
