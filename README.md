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
internal/tunnel    TLS (self-signed + pinning) and PSK auth
internal/server    QUIC listener, TCP relay, UDP NAT
internal/client    QUIC dial/auth/reconnect + datagram dispatch
internal/proxy     SOCKS5 (+UDP ASSOCIATE) and HTTP (CONNECT/forward)
```

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

- BBR congestion control tuning for high-BDP links.
- 0-RTT session resumption (guarded against replay for non-idempotent use).
- Adaptive, content-type-aware compression.
- Access-control lists (allow/deny destinations) on the server.
- Prometheus metrics (per-stream RTT, loss, throughput).
- HTTP/3 (`:443`, ALPN `h3`) camouflage option for DPI-heavy networks.
- MASQUE / CONNECT-UDP (RFC 9298) compatibility mode.
