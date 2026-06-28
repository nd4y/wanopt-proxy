# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wanopt-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wanopt-keygen ./cmd/keygen

# Runtime stage
FROM alpine:3.20
RUN adduser -D -u 10001 wanopt
COPY --from=build /out/wanopt-server /usr/local/bin/wanopt-server
COPY --from=build /out/wanopt-keygen /usr/local/bin/wanopt-keygen
USER wanopt
EXPOSE 4242/udp
ENTRYPOINT ["wanopt-server"]
CMD ["-config", "/etc/wanopt/server.yaml"]
