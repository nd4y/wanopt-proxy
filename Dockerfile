FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=512MiB
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/server ./cmd/server
COPY cmd/keygen ./cmd/keygen
COPY internal ./internal
RUN --mount=type=cache,target=/root/.cache/go-build go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/wanopt-server ./cmd/server \
 && go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/wanopt-keygen ./cmd/keygen

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/wanopt-server /usr/local/bin/wanopt-server
COPY --from=build /out/wanopt-keygen /usr/local/bin/wanopt-keygen
USER 10001:10001
WORKDIR /etc/wanopt
EXPOSE 4242/udp
ENTRYPOINT ["/usr/local/bin/wanopt-server"]
CMD ["-config", "/etc/wanopt/server.yaml"]