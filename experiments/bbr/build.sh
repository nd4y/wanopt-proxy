#!/usr/bin/env bash
# Build the exact isolated BBR experiment; the normal module stays untouched.
set -euo pipefail
export GOWORK=off
export GOTOOLCHAIN=go1.27.2
base=88fbe38901713ff2975870f89b33e20de86c258d
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
output=${1:?Usage: bash experiments/bbr/build.sh NEW_OUTPUT_DIRECTORY}
if [[ -e "$output" ]]; then echo 'Output directory must not exist' >&2; exit 1; fi
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd)
work=$(mktemp -d -t wanopt-bbr.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
test_with_events() {
 local suite=$1
 shift
 if [[ -n "${WANOPT_EVENT_DIR:-}" ]]; then
  mkdir -p -- "$WANOPT_EVENT_DIR"
  go test -json "$@" | tee "$WANOPT_EVENT_DIR/$suite.jsonl"
 else
  go test "$@"
 fi
}
mkdir "$work/app"
git -C "$repo" archive "$base" | tar -x -C "$work/app"
(cd "$repo" && go mod download github.com/quic-go/quic-go@v0.64.0)
cache=$(go env GOMODCACHE)
cp -R "$cache/github.com/quic-go/quic-go@v0.64.0" "$work/quic-bbr-transport"
chmod -R u+w "$work/quic-bbr-transport"
(cd "$work/quic-bbr-transport" && git apply "$here/quic-go.patch" && go mod verify && test_with_events transport -race ./internal/ackhandler ./internal/congestion ./http3 . -timeout=5m)
cd "$work/app"
git apply "$here/wanopt.patch"
cp "$here/coherence_test.go.txt" internal/congestion/bbr/release_coherence_test.go
go mod verify
test_with_events application -race ./... -timeout=5m
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
for target in client server keygen; do
 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$output/wanopt-$target" "./cmd/$target"
done
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$output/wanbench" ./tools/wanbench
printf '%s\n' "$base" > "$output/BASE_COMMIT"
sha256sum "$here/wanopt.patch" "$here/quic-go.patch" > "$output/PATCH_SHA256"
printf 'Experimental binaries: %s\n' "$output"
