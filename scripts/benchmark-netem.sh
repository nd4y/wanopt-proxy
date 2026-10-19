#!/bin/sh
# Run only inside a fresh network namespace, never in the host namespace.
set -eu
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)" ]; then
    echo 'Refusing to alter the host network namespace. Use: sudo unshare -n ...' >&2
    exit 1
fi
binary=${1:?Usage: benchmark-netem.sh /absolute/path/relay.test [iterations]}
iterations=${2:-3x}
ip link set lo up
trap 'tc qdisc del dev lo root 2>/dev/null || true' EXIT INT TERM
for rtt in 0 50 150; do
    for loss in 0 0.1 1; do
        tc qdisc del dev lo root 2>/dev/null || true
        tc qdisc add dev lo root handle 1: prio bands 3
        tc qdisc add dev lo parent 1:3 handle 30: netem delay "$((rtt / 2))ms" loss "${loss}%" limit 10000
        # Shape the client-facing leg only. Egress uses 127.0.0.2.
        tc filter add dev lo parent 1: protocol ip prio 1 u32 \
            match ip src 127.0.0.1/32 match ip dst 127.0.0.1/32 flowid 1:3
        printf '\nRTT=%sms LOSS=%s%%\n' "$rtt" "$loss"
        GOMAXPROCS=2 "$binary" -test.run '^$' -test.bench '^BenchmarkRelay$' \
            -test.benchtime "$iterations" -test.timeout 3m
    done
done
