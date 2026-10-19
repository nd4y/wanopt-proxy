#!/usr/bin/env python3
"""Exercise actual release processes. Credentials live only in a temporary dir.

--netem creates two owned, directly connected namespaces on a disposable runner.
It never changes a pre-existing interface, route, firewall rule or host sysctl.
"""
import argparse
import base64
import contextlib
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def command(args, timeout=30, check=True):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{Path(str(args[0])).name} exited {p.returncode}: {p.stderr[-1000:]}")
    return p


def metric(text, name):
    return sum(float(line.split()[-1]) for line in text.splitlines()
               if line.startswith(name + "{") or line.startswith(name + " "))


def udp_counters(text):
    lines = text.splitlines()
    for i, line in enumerate(lines[:-1]):
        if line.startswith("Udp:"):
            return dict(zip(line.split()[1:], map(int, lines[i + 1].split()[1:])))
    raise ValueError("UDP counters missing")


def check_udp(before, after):
    keys = ("SndbufErrors", "RcvbufErrors", "InErrors", "InCsumErrors", "MemErrors", "NoPorts")
    delta = {k: after.get(k, 0) - before.get(k, 0) for k in keys}
    if any(delta.values()):
        raise AssertionError(f"unexpected namespace UDP errors: {delta}")
    return delta


class Network:
    def __init__(self, enabled):
        self.enabled = enabled
        suffix = secrets.token_hex(3)
        self.names = ["wvc" + suffix, "wvs" + suffix]
        self.links = ["wvcv" + suffix, "wvsv" + suffix]
        self.created = []

    def prefix(self, side):
        return ["ip", "netns", "exec", self.names[side]] if self.enabled else []

    @property
    def address(self):
        return "10.254.98.2" if self.enabled else "127.0.0.1"

    def setup(self):
        if not self.enabled:
            return
        if os.geteuid() != 0:
            raise RuntimeError("--netem requires root on a disposable runner")
        for name in self.names:
            command(["ip", "netns", "add", name])
            self.created.append(name)
        command(["ip", "link", "add", self.links[0], "type", "veth", "peer", "name", self.links[1]])
        for side in range(2):
            command(["ip", "link", "set", self.links[side], "netns", self.names[side]])
            p = self.prefix(side)
            command(p + ["ip", "addr", "add", f"10.254.98.{side + 1}/30", "dev", self.links[side]])
            command(p + ["ip", "link", "set", self.links[side], "up"])
            command(p + ["ip", "link", "set", "lo", "up"])
            command(p + ["ethtool", "-K", self.links[side], "gro", "off", "gso", "off", "tso", "off"])

    def profile(self, name):
        for side in range(2) if self.enabled else []:
            p = self.prefix(side)
            command(p + ["tc", "qdisc", "del", "dev", self.links[side], "root"], check=False)
            if name != "native":
                args = ["tc", "qdisc", "replace", "dev", self.links[side], "root", "netem",
                        "limit", "10000", "delay", "50ms", "5ms", "loss"]
                args += ["0.1%", "rate", "100mbit"] if name == "moderate" else ["1%", "rate", "20mbit"]
                command(p + args)

    def mtu(self, size):
        for side in range(2):
            command(self.prefix(side) + ["ip", "link", "set", self.links[side], "mtu", str(size)])

    def blackhole(self):
        for side in range(2):
            command(self.prefix(side) + ["tc", "qdisc", "replace", "dev", self.links[side],
                                        "root", "netem", "loss", "100%"])

    def counters(self):
        if not self.enabled:
            return []
        return [udp_counters(command(self.prefix(i) + ["cat", "/proc/net/snmp"]).stdout) for i in range(2)]

    def cleanup(self):
        errors = []
        for name in reversed(self.created):
            p = command(["ip", "netns", "del", name], check=False)
            if p.returncode:
                errors.append(name)
        if self.enabled:
            for link in self.links:
                command(["ip", "link", "del", link], check=False)
            remaining = command(["ip", "netns", "list"]).stdout
            errors += [name for name in self.created if name in remaining]
        if errors:
            raise RuntimeError(f"namespace cleanup failed: {errors}")


class Suite:
    def __init__(self, options, runtime):
        self.o, self.root = options, Path(runtime)
        self.net = Network(options.netem)
        self.processes = []
        self.report = {"controller": options.cc, "netem": options.netem, "cases": [], "measurements": []}
        self.suffix = ".exe" if os.name == "nt" else ""
        self.client = None

    def binary(self, name):
        p = self.o.bin.resolve() / (name + self.suffix)
        if not p.is_file():
            raise FileNotFoundError(p)
        return str(p)

    def record(self, name, **fields):
        self.report["cases"].append({"name": name, "passed": True, **fields})
        print(name + ": PASS", flush=True)

    def start(self, name, binary, args, side):
        log = open(self.root / (name + ".log"), "w+")
        env = dict(os.environ, GOMAXPROCS="2", GOMEMLIMIT="64MiB")
        if self.o.netem:
            env["QUIC_GO_DISABLE_GSO"] = "1"
        try:
            p = subprocess.Popen(self.net.prefix(side) + [self.binary(binary), *map(str, args)],
                                 cwd=self.root, stdout=log, stderr=log, env=env)
        except BaseException:
            log.close()
            raise
        self.processes.append((p, log))
        return p

    def stop(self, p, graceful=True):
        if p is None:
            return
        if p.poll() is not None:
            raise RuntimeError(f"process exited unexpectedly ({p.returncode})")
        p.terminate()
        try:
            code = p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
            raise RuntimeError("process did not stop within deadline")
        if graceful and os.name != "nt" and code != 0:
            raise RuntimeError(f"SIGTERM exit code {code}")

    def config(self, name, cfg):
        p = self.root / (name + ".json")
        p.write_text(json.dumps(cfg))
        os.chmod(p, 0o600)
        return str(p)

    def fetch(self, side, url):
        if not self.o.netem:
            with urllib.request.urlopen(url, timeout=1) as r:
                return r.read().decode()
        code = "import urllib.request,sys;sys.stdout.write(urllib.request.urlopen(sys.argv[1],timeout=1).read().decode())"
        return command(self.net.prefix(side) + [sys.executable, "-c", code, url], timeout=3).stdout

    def ready(self, side, url, condition=lambda text: True, timeout=15):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if any(p.poll() is not None for p, _ in self.processes if p is self.client or p is self.server or p is self.origin):
                raise RuntimeError("owned process exited during readiness")
            try:
                text = self.fetch(side, url)
                if condition(text):
                    return text
            except (OSError, RuntimeError):
                pass
            time.sleep(.1)
        raise RuntimeError("readiness or lease drain timed out")

    def bench(self, name, direction, kind="random", proxy=True, extra=(), success=True, size=262144):
        args = [self.binary("wanbench"), "-url", self.proxy_target if proxy else self.direct,
                "-kind", kind, "-bytes", str(size), "-direction", direction,
                "-request-timeout", "20s", "-label", name]
        if proxy:
            args += ["-proxy", self.proxy]
        args += list(extra)
        p = command(self.net.prefix(0) + args, timeout=45, check=False)
        try:
            result = json.loads(p.stdout)
        except json.JSONDecodeError:
            result = {"integrity": False, "no_result": True, "error": p.stderr[-1000:]}
        ok = result.get("integrity") is True and p.returncode == 0
        self.report["measurements"].append({"case": name, "expected_success": success,
                                             "exit": p.returncode, "result": result})
        if ok != success:
            self.report["cases"].append({"name": name, "passed": False})
            raise AssertionError(f"{name}: unexpected benchmark outcome: {result}")
        self.record(name)
        return result

    def rejected(self, name, target):
        # Raw absolute-form request: urllib's localhost proxy bypass must not
        # accidentally turn an ACL/authentication probe into a direct request.
        code = ("import http.client,sys; c=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]),timeout=6);"
                "c.request('GET',sys.argv[2]);r=c.getresponse();r.read();print(r.status);c.close()")
        port = self.proxy.rsplit(":", 1)[1]
        status = command(self.net.prefix(0) + [sys.executable, "-c", code, port, target], timeout=8).stdout.strip()
        if status != "502":
            raise AssertionError(f"{name}: expected gateway rejection 502, got {status}")
        self.record(name, expected_http_status=502)

    def drain(self):
        snapshots = []
        for side, url in [(0, self.cm), (1, self.sm)]:
            text = self.ready(side, url, lambda t: metric(t, "wanopt_admitted_streams") == 0
                              and metric(t, "wanopt_admitted_codecs") == 0, timeout=15)
            snapshots.append({"active": metric(text, "wanopt_admitted_streams"),
                              "codecs": metric(text, "wanopt_admitted_codecs"),
                              "reconnects": metric(text, "wanopt_tunnel_reconnects_total")})
        return snapshots

    def reload(self, cfg, rejected=False):
        log = self.root / "server.log"
        message = "credential reload rejected" if rejected else "credentials reloaded"
        count = log.read_text().count(message)
        self.config("server", cfg)
        self.server.send_signal(signal.SIGHUP)
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if self.server.poll() is not None:
                raise RuntimeError("server exited during credential reload")
            if log.read_text().count(message) > count:
                return
            time.sleep(.05)
        raise RuntimeError("credential reload result was not observed")

    def rotation(self, cfg, client_cfg):
        def expiry(seconds):
            return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)).isoformat()

        self.client = self.start("rotation-original", "wanopt-client", ["-config", self.config("client", client_cfg)], 0)
        self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
        for kind in ["bad", "runtime", "fifo"]:
            invalid = dict(cfg)
            if kind == "bad":
                invalid["unknown_credential_setting"] = True
            elif kind == "runtime":
                invalid["max_active_streams"] += 1
            if kind == "fifo":
                path = self.root / "server.json"
                path.unlink()
                os.mkfifo(path, 0o600)
                message = "credential reload rejected"
                count = (self.root / "server.log").read_text().count(message)
                self.server.send_signal(signal.SIGHUP)
                end = time.monotonic() + 5
                try:
                    while (self.root / "server.log").read_text().count(message) <= count:
                        if time.monotonic() >= end:
                            raise RuntimeError("FIFO reload blocked")
                        time.sleep(.05)
                finally:
                    path.unlink()
                    self.config("server", cfg)
            else:
                try:
                    self.reload(invalid, rejected=True)
                finally:
                    self.config("server", cfg)
            self.bench("reload-reject-" + kind, "GET", size=32768)
        rotated = self.root / "rotated"
        rotated.mkdir()
        output = command([self.binary("wanopt-keygen"), "-cert", "-out", str(rotated)]).stdout
        keys = dict(line.split(": ", 1) for line in output.splitlines() if line.startswith(("psk: ", "pin: ")))
        old_psk = client_cfg["psk"]
        client_cfg.update(next_pin=keys["pin"], next_pin_expires=expiry(3600))
        self.stop(self.client)
        self.client = self.start("rotation-overlap", "wanopt-client", ["-config", self.config("client", client_cfg)], 0)
        self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
        self.bench("rotation-before", "GET", size=32768)
        cfg.update(psk=keys["psk"], previous_psk=old_psk, previous_psk_expires=expiry(120),
                   cert_file=str(rotated / "cert.pem"), key_file=str(rotated / "key.pem"))
        self.reload(cfg)
        self.bench("rotation-old-session-grace", "POST", size=32768)
        self.stop(self.client)
        self.client = self.start("rotation-next-pin", "wanopt-client", ["-config", self.config("client", client_cfg)], 0)
        self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
        self.bench("rotation-next-pin-real-handshake", "POST", size=32768)
        with contextlib.ExitStack() as stack:
            sockets = [stack.enter_context(socket.socket()) for _ in range(2)]
            for sock in sockets:
                sock.bind(("127.0.0.1", 0))
            port, metrics_port = [sock.getsockname()[1] for sock in sockets]
        alternate = dict(client_cfg, psk=keys["psk"], pin=keys["pin"],
                         http_listen=f"127.0.0.1:{port}", metrics_listen=f"127.0.0.1:{metrics_port}")
        alternate.pop("next_pin", None)
        alternate.pop("next_pin_expires", None)
        proxy = self.proxy

        def alternate_bench(name):
            try:
                self.proxy = f"http://127.0.0.1:{port}"
                self.bench(name, "POST", size=32768)
            finally:
                self.proxy = proxy

        secondary = self.start("rotation-primary-key", "wanopt-client", ["-config", self.config("alternate", alternate)], 0)
        self.ready(0, f"http://127.0.0.1:{metrics_port}/metrics", lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
        alternate_bench("rotation-new-key")
        cfg.pop("previous_psk")
        cfg.pop("previous_psk_expires")
        self.reload(cfg)
        self.rejected("rotation-old-key-revoked", self.proxy_target + "/ping")
        alternate_bench("rotation-new-key-session-retained")
        self.stop(self.client)
        self.stop(secondary)
        client_cfg.update(psk=keys["psk"], pin=keys["pin"])
        client_cfg.pop("next_pin", None)
        client_cfg.pop("next_pin_expires", None)
        self.client = self.start("rotation-current", "wanopt-client", ["-config", self.config("client", client_cfg)], 0)
        self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
        self.bench("rotation-primary-restored", "GET", size=32768)
        expires = expiry(20)
        cfg.update(previous_psk=old_psk, previous_psk_expires=expires)
        self.reload(cfg)
        alternate["psk"] = old_psk
        secondary = self.start("expiry-old-key", "wanopt-client", ["-config", self.config("alternate", alternate)], 0)
        self.ready(0, f"http://127.0.0.1:{metrics_port}/metrics", lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
        alternate_bench("expiry-grace")
        time.sleep(max(0, datetime.datetime.fromisoformat(expires).timestamp() - time.time()) + 1)
        try:
            self.proxy = f"http://127.0.0.1:{port}"
            self.rejected("expiry-revoked-without-HUP", self.proxy_target + "/ping")
        finally:
            self.proxy = proxy
        self.bench("expiry-primary-unaffected", "POST", size=32768)
        self.stop(secondary)
        cfg.pop("previous_psk")
        cfg.pop("previous_psk_expires")
        self.reload(cfg)
        self.drain()
        self.stop(self.client)
        self.client = None

    def run(self):
        for name in ["wanopt-client", "wanopt-server", "wanopt-keygen", "wanbench"]:
            help_result = command([self.binary(name), "-h"], check=False)
            if help_result.returncode not in [0, 1] or "-" not in help_result.stderr + help_result.stdout:
                raise AssertionError(f"{name}: help was not available")
            self.record(name + "-help")
        invalid = self.config("invalid", {"unknown_release_setting": True})
        for name in ["wanopt-client", "wanopt-server"]:
            invalid_result = command([self.binary(name), "-config", invalid], check=False)
            if invalid_result.returncode != 1 or "unknown_release_setting" not in invalid_result.stderr:
                raise AssertionError(f"{name}: invalid config was not rejected")
            self.record(name + "-invalid-config")
        # Reserve all local endpoints together to avoid selecting a port twice.
        with contextlib.ExitStack() as stack:
            sockets = [stack.enter_context(socket.socket()) for _ in range(4)]
            for sock in sockets:
                sock.bind(("127.0.0.1", 0))
            op, pp, cp, sp = [s.getsockname()[1] for s in sockets]
            udp = stack.enter_context(socket.socket(type=socket.SOCK_DGRAM))
            udp.bind(("127.0.0.1", 0))
            up = udp.getsockname()[1]
        self.cm, self.sm = f"http://127.0.0.1:{cp}/metrics", f"http://127.0.0.1:{sp}/metrics"
        self.proxy, self.direct = f"http://127.0.0.1:{pp}", f"http://{self.net.address}:{op}"
        self.proxy_target = f"http://127.0.0.1:{op}"
        generated = command([self.binary("wanopt-keygen"), "-cert", "-out", str(self.root)]).stdout
        values = dict(line.split(": ", 1) for line in generated.splitlines() if line.startswith(("psk: ", "pin: ")))
        psk, pin = values["psk"], values["pin"]
        key_before = hashlib.sha256((self.root / "key.pem").read_bytes()).digest()
        duplicate = command([self.binary("wanopt-keygen"), "-cert", "-out", str(self.root)], check=False)
        if duplicate.returncode != 1 or hashlib.sha256((self.root / "key.pem").read_bytes()).digest() != key_before:
            raise AssertionError("keygen overwrote an existing private key")
        self.record("keygen-never-overwrites")
        self.net.setup()
        self.server = self.origin = None
        before = self.net.counters()
        origin_address = "0.0.0.0" if self.o.netem else "127.0.0.1"
        self.origin = self.start("origin", "wanbench", ["-serve", "-listen", f"{origin_address}:{op}",
                                 "-fixture-sizes", "1,32768,262144,1048576"], 1)
        cfg = dict(listen=f"{self.net.address}:{up}", psk=psk, cert_file="cert.pem", key_file="key.pem",
                   compression=True, congestion_control=self.o.cc, max_active_streams=4,
                   max_compressed_streams=1, metrics_listen=f"127.0.0.1:{sp}",
                   acl={"allow": ["127.0.0.1"], "allow_ports": [op]})
        self.server = self.start("server", "wanopt-server", ["-config", self.config("server", cfg)], 1)
        self.ready(1, self.sm)
        self.ready(1, f"http://{self.net.address}:{op}/ping")
        client_cfg = dict(server=f"{self.net.address}:{up}", psk=psk, pin=pin,
                          http_listen=f"127.0.0.1:{pp}", metrics_listen=f"127.0.0.1:{cp}",
                          congestion_control=self.o.cc, proxy_idle_timeout_sec=1,
                          max_active_streams=4, max_compressed_streams=1,
                          request_timeout_sec=2, handshake_timeout_sec=2)
        profiles = ["native", "moderate", "severe"] if self.o.netem else ["native"]
        for compressed in [False, True]:
            client_cfg["compression"] = compressed
            self.client = self.start("client-" + str(compressed), "wanopt-client",
                                     ["-config", self.config("client", client_cfg)], 0)
            self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
            if self.o.fail_after_ready:
                raise RuntimeError("intentional harness failure probe")
            for profile in profiles:
                self.net.profile(profile)
                for kind in ["text", "random"]:
                    for direction in ["GET", "POST"]:
                        label = f"{profile}-{compressed}-{kind}-{direction}"
                        # Interleave the baseline to reduce order/temperature bias.
                        for proxy in [False, True]:
                            self.bench(label + ("-proxy" if proxy else "-tcp"), direction, kind, proxy,
                                       ["-warm", "-repeats", "2"])
            self.bench(f"abort-recovery-{compressed}", "GET", extra=["-abort-after", "1024", "-warm"])
            for direction in ["GET", "POST"]:
                self.bench(f"stream-{compressed}-{direction}", direction,
                           extra=["-stream", "-duration", "300ms", "-warm"], size=32768)
                self.bench(f"slow-{compressed}-{direction}", direction,
                           extra=["-slow-read-delay" if direction == "GET" else "-slow-write-delay", "1ms"], size=32768)
            self.bench(f"concurrent-{compressed}", "GET", extra=["-concurrency", "4", "-warm"])
            self.rejected(f"acl-denied-{compressed}", "http://127.0.0.1:1/ping")
            self.bench(f"recovery-after-denial-{compressed}", "POST")
            self.record(f"idle-drain-{compressed}", snapshots=self.drain())
            time.sleep(2)
            self.bench(f"idle-reuse-{compressed}", "POST")
            self.drain()
            self.stop(self.client)
            self.client = None
        if os.name != "nt":
            self.rotation(cfg, client_cfg)
        else:
            self.report["platform_skipped"] = ["Unix SIGHUP/FIFO CLI tests; credential logic is covered by cross-platform Go tests"]
        # Real handshake failures in separate client processes, followed by recovery.
        for name, field in [("bad-psk", "psk"), ("bad-pin", "pin")]:
            bad = dict(client_cfg)
            bad[field] = base64.b64encode(secrets.token_bytes(32)).decode()
            self.client = self.start(name, "wanopt-client", ["-config", self.config(name, bad)], 0)
            self.ready(0, self.cm)
            self.rejected(name, self.proxy_target + "/ping")
            self.stop(self.client)
            self.client = None
        self.client = self.start("client-final", "wanopt-client", ["-config", self.config("client-final", client_cfg)], 0)
        self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
        self.bench("valid-after-auth-failures", "POST")
        for direction in ["GET", "POST"]:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                tasks = [pool.submit(self.bench, "competing-" + direction + ("-proxy" if proxy else "-tcp"),
                                     direction, "random", proxy, ["-stream", "-duration", "300ms", "-warm"], True, 32768)
                         for proxy in [False, True]]
                for task in tasks:
                    task.result()
        if self.o.netem:
            # The earlier one-second idle policy intentionally cannot survive a
            # two-second outage. Require its rejection and subsequent recovery.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                task = pool.submit(self.bench, "blackhole-exceeds-idle-policy", "GET", "random", True,
                                   ["-stream", "-duration", "8s", "-request-timeout", "25s", "-warm"], False, 32768)
                time.sleep(1.5)
                try:
                    self.net.blackhole()
                    time.sleep(2)
                finally:
                    self.net.profile("severe")
                result = task.result()
                if not any(word in result.get("error", "").lower() for word in ["eof", "timeout"]):
                    raise AssertionError("outage failed for an unexpected reason")
            self.bench("recovery-after-idle-expiry", "POST")
            self.drain()
            self.stop(self.client)
            client_cfg["proxy_idle_timeout_sec"] = 10
            self.client = self.start("client-outage-tolerance", "wanopt-client",
                                     ["-config", self.config("client-outage-tolerance", client_cfg)], 0)
            self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                task = pool.submit(self.bench, "blackhole-recovery", "GET", "random", True,
                                   ["-stream", "-duration", "8s", "-request-timeout", "25s", "-warm"], True, 32768)
                time.sleep(1.5)
                try:
                    self.net.blackhole()
                    time.sleep(2)
                finally:
                    self.net.profile("severe")
                task.result()
            self.net.mtu(1280)
            self.stop(self.client)
            self.client = self.start("client-mtu", "wanopt-client", ["-config", str(self.root / "client-final.json")], 0)
            self.ready(0, self.cm, lambda t: metric(t, "wanopt_tunnel_connections") >= 1)
            for direction in ["GET", "POST"]:
                self.bench("mtu1280-" + direction, direction)
            self.net.mtu(1500)
        self.record("final-lease-drain", snapshots=self.drain())
        metrics = [self.fetch(0, self.cm), self.fetch(1, self.sm)]
        if not all(f'algorithm="{self.o.cc}"' in m for m in metrics):
            raise AssertionError("actual congestion controller was not observed on both endpoints")
        self.report["final_metrics"] = metrics
        # Stop the QUIC endpoints before checking counters: later stale test packets
        # must not be mistaken for a receive failure in an application under test.
        if before:
            self.report["udp_deltas"] = [check_udp(a, b) for a, b in zip(before, self.net.counters())]
        for p in [self.client, self.server]:
            self.stop(p)
        self.stop(self.origin, graceful=False)
        self.record("graceful-shutdown" if os.name != "nt" else "process-teardown")

    def cleanup(self):
        for p, log in reversed(self.processes):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
            log.close()
        self.net.cleanup()
        self.report["owned_processes_remaining"] = [p.pid for p, _ in self.processes if p.poll() is None]
        if self.report["owned_processes_remaining"]:
            raise RuntimeError("owned process cleanup failed")
        self.report["cleanup_passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--cc", choices=["reno", "bbr"], default="reno")
    parser.add_argument("--netem", action="store_true")
    parser.add_argument("--fail-after-ready", action="store_true", help="exercise failure teardown, expects nonzero exit")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    suite = None
    try:
        with tempfile.TemporaryDirectory(prefix="wanopt-validation-") as runtime:
            suite = Suite(args, runtime)
            try:
                suite.run()
                suite.report["passed"] = True
            except BaseException as error:
                suite.report["passed"] = False
                suite.report["error"] = str(error)
                raise
            finally:
                try:
                    suite.cleanup()
                except BaseException as error:
                    suite.report["passed"] = False
                    suite.report["cleanup_error"] = str(error)
                    raise
    finally:
        if suite is not None:
            suite.report["runtime_removed"] = not Path(runtime).exists()
            if not suite.report["runtime_removed"]:
                suite.report["passed"] = False
            args.report.write_text(json.dumps(suite.report, indent=2) + "\n")


if __name__ == "__main__":
    main()
