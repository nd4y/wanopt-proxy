import unittest
import queue
import socket
import subprocess
import sys
import threading
from check import PROBE_RECEIVER_CODE, check_udp, metric, udp_counters


class Observations(unittest.TestCase):
    def test_probe_receiver_consumes_warm_datagram_and_exits(self):
        with socket.socket(type=socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen([sys.executable, "-u", "-c", PROBE_RECEIVER_CODE,
                                    "127.0.0.1", str(port)], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        lines = queue.Queue()
        def read_lines():
            for line in process.stdout:
                lines.put(line.strip())
        reader = threading.Thread(target=read_lines, daemon=True)
        reader.start()
        try:
            self.assertEqual(lines.get(timeout=5), "ready")
            with socket.socket(type=socket.SOCK_DGRAM) as sender:
                sender.sendto(b"warm", ("127.0.0.1", port))
            self.assertEqual(lines.get(timeout=5), "warm-delivered")
            self.assertIsNone(process.poll())
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            reader.join(timeout=3)
            process.stdout.close()
        self.assertFalse(reader.is_alive())
        self.assertIsNotNone(process.poll())

    def test_metric_sums_labeled_leases_without_prefix_collision(self):
        self.assertEqual(metric('x{side="a"} 2\nx{side="b"} 3\nxy 50\n# x 99', "x"), 5)

    def test_udp_error_is_not_hidden_by_successful_packets(self):
        before = udp_counters("Udp: OutDatagrams SndbufErrors\nUdp: 100 7\n")
        after = udp_counters("Udp: OutDatagrams SndbufErrors\nUdp: 2000 8\n")
        with self.assertRaises(AssertionError):
            check_udp(before, after)

    def test_existing_cumulative_error_is_not_a_new_failure(self):
        self.assertEqual(check_udp({"SndbufErrors": 7}, {"SndbufErrors": 7})["SndbufErrors"], 0)

    def test_missing_udp_snapshot_is_rejected(self):
        with self.assertRaises(ValueError):
            udp_counters("Tcp: InSegs\nTcp: 5\n")

    def test_closed_port_exception_never_hides_send_buffer_errors(self):
        with self.assertRaises(AssertionError):
            check_udp({}, {"NoPorts": 5, "SndbufErrors": 1}, allow_closed_ports=True)

    def test_no_ports_is_strict_for_steady_workload_and_retained_for_lifecycle(self):
        with self.assertRaises(AssertionError):
            check_udp({}, {"NoPorts": 5})
        self.assertEqual(check_udp({}, {"NoPorts": 5}, allow_closed_ports=True)["NoPorts"], 5)


if __name__ == "__main__":
    unittest.main()
