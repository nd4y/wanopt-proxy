import unittest
from check import check_udp, metric, udp_counters


class Observations(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
