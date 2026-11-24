import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark_dom import RANGES, evaluate_range, BENCHMARKS_DIR


class TestBenchmarkRanges(unittest.TestCase):
    def test_detection_rate_is_100_percent_on_all_ranges(self):
        for name in RANGES:
            stats, _ = evaluate_range(os.path.join(BENCHMARKS_DIR, name))
            with self.subTest(range=name):
                self.assertEqual(stats['recall'], 1.0,
                                 'recall on %s: %s' % (name, stats))
                self.assertEqual(stats['precision'], 1.0,
                                 'precision on %s: %s' % (name, stats))


if __name__ == '__main__':
    unittest.main()
