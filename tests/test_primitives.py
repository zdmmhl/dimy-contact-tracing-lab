"""Network-free checks of the existing protocol primitives."""
import itertools
import unittest

from Dimy import BloomFilter, split_secret_shamir, reconstruct_secret_shamir
from DimyServer import DimyServer


class PrimitiveTests(unittest.TestCase):
    def test_every_threshold_subset_reconstructs(self):
        for secret in [bytes(range(32)), bytes([0] * 32), bytes([255] * 32)]:
            shares = split_secret_shamir(secret, 3, 5)
            for subset in itertools.combinations(shares, 3):
                self.assertEqual(reconstruct_secret_shamir(list(subset)), secret)

    def test_bloom_merge_preserves_both_insertions(self):
        left, right = BloomFilter(), BloomFilter()
        left.add(b"encounter-a")
        right.add(b"encounter-b")
        left.merge(right)
        self.assertIn(b"encounter-a", left)
        self.assertIn(b"encounter-b", left)

    def test_serialised_filter_preserves_membership(self):
        original = BloomFilter()
        original.add(b"encounter-c")
        restored = BloomFilter.from_bytes(original.to_bytes())
        self.assertIn(b"encounter-c", restored)

    def test_backend_matches_identical_filter(self):
        bf = BloomFilter()
        bf.add(b"encounter-d")
        server = DimyServer(host="127.0.0.1")
        server._cbfs.append(bf.to_bytes())
        self.assertTrue(server._is_matched(bf.to_bytes()))


if __name__ == "__main__":
    unittest.main()
