"""PUF and fuzzy-extractor behaviour."""

import unittest

import numpy as np

from hfselap.puf import ArbiterPUF, FuzzyExtractor, block_failure_probability


class PufTests(unittest.TestCase):
    def setUp(self):
        self.rng = np.random.default_rng(5)
        self.fe = FuzzyExtractor(rep=7)
        self.puf = ArbiterPUF(self.fe.n_bits, 0.03, self.rng)
        self.challenge = bytes(range(16))

    def test_key_reproduced_from_noisy_reads(self):
        reference = self.puf.enrol_response(self.challenge, 9)
        key, helper = self.fe.gen(reference, self.rng)
        hits = sum(self.fe.rep_(self.puf.evaluate(self.challenge), helper) == key
                   for _ in range(200))
        self.assertGreaterEqual(hits, 195)

    def test_other_device_cannot_reproduce_key(self):
        key, helper = self.fe.gen(self.puf.enrol_response(self.challenge, 9), self.rng)
        other = ArbiterPUF(self.fe.n_bits, 0.03, np.random.default_rng(99))
        self.assertNotEqual(self.fe.rep_(other.evaluate(self.challenge), helper), key)

    def test_uniqueness_close_to_half(self):
        a = self.puf.ideal_response(self.challenge)
        b = ArbiterPUF(self.fe.n_bits, 0.03, np.random.default_rng(1)).ideal_response(self.challenge)
        self.assertTrue(0.35 < np.mean(a != b) < 0.65)

    def test_tampered_puf_fails(self):
        key, helper = self.fe.gen(self.puf.enrol_response(self.challenge, 9), self.rng)
        self.puf.tamper()
        self.assertNotEqual(self.fe.rep_(self.puf.evaluate(self.challenge), helper), key)

    def test_analytic_failure_probability_monotone(self):
        self.assertLess(block_failure_probability(0.05, 9), block_failure_probability(0.05, 5))
        self.assertLess(block_failure_probability(0.02, 7), block_failure_probability(0.08, 7))

    def test_even_repetition_rejected(self):
        with self.assertRaises(ValueError):
            FuzzyExtractor(rep=4)


if __name__ == "__main__":
    unittest.main()
