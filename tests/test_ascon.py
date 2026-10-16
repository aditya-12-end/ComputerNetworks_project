"""ASCON v1.2 correctness against the independent reference implementation."""

import os
import unittest

from hfselap import ascon

try:
    import ascon as reference          # PyPI package ascon==0.0.9 (pyascon, v1.2)
except ImportError:                    # pragma: no cover
    reference = None


class AsconTests(unittest.TestCase):
    def test_known_answer_vector(self):
        # LWC KAT Ascon-128 v1.2, Count = 1 (empty AD and plaintext)
        c, tag = ascon.encrypt(bytes(range(16)), bytes(range(16)), b"", b"")
        self.assertEqual(c + tag, bytes.fromhex("e355159f292911f794cb1432a0103a8a"))

    @unittest.skipIf(reference is None, "reference package 'ascon' not installed")
    def test_matches_reference_both_variants(self):
        for variant, klen in (("Ascon-128", 16), ("Ascon-80pq", 20)):
            for n in range(0, 90, 7):
                key, iv = os.urandom(klen), os.urandom(16)
                ad, pt = os.urandom(n % 33), os.urandom(n)
                c, tag = ascon.encrypt(key, iv, ad, pt, variant)
                self.assertEqual(c + tag, reference.encrypt(key, iv, ad, pt, variant))

    def test_round_trip(self):
        key, iv = os.urandom(16), os.urandom(16)
        c, tag = ascon.encrypt(key, iv, b"ad", b"emergency payload")
        self.assertEqual(ascon.decrypt(key, iv, b"ad", c, tag), b"emergency payload")

    def test_tamper_detection(self):
        key, iv = os.urandom(16), os.urandom(16)
        c, tag = ascon.encrypt(key, iv, b"ad", b"emergency payload")
        with self.assertRaises(ascon.AsconAuthError):
            ascon.decrypt(key, iv, b"ad", bytes([c[0] ^ 1]) + c[1:], tag)
        with self.assertRaises(ascon.AsconAuthError):
            ascon.decrypt(key, iv, b"AD", c, tag)
        with self.assertRaises(ascon.AsconAuthError):
            ascon.decrypt(key, iv, b"ad", c, bytes([tag[0] ^ 1]) + tag[1:])

    def test_parameter_validation(self):
        with self.assertRaises(ValueError):
            ascon.encrypt(os.urandom(15), os.urandom(16), b"", b"")
        with self.assertRaises(ValueError):
            ascon.encrypt(os.urandom(16), os.urandom(12), b"", b"")


if __name__ == "__main__":
    unittest.main()
