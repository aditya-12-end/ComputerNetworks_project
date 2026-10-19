"""Certificateless key generation, validation and signatures."""

import unittest

from hfselap import certificateless as cl


class CurveTests(unittest.TestCase):
    def test_python_arithmetic_matches_openssl(self):
        self.assertTrue(cl.on_curve(cl.G))
        self.assertEqual(cl.base_mult(1), cl.G)
        for _ in range(10):
            k, a, b = cl.random_scalar(), cl.random_scalar(), cl.random_scalar()
            self.assertEqual(cl.scalar_mult(k, cl.G), cl.base_mult(k))
            self.assertEqual(cl.point_add(cl.base_mult(a), cl.base_mult(b)), cl.base_mult(a + b))
        self.assertIsNone(cl.point_add(cl.G, cl.point_neg(cl.G)))

    def test_fixed_base_table_and_encoding(self):
        kgc = cl.KGC()
        for _ in range(5):
            k = cl.random_scalar()
            pt = kgc.public.mult(k)
            self.assertEqual(pt, cl.scalar_mult(k, kgc.public.p_pub))
            self.assertEqual(cl.decode_point(cl.encode_point(pt)), pt)
        x = next(x for x in range(1, 100)                    # an x with no curve point
                 if pow((x ** 3 + cl.A * x + cl.B) % cl.P, (cl.P - 1) // 2, cl.P) != 1)
        with self.assertRaises(cl.EnrolmentError):
            cl.decode_point(b"\x02" + x.to_bytes(32, "big"))


class KeyTests(unittest.TestCase):
    def setUp(self):
        self.kgc = cl.KGC()
        self.ident = b"UAV-identity-123"
        self.x, self.x_pub = cl.new_secret_value()
        self.r_pub, self.d = self.kgc.extract_partial_key(self.ident, self.x_pub)

    def test_full_key_matches_verification_key(self):
        sk = cl.full_private_key(self.ident, self.x, self.x_pub, self.r_pub, self.d,
                                 self.kgc.public)
        self.assertEqual(int.from_bytes(sk, "big"), (self.x + self.d) % cl.N)   # SK = x + D
        q = cl.verification_key(self.ident, self.x_pub, self.r_pub, self.kgc.public)
        self.assertEqual(cl.encode_point(cl.base_mult(int.from_bytes(sk, "big"))), q)
        sigma = cl.sign(cl.signer(sk), b"authentication message")
        self.assertEqual(len(sigma), cl.SIG_BYTES)
        self.assertTrue(cl.verify(cl.verifier(q), sigma, b"authentication message"))
        self.assertFalse(cl.verify(cl.verifier(q), sigma, b"other message"))
        self.assertFalse(cl.verify(cl.verifier(q), bytes([sigma[0] ^ 1]) + sigma[1:],
                                   b"authentication message"))

    def test_partial_key_validation(self):
        self.assertTrue(cl.partial_key_valid(self.ident, self.x_pub, self.r_pub, self.d,
                                             self.kgc.public))
        for bad in ((self.d + 1) % cl.N, 0):
            self.assertFalse(cl.partial_key_valid(self.ident, self.x_pub, self.r_pub, bad,
                                                  self.kgc.public))
        self.assertFalse(cl.partial_key_valid(b"another-identity", self.x_pub, self.r_pub,
                                              self.d, self.kgc.public))
        with self.assertRaises(cl.EnrolmentError):
            cl.full_private_key(self.ident, self.x, self.x_pub, self.r_pub, self.d + 1,
                                self.kgc.public)

    def test_replaced_public_key_does_not_fit_partial_key(self):
        _, other_x = cl.new_secret_value()
        q_genuine = cl.verification_key(self.ident, self.x_pub, self.r_pub, self.kgc.public)
        q_replaced = cl.verification_key(self.ident, other_x, self.r_pub, self.kgc.public)
        self.assertNotEqual(q_genuine, q_replaced)
        self.assertFalse(cl.partial_key_valid(self.ident, other_x, self.r_pub, self.d,
                                              self.kgc.public))

    def test_kgc_alone_cannot_sign(self):
        q = cl.verification_key(self.ident, self.x_pub, self.r_pub, self.kgc.public)
        sigma = cl.sign(cl.signer(self.d.to_bytes(32, "big")), b"m")
        self.assertFalse(cl.verify(cl.verifier(q), sigma, b"m"))


if __name__ == "__main__":
    unittest.main()
