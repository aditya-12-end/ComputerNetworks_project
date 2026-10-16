"""Post-authentication data channel."""

import unittest

from hfselap.attacks import world
from hfselap.channel import ChannelError, SecureDataChannel


class ChannelTests(unittest.TestCase):
    def setUp(self):
        s = world()
        r = s.authenticate(s.vehicles["V1"], s.uavs["U1"])
        self.tx = SecureDataChannel(r.sk_vehicle, "vehicle")
        self.rx = SecureDataChannel(r.sk_uav, "uav")

    def test_round_trip_both_directions(self):
        self.assertEqual(self.rx.open(self.tx.seal(b"need medical team")), b"need medical team")
        self.assertEqual(self.tx.open(self.rx.seal(b"route via exit 4")), b"route via exit 4")

    def test_replay_and_tamper_rejected(self):
        packet = self.tx.seal(b"position update")
        self.rx.open(packet)
        with self.assertRaises(ChannelError):
            self.rx.open(packet)
        bad = bytearray(self.tx.seal(b"position update"))
        bad[6] ^= 1
        with self.assertRaises(ChannelError):
            self.rx.open(bytes(bad))

    def test_reflection_rejected(self):
        packet = self.tx.seal(b"hello")
        with self.assertRaises(ChannelError):
            self.tx.open(packet)


if __name__ == "__main__":
    unittest.main()
