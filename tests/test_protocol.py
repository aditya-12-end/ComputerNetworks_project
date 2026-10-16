"""Functional correctness of the SELAP exchange inside HF-SELAP."""

import unittest
from pathlib import Path

from hfselap import HFSELAP, Config
from hfselap.attacks import world
from hfselap.primitives import METER


class ProtocolTests(unittest.TestCase):
    def test_session_keys_match_and_message_sizes(self):
        s = world()
        r = s.authenticate(s.vehicles["V1"], s.uavs["U1"])
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.sk_vehicle, r.sk_uav)
        self.assertEqual(r.bits, {"msg1": 544, "msg2": 672, "msg3": 416, "msg4": 800})

    def test_operation_counts_match_cost_model(self):
        s = world()
        METER.reset()
        self.assertTrue(s.authenticate(s.vehicles["V1"], s.uavs["U1"]).ok)
        ops = METER.snapshot()
        self.assertEqual(ops["vehicle"], {"hash": 5, "ascon": 2})
        self.assertEqual(ops["uav"], {"hash": 5, "ascon": 2, "puf": 1, "fe": 1})
        self.assertEqual(ops["ta"]["hash"], 8)
        # 4 protocol ASCON operations + 1 for the federation write-through sync
        self.assertEqual(ops["ta"]["ascon"], 5)

    def test_single_ta_is_plain_selap(self):
        s = HFSELAP(seed=3)
        s.add_ta("TA", "Region-A")
        v, u = s.register_vehicle("V", "Region-A"), s.register_uav("U", "Region-A")
        v.login()
        u.login()
        METER.reset()
        self.assertTrue(s.authenticate(v, u).ok)
        self.assertEqual(METER.snapshot()["ta"], {"hash": 8, "ascon": 4})

    def test_tid_rotates_every_session(self):
        s = world()
        v, u = s.vehicles["V1"], s.uavs["U1"]
        seen = {v.card.tid}
        for _ in range(5):
            self.assertTrue(s.authenticate(v, u).ok)
            self.assertNotIn(v.card.tid, seen)
            seen.add(v.card.tid)

    def test_post_quantum_mode(self):
        s = world(pq_mode=True)
        r = s.authenticate(s.vehicles["V1"], s.uavs["U1"])
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(sum(r.bits.values()), 2432)

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            Config.from_dict({"protocol": {"fe_repetition": 4}})
        with self.assertRaises(ValueError):
            Config.from_dict({"federation": {"lb_weights": {"load": 1, "trust": 1,
                                                             "latency": 0, "home": 0}}})
        with self.assertRaises(ValueError):
            Config.from_dict({"protocol": {"unknown_key": 1}})

    def test_config_file_loads(self):
        cfg = Config.load(Path(__file__).resolve().parents[1] / "config.json")
        self.assertEqual(cfg.protocol.fe_repetition, 7)


if __name__ == "__main__":
    unittest.main()
