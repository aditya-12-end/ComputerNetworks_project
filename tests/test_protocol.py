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
        self.assertEqual(r.bits, {"msg1": 1056, "msg2": 800, "msg3": 928, "msg4": 800})

    def test_operation_counts_match_cost_model(self):
        s = world()
        METER.reset()
        self.assertTrue(s.authenticate(s.vehicles["V1"], s.uavs["U1"]).ok)
        ops = METER.snapshot()
        self.assertEqual(ops["vehicle"], {"hash": 6, "ascon": 2, "sign": 1})
        self.assertEqual(ops["uav"], {"hash": 5, "ascon": 2, "sign": 1})
        self.assertEqual(ops["ta"]["hash"], 9)
        self.assertEqual(ops["ta"]["verify"], 2)
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
        self.assertEqual(METER.snapshot()["ta"], {"hash": 9, "ascon": 4, "verify": 2})

    def test_tid_refresh_is_consistent_everywhere(self):
        s = world()
        v, u = s.vehicles["V1"], s.uavs["U1"]
        old_tid = v.card.tid
        self.assertTrue(s.authenticate(v, u, ta="RTA-1").ok)
        rec = s.root.tas["RTA-1"].by_handle[v.handle]
        self.assertEqual((rec.tid_o, rec.tid_c), (old_tid, v.card.tid))
        self.assertEqual(s.root.v_tids[v.handle], (old_tid, v.card.tid))

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
        self.assertEqual(sum(r.bits.values()), 3584)

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            Config.from_dict({"protocol": {"delta_t_ms": 0}})
        with self.assertRaises(ValueError):
            Config.from_dict({"federation": {"lb_weights": {"load": 1, "availability": 1,
                                                             "reliability": 0, "delay": 0}}})
        with self.assertRaises(ValueError):
            Config.from_dict({"federation": {"max_load": 1.5}})
        with self.assertRaises(ValueError):
            Config.from_dict({"protocol": {"unknown_key": 1}})

    def test_config_file_loads(self):
        cfg = Config.load(Path(__file__).resolve().parents[1] / "config.json")
        self.assertEqual(cfg.federation.lb_weights["load"], 0.45)
        self.assertEqual(cfg.federation.max_load, 0.9)


if __name__ == "__main__":
    unittest.main()
