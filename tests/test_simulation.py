"""Event simulation sanity checks."""

import unittest

from hfselap import HFSELAP
from hfselap.simulation import Simulation


def build(n_tas):
    s = HFSELAP(seed=11, monitor_mode="heartbeat")
    regions = ["Region-A", "Region-B", "Region-C"][:n_tas]
    for i, r in enumerate(regions):
        s.add_ta(f"RTA-{i + 1}", r)
    names = list(s.root.tas)
    for a in names:
        for b in names:
            if a < b:
                s.trust(a, b, 0.9)
    vs = [s.register_vehicle(f"V{i}", regions[i % n_tas]) for i in range(40)]
    us = [s.register_uav(f"U{i}", regions[i % n_tas]) for i in range(6)]
    for e in vs + us:
        e.login()
    return s, vs, us


class SimulationTests(unittest.TestCase):
    def test_all_requests_succeed_on_clean_network(self):
        s, vs, us = build(2)
        sim = Simulation(s, seed=1)
        for i, v in enumerate(vs):
            sim.submit(i * 5.0, v.name, us[i % len(us)].name)
        sim.run(5000)
        sim.finalize(5000)
        summary = sim.summary()
        self.assertEqual(summary["success_rate"], 1.0)
        self.assertGreater(summary["mean_latency_ms"], 0)
        # T_auth = T_req + T_TA + T_authz + T_UAV + T_resp (+ earlier attempts)
        for r in sim.requests:
            self.assertAlmostEqual(sum(r.breakdown.values()), r.t_end - r.t_start, places=6)
        parts = summary["t_auth_breakdown_ms"]
        self.assertGreater(parts["T_req"], 0)
        self.assertGreater(parts["T_UAV"], 0)
        self.assertGreaterEqual(summary["load_imbalance"], 0.0)

    def test_failover_after_ta_failure(self):
        s, vs, us = build(2)
        sim = Simulation(s, seed=1)
        sim.fail_ta(0.0, "RTA-1")
        for i, v in enumerate(vs):
            sim.submit(2000 + i * 10.0, v.name, us[i % len(us)].name)
        sim.run(8000)
        sim.finalize(8000)
        self.assertEqual(sim.summary()["success_rate"], 1.0)
        self.assertTrue(all("RTA-1" not in r.tas for r in sim.requests))


if __name__ == "__main__":
    unittest.main()
