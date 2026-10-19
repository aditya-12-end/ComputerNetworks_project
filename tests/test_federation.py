"""Federation: cross-region service, fail-over, resync, revocation, load balancing."""

import unittest

from hfselap.attacks import world


class FederationTests(unittest.TestCase):
    def test_cross_region_delegation(self):
        s = world()
        r = s.authenticate(s.vehicles["V1"], s.uavs["U2"])
        self.assertTrue(r.ok, r.reason)
        self.assertTrue(r.delegated)
        self.assertGreaterEqual(r.fetches, 1)

    def test_failover_when_home_ta_is_down(self):
        s = world()
        v, u = s.vehicles["V1"], s.uavs["U1"]
        s.root.tas["RTA-1"].fail()
        r = s.authenticate(v, u)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.ta, "RTA-2")

    def test_recovered_ta_is_resynchronised(self):
        s = world()
        v, u = s.vehicles["V1"], s.uavs["U1"]
        s.root.tas["RTA-1"].fail()
        self.assertTrue(s.authenticate(v, u).ok)            # served by RTA-2, TID rotated
        s.revoke(s.vehicles["V2"], "lost")                  # RTA-1 misses this revocation
        s.root.tas["RTA-1"].recover()
        rta1 = s.root.tas["RTA-1"]
        self.assertIn(s.vehicles["V2"].handle, rta1.revoked)
        r = s.authenticate(v, u, ta="RTA-1")                # home TA knows the new TID
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.fetches, 0)

    def test_revocation_reaches_every_ta(self):
        s = world()
        n = s.revoke(s.vehicles["V1"], "compromised")
        self.assertEqual(n, 2)
        for ta in s.root.tas.values():
            self.assertIn(s.vehicles["V1"].handle, ta.revoked)

    def test_load_balancer_prefers_less_loaded_ta(self):
        s = world()
        s.root.tas["RTA-1"].queue_len = s.cfg.network.ta_queue_capacity
        self.assertEqual(s.select_ta(s.vehicles["V1"]).name, "RTA-2")
        s.root.tas["RTA-1"].queue_len = 0
        self.assertEqual(s.select_ta(s.vehicles["V1"]).name, "RTA-1")

    def test_load_above_max_is_bypassed(self):
        s = world()
        rta1 = s.root.tas["RTA-1"]
        cap = s.cfg.network.ta_queue_capacity
        rta1.queue_len = int(cap * s.cfg.federation.max_load) + 1    # L_1 > L_max
        self.assertEqual(s.select_ta(s.vehicles["V1"]).name, "RTA-2")
        s.root.tas["RTA-2"].queue_len = cap                          # both overloaded
        self.assertEqual(s.select_ta(s.vehicles["V1"]).name, "RTA-1")

    def test_trust_update_rule(self):
        s = world()
        alpha = s.cfg.federation.trust_history_weight
        before = s.root.trust[("RTA-2", "RTA-1")]
        r = s.authenticate(s.vehicles["V1"], s.uavs["U2"], ta="RTA-1")   # U2 is homed at RTA-2
        self.assertTrue(r.ok, r.reason)
        self.assertAlmostEqual(s.root.trust[("RTA-2", "RTA-1")], alpha * before + (1 - alpha))
        s.root.observe("RTA-1", False, ("RTA-2",))
        self.assertLess(s.root.trust[("RTA-2", "RTA-1")], alpha * before + (1 - alpha))

    def test_heartbeat_availability(self):
        s = world()
        s.monitor.mode = "heartbeat"
        for t in range(0, 10_001, 500):
            s.monitor.beat("RTA-1", float(t))
        self.assertEqual(s.monitor.availability("RTA-1", 10_000.0), 1.0)
        for t in range(14_000, 20_001, 500):                      # 4 s without heartbeats
            s.monitor.beat("RTA-1", float(t))
        self.assertTrue(0.55 < s.monitor.availability("RTA-1", 20_000.0) < 0.75)

    def test_uav_reenrolment_with_new_key_pair(self):
        s = world()
        u = s.uavs["U1"]
        new_u = s.reenrol_uav(u)
        new_u.login()
        self.assertTrue(s.authenticate(s.vehicles["V1"], new_u).ok)
        self.assertFalse(s.authenticate(s.vehicles["V2"], u).ok)


if __name__ == "__main__":
    unittest.main()
