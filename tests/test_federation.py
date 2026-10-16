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

    def test_uav_reenrolment_with_new_challenge(self):
        s = world()
        u = s.uavs["U1"]
        new_u = s.reenrol_uav(u)
        new_u.login()
        self.assertTrue(s.authenticate(s.vehicles["V1"], new_u).ok)
        self.assertFalse(s.authenticate(s.vehicles["V2"], u).ok)


if __name__ == "__main__":
    unittest.main()
