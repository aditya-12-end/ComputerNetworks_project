"""Every attack scenario must be blocked; the ablation must show the weakness."""

import unittest

from hfselap import attacks


class SecurityTests(unittest.TestCase):
    def test_all_attacks_blocked(self):
        for outcome in attacks.all_scenarios():
            with self.subTest(attack=outcome.attack):
                self.assertTrue(outcome.blocked, outcome.observed)

    def test_dual_record_is_what_prevents_desync(self):
        self.assertFalse(attacks.desynchronisation(dual_record=False).blocked)


if __name__ == "__main__":
    unittest.main()
