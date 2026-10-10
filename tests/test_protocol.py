import unittest
from hf_selap.config import SecurityConfig
from hf_selap.federation import Federation
from hf_selap.protocol import HFSELAP


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.config = SecurityConfig.load("config.json")
        self.federation = Federation(self.config)
        self.system = HFSELAP(self.config, self.federation)
        self.system.add_ta("TA-A", "A", 10, 1, .95, 10)
        self.system.add_ta("TA-B", "B", 10, 1, .95, 15)
        self.federation.set_trust("TA-A", "TA-B", .9)
        self.federation.set_trust("TA-B", "TA-A", .9)
        self.system.register("vehicle", "vehicle", "A")
        self.system.register("uav", "uav", "A")
        self.system.register("other_vehicle", "vehicle", "A")
        self.system.register("other_uav", "uav", "B")

    def test_auth_and_encryption(self):
        session = self.system.authenticate("vehicle", "uav")
        plain = b"rescue data"
        packet = self.system.encrypt_emergency_data(session.session_id, plain)
        self.assertEqual(self.system.decrypt_emergency_data(packet), plain)
        packet["ciphertext"] = packet["ciphertext"][:-1] + bytes([packet["ciphertext"][-1] ^ 1])
        with self.assertRaises(PermissionError):
            self.system.decrypt_emergency_data(packet)

    def test_revocation(self):
        self.system.revoke("vehicle", "test")
        with self.assertRaises(PermissionError):
            self.system.authenticate("vehicle", "uav")

    def test_federation_signature_tamper(self):
        msg = self.system.signed_federation_message("TA-A", {"target": "TA-B"})
        self.assertTrue(self.system.verify_federation_message(msg))
        msg["payload"]["target"] = "TA-EVIL"
        self.assertFalse(self.system.verify_federation_message(msg))

    def test_untrusted_relationship_rejected(self):
        self.federation.trust.pop(("TA-A", "TA-B"))
        with self.assertRaises(PermissionError):
            self.system.authenticate("other_vehicle", "other_uav")

    def test_failover_selection(self):
        self.system.fail_ta("TA-A", False)
        ta = self.federation.select_ta(list(self.system.tas.values()), self.config.selection_weights)
        self.assertEqual(ta.name, "TA-B")


if __name__ == "__main__":
    unittest.main()
