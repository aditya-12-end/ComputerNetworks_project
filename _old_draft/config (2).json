import json
from hf_selap.config import SecurityConfig
from hf_selap.federation import Federation
from hf_selap.protocol import HFSELAP


def main():
    config = SecurityConfig.load("config.json")
    federation = Federation(config)
    system = HFSELAP(config, federation)

    system.add_ta("TA1", "Region-A", 10, 1.0, 0.96, 12)
    system.add_ta("TA2", "Region-A", 8, 1.0, 0.94, 18)
    system.add_ta("TA3", "Region-B", 12, 1.0, 0.98, 8)

    for a, b, trust in [
        ("TA1", "TA2", 0.95), ("TA2", "TA1", 0.95),
        ("TA1", "TA3", 0.90), ("TA3", "TA1", 0.90),
        ("TA2", "TA3", 0.85), ("TA3", "TA2", 0.85),
    ]:
        federation.set_trust(a, b, trust)

    system.register("Vehicle1", "vehicle", "Region-A")
    system.register("UAV1", "uav", "Region-A")
    system.register("Vehicle2", "vehicle", "Region-A")
    system.register("UAV2", "uav", "Region-B")

    session = system.authenticate("Vehicle1", "UAV1")
    payload = b"Emergency rescue request: vehicle requires assistance."
    packet = system.encrypt_emergency_data(session.session_id, payload)
    recovered = system.decrypt_emergency_data(packet)

    print("Authenticated session established:", bool(session.session_id))
    print("Selected TA:", session.ta_name)
    print("Encrypted emergency data:", packet["ciphertext"].hex())
    print("Decryption and integrity verification passed:", recovered == payload)
    print("Session key is intentionally not printed.")

    message = system.signed_federation_message("TA1", {
        "action": "cross-region-handoff",
        "target_ta": "TA3",
        "request_id": "demo-request-1",
    })
    print("Federation message signature valid:", system.verify_federation_message(message))

    system.revoke("Vehicle2", "simulated compromise")
    try:
        system.authenticate("Vehicle2", "UAV2")
    except PermissionError as exc:
        print("Revocation test passed:", exc)

    print("Metrics:", json.dumps(system.evaluate(), indent=2))


if __name__ == "__main__":
    main()
