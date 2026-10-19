"""Guided demonstration of HF-SELAP (run: python demo.py).

Walks through every block of the proposed architecture: federation set-up,
certificateless registration, intra- and cross-region authentication,
protected emergency data, attacks, Regional-TA failure with fail-over,
revocation, recovery and the post-quantum mode.  Keys are never printed.
"""

from __future__ import annotations

from hfselap import HFSELAP, Config
from hfselap.attacks import replay_msg1_within_window, uav_signature_forgery
from hfselap.channel import ChannelError, SecureDataChannel


def banner(text: str):
    print(f"\n=== {text} " + "=" * max(0, 66 - len(text)))


def show(label: str, result):
    status = "SUCCESS" if result.ok else "REJECTED"
    extra = f" via {result.ta}" if result.ta else ""
    bits = f", {sum(result.bits.values())} air bits" if result.ok else ""
    print(f"  {label:48s} {status}{extra}{bits}")
    if not result.ok:
        print(f"      reason: {result.reason}")


def main():
    cfg = Config.load("config.json")
    banner("1. Federation: Root TA + two Regional TAs")
    s = HFSELAP(cfg, seed=2026)
    s.add_ta("RTA-1", "Region-A")
    s.add_ta("RTA-2", "Region-B")
    s.trust("RTA-1", "RTA-2", 0.9)
    print("  RTA-1 (Region-A) and RTA-2 (Region-B) linked to the Root TA, mutual trust 0.9")

    banner("2. Certificateless registration over the secure enrolment channel")
    car = s.register_vehicle("Ambulance-17", "Region-A", password=b"amb-17-pass")
    van = s.register_vehicle("Rescue-Van-4", "Region-A", password=b"van-4-pass")
    uav_a = s.register_uav("UAV-Alpha", "Region-A", password=b"alpha-op")
    uav_b = s.register_uav("UAV-Bravo", "Region-B", password=b"bravo-op")
    for e in (car, van, uav_a, uav_b):
        e.login()
    print("  each entity: secret value x, partial key D from the Root TA's KGC (validated),")
    print("  full private key SK = x + D sealed in its smart card; Q = X + R + h*P_pub at the RTA")
    print(f"  vehicle smart card: {car.card.storage_bits} bits, "
          f"UAV smart card: {uav_a.card.storage_bits} bits")

    banner("3. Mutual authentication and key agreement")
    r = s.authenticate(car, uav_a)
    show("Ambulance-17 <-> UAV-Alpha (same region)", r)
    print(f"  message sizes: {r.bits}")
    r2 = s.authenticate(car, uav_b)
    show("Ambulance-17 <-> UAV-Bravo (cross-region)", r2)
    print(f"  delegated credential fetches from the Root TA: {r2.fetches}")

    banner("4. Emergency data protected with the session key")
    tx = SecureDataChannel(r2.sk_vehicle, "vehicle")
    rx = SecureDataChannel(r2.sk_uav, "uav")
    packet = tx.seal(b"Casualty x2 at km 14.2, road blocked northbound")
    print(f"  UAV received: {rx.open(packet).decode()}")
    try:
        rx.open(packet)
    except ChannelError as exc:
        print(f"  replayed packet rejected: {exc}")

    banner("5. Attack examples")
    for outcome in (replay_msg1_within_window(), uav_signature_forgery()):
        print(f"  {outcome.attack}: {'BLOCKED' if outcome.blocked else 'NOT BLOCKED'}")
        print(f"      ({outcome.observed})")

    banner("6. Fault tolerance: RTA-1 crashes")
    s.root.tas["RTA-1"].fail()
    show("Rescue-Van-4 <-> UAV-Alpha while RTA-1 is down", s.authenticate(van, uav_a))
    s.root.tas["RTA-1"].recover()
    show("Rescue-Van-4 <-> UAV-Alpha after RTA-1 recovers", s.authenticate(van, uav_a))

    banner("7. Revocation registry")
    notified = s.revoke(van, "vehicle reported stolen")
    print(f"  revocation pushed to {notified} Regional TAs")
    show("Revoked Rescue-Van-4 tries again", s.authenticate(van, uav_a))

    banner("8. Recovery / re-enrolment (no network reset)")
    van2 = s.reenrol_vehicle(van, password=b"van-4-new-pass")
    van2.login()
    show("Re-enrolled Rescue-Van-4 <-> UAV-Alpha", s.authenticate(van2, uav_a))
    show("Ambulance-17 unaffected", s.authenticate(car, uav_a))

    banner("9. Post-quantum hardened mode (Ascon-80pq, 160-bit keys)")
    cfg_pq = Config.load("config.json")
    cfg_pq.protocol.pq_mode = True
    pq = HFSELAP(cfg_pq, seed=7)
    pq.add_ta("RTA-PQ", "Region-A")
    v = pq.register_vehicle("Vehicle-PQ", "Region-A")
    u = pq.register_uav("UAV-PQ", "Region-A")
    v.login()
    u.login()
    show("Vehicle-PQ <-> UAV-PQ", pq.authenticate(v, u))

    banner("Federation traffic (inter-TA messages)")
    for name, (count, bits) in sorted(s.root.traffic.items()):
        print(f"  {name:20s} {count:3d} messages {bits:6d} bits")


if __name__ == "__main__":
    main()
