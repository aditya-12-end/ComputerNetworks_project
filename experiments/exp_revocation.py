"""E9 - revocation and recovery / re-enrolment cost versus a full network reset.

For federations holding N enrolled vehicles we measure
* federation-wide revocation of one entity (CPU time, inter-TA bits, RTAs reached);
* recovery of one entity by re-enrolment (CPU time, inter-TA bits);
* the alternative without a recovery protocol: re-registering all N vehicles.
The revoked credential is then tested against every RTA.
"""

from __future__ import annotations

import time

from common import build_federation, save_json


def _bits(s):
    return sum(b for _, b in s.root.traffic.values())


def main(sizes=(100, 500, 1000, 2000)):
    rows = []
    for n in sizes:
        s = build_federation(3, seed=9, monitor_mode="oracle")
        t = time.perf_counter()
        vs = [s.register_vehicle(f"V{i}", ["Region-A", "Region-B", "Region-C"][i % 3])
              for i in range(n)]
        reg_total_ms = (time.perf_counter() - t) * 1000.0
        reg_bits = _bits(s)
        u = s.register_uav("U", "Region-A")
        u.login()
        victim = vs[0]
        victim.login()
        assert s.authenticate(victim, u).ok

        b0 = _bits(s)
        t = time.perf_counter()
        reached = s.revoke(victim, "compromised")
        revoke_ms = (time.perf_counter() - t) * 1000.0
        revoke_bits = _bits(s) - b0
        rejected_everywhere = all(not s.authenticate(victim, u, ta=name).ok for name in s.root.tas)

        b0 = _bits(s)
        t = time.perf_counter()
        fresh = s.reenrol_vehicle(victim)
        reenrol_ms = (time.perf_counter() - t) * 1000.0
        reenrol_bits = _bits(s) - b0
        fresh.login()
        works = s.authenticate(fresh, u).ok
        rows.append({"N": n, "revoke_ms": revoke_ms, "revoke_bits": revoke_bits,
                     "rtas_notified": reached, "revoked_rejected_by_all_rtas": rejected_everywhere,
                     "reenrol_ms": reenrol_ms, "reenrol_bits": reenrol_bits,
                     "reenrolled_entity_authenticates": works,
                     "full_reset_ms": reg_total_ms, "full_reset_bits": reg_bits,
                     "reset_entities": n})
        print(f"N={n}: revoke {revoke_ms:.2f} ms/{revoke_bits} b, re-enrol {reenrol_ms:.2f} ms/"
              f"{reenrol_bits} b, full reset {reg_total_ms:.0f} ms/{reg_bits} b")
    save_json("e9_revocation", {"rows": rows})
    return rows


if __name__ == "__main__":
    main()
