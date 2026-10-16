"""E3/E4 - communication overhead (air interface + backhaul) and storage cost.

Every number is measured from serialised bytes produced by the implementation.
Air-interface figures of four earlier schemes are the values *reported* in the
SELAP base paper (Wu et al., Computer Networks 287, 2026, Fig. 5) and are used
only as a reference line; they are not re-implemented here.
"""

from __future__ import annotations

from common import BLUE, INK2, build_federation, new_figure, save_figure, save_json

REPORTED_AIR_BITS = {                      # base paper, Fig. 5
    "Miao et al. (2024)": 4464,
    "Wang et al. (2024)": 3424,
    "Wu et al. (2022)": 6712,
    "Xu et al. (2023)": 4016,
    "SELAP (base paper)": 2432,
}


def _delta(before: dict, after: dict) -> dict:
    out = {}
    for k, (cnt, bits) in after.items():
        c0, b0 = before.get(k, (0, 0))
        if cnt != c0:
            out[k] = {"messages": cnt - c0, "bits": bits - b0}
    return out


def _snap(s):
    return {k: tuple(v) for k, v in s.root.traffic.items()}


def main():
    s = build_federation(3, seed=5, monitor_mode="oracle")
    v = s.register_vehicle("V1", "Region-A")
    v2 = s.register_vehicle("V2", "Region-A")
    u_local = s.register_uav("U-A", "Region-A")
    u_remote = s.register_uav("U-B", "Region-B")
    for e in (v, v2, u_local, u_remote):
        e.login()

    scenarios = {}

    def run(label, vehicle, uav, ta=None):
        before = _snap(s)
        r = s.authenticate(vehicle, uav, ta=ta)
        assert r.ok, r.reason
        back = _delta(before, _snap(s))
        scenarios[label] = {"air_bits": r.bits, "air_total": sum(r.bits.values()),
                            "backhaul": back,
                            "backhaul_total": sum(x["bits"] for x in back.values()),
                            "serving_ta": r.ta}

    run("Intra-region (home RTA serves)", v, u_local)
    run("Cross-region, first request (cold cache)", v, u_remote, ta="RTA-1")
    run("Cross-region, cached credential", v, u_remote, ta="RTA-1")
    run("Fail-over / load-shared to foreign RTA (cold)", v2, u_local, ta="RTA-2")
    run("Fail-over / load-shared to foreign RTA (cached)", v2, u_local, ta="RTA-2")

    # control-plane messages
    hb = s.root.heartbeat_bits()
    before = _snap(s)
    s.revoke(v2, "experiment")
    revoke = _delta(before, _snap(s))
    before = _snap(s)
    s.register_vehicle("V3", "Region-A")
    deposit_v = _delta(before, _snap(s))
    before = _snap(s)
    s.register_uav("U-C", "Region-A")
    deposit_u = _delta(before, _snap(s))

    storage = {
        "Vehicle smart card": v.card.storage_bits,
        "UAV smart card": u_local.card.storage_bits,
        "Regional TA, per own vehicle <TID_o,TID_c,N_VR2,M_VR1>":
            s.root.tas["RTA-1"].storage_bits_per_vehicle,
        "Regional TA, per own UAV <ID_U,M_UR1,C_U>": s.root.tas["RTA-1"].storage_bits_per_uav,
        "Regional TA, per cached foreign vehicle <TID_o,TID_c,N_VR2,PID_V>": 8 * (16 + 16 + 16 + 32),
        "Root TA escrow, per vehicle (sealed)": s.root.escrow_bits(v.handle),
        "Root TA escrow, per UAV (sealed)": s.root.escrow_bits(u_local.handle),
    }
    storage_reported = {"Vehicle (SELAP, reported)": 768, "UAV (SELAP, reported)": 656,
                        "TA (SELAP, reported)": 1280}

    out = {"scenarios": scenarios,
           "control_plane": {"heartbeat_bits": hb, "revocation_broadcast": revoke,
                             "deposit_vehicle": deposit_v, "deposit_uav": deposit_u},
           "storage_bits": storage, "storage_reported_selap": storage_reported,
           "reported_air_bits": REPORTED_AIR_BITS}
    save_json("e3_overhead", out)
    for k, sc in scenarios.items():
        print(f"{k:50s} air {sc['air_total']} bits  backhaul {sc['backhaul_total']} bits")
    print("storage", storage)
    plot(out)
    return out


def plot(out):
    measured = out["scenarios"]["Intra-region (home RTA serves)"]["air_total"]
    items = list(out["reported_air_bits"].items()) + [("HF-SELAP (this work, measured)", measured)]
    fig, ax = new_figure(6.4, 3.0)
    names = [n for n, _ in items]
    vals = [b for _, b in items]
    colors = ["#b4b2ab"] * (len(items) - 1) + [BLUE]
    ax.barh(names, vals, color=colors, height=0.55)
    for y, val in enumerate(vals):
        ax.text(val + 80, y, f"{val}", va="center", fontsize=8, color=INK2)
    ax.invert_yaxis()
    ax.set_xlabel("Air-interface bits per authentication (Msg1-Msg4)")
    ax.set_title("Communication overhead on the vehicle/UAV radio links")
    ax.set_xlim(0, max(vals) * 1.12)
    ax.grid(axis="y", visible=False)
    save_figure(fig, "fig_comm_overhead")


if __name__ == "__main__":
    main()
