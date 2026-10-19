"""E7 - high-mobility and stress evaluation on a highway evacuation corridor.

Model
-----
* A 30 km ring corridor crosses three regions (10 km each).  UAVs hover over
  1 km cells (30 UAVs); each UAV is enrolled at the RTA of its region.
* N vehicles start at uniform positions, move at speed v (+/- 10 %) and
  authenticate with the next UAV every time they enter a new cell.  Their home
  region is random (evacuees come from everywhere), so many requests are
  cross-region.
* Wireless loss grows with speed (Doppler / handover stress, an explicit
  assumption of this study): p_vehicle(v) = 0.5 % + 0.04 % per km/h on every
  vehicle hop; UAV hops lose 0.5 %.  Backhaul is lossless.

Deployments: a single TA in Region-B, HF-SELAP (3 RTAs, load balancing), and
HF-SELAP without dual TID records (desynchronisation ablation).
"""

from __future__ import annotations

import numpy as np

from common import (BLUE, ORANGE, AQUA, MARKERS, REGIONS, build_federation, load_config,
                    new_figure, save_figure, save_json)
from hfselap.simulation import Simulation

CORRIDOR_KM, CELL_KM = 30, 1
REGION_KM = 10
CONFIGS = [("Single TA (no federation)", 1, True),
           ("HF-SELAP (3 RTAs)", 3, True),
           ("HF-SELAP without dual TID records", 3, False)]
DEADLINE_MS = 1000.0


def region_of(km: float) -> str:
    return REGIONS[int(km // REGION_KM) % 3]


def vehicle_loss(speed_kmh: float) -> float:
    return 0.005 + 0.0004 * speed_kmh


def run(n_tas, dual, speed, n_vehicles, duration_s, seed):
    cfg = load_config()
    cfg.protocol.dual_record = dual
    s = build_federation(n_tas, cfg, seed=seed)
    if n_tas == 1:                                     # the single TA sits mid-corridor
        s.root.tas["RTA-1"].region = "Region-B"
    rng = np.random.default_rng(seed)
    uavs = []
    for cell in range(CORRIDOR_KM // CELL_KM):
        reg = region_of(cell * CELL_KM + 0.5)
        u = s.register_uav(f"U{cell}", reg, ta="RTA-1" if n_tas == 1 else None)
        u.login()
        uavs.append(u.name)
    speeds, events = {}, []
    for i in range(n_vehicles):
        home = REGIONS[rng.integers(3)]
        v = s.register_vehicle(f"V{i}", home, ta="RTA-1" if n_tas == 1 else None)
        v.login()
        vs = speed * rng.uniform(0.9, 1.1)
        speeds[v.name] = vs
        pos = rng.uniform(0, CORRIDOR_KM)
        direction = 1 if rng.random() < 0.5 else -1
        mps = vs / 3.6
        # time until the next cell boundary, then one boundary every CELL_KM
        frac = pos % CELL_KM
        first_km = (CELL_KM - frac) if direction > 0 else frac
        t = first_km * 1000.0 / mps
        while t < duration_s:
            km = (pos + direction * (t * mps / 1000.0 + 1e-6)) % CORRIDOR_KM
            events.append((t * 1000.0, v.name, uavs[int(km // CELL_KM)], region_of(km)))
            t += CELL_KM * 1000.0 / mps
    events.sort()

    def loss(link, vehicle):
        if link in ("v2ta", "ta2v") and vehicle is not None:
            return vehicle_loss(speeds[vehicle.name])
        return 0.005

    sim = Simulation(s, seed=seed, loss_fn=loss)
    for t, vn, un, reg in events:
        sim.submit(t, vn, un, reg)
    horizon = duration_s * 1000.0 + 8000.0
    sim.run(horizon)
    sim.finalize(horizon)
    reqs = sim.requests
    ok = [q for q in reqs if q.ok]
    lockouts = sum(1 for q in reqs if not q.ok and
                   ("unknown vehicle" in q.reason or "stale temporary identity" in q.reason))
    summ = sim.summary()
    return {
        "speed_kmh": speed, "requests": len(reqs), "offered_rate_per_s": len(events) / duration_s,
        "success_pct": 100.0 * len(ok) / len(reqs),
        "timely_pct": 100.0 * sum(q.t_end - q.t_start <= DEADLINE_MS for q in ok) / len(reqs),
        "mean_latency_ms": float(np.mean([q.t_end - q.t_start for q in ok])),
        "p95_latency_ms": float(np.percentile([q.t_end - q.t_start for q in ok], 95)),
        "mean_attempts": summ["mean_attempts"],
        "delegated_pct": 100.0 * summ["delegated_fraction"],
        "desync_lockouts": lockouts,
        "lost_messages": summ["lost_messages"],
        "vehicle_hop_loss_pct": 100.0 * vehicle_loss(speed),
    }


def main(speeds=(20, 40, 60, 80, 100, 120, 140), n_vehicles=6000, duration_s=40.0):
    out = {"speeds": list(speeds), "n_vehicles": n_vehicles, "duration_s": duration_s,
           "deadline_ms": DEADLINE_MS, "configs": {}}
    for name, n, dual in CONFIGS:
        pts = []
        for i, v in enumerate(speeds):
            print(f"  running {name}, {v} km/h...", flush=True)
            p = run(n, dual, v, n_vehicles, duration_s, seed=300 + i)
            pts.append(p)
            print(f"{name:36s} {v:3d} km/h  {p['offered_rate_per_s']:6.1f} req/s  success "
                  f"{p['success_pct']:.2f}%  timely {p['timely_pct']:.2f}%  mean "
                  f"{p['mean_latency_ms']:.1f} ms  lockouts {p['desync_lockouts']}  "
                  f"delegated {p['delegated_pct']:.0f}%", flush=True)
        out["configs"][name] = pts
    save_json("e7_mobility", out)
    plot(out)
    return out


def plot(out):
    colors = [BLUE, ORANGE, AQUA]
    for key, ylabel, fname, title in (
            ("success_pct", "Successful authentications (%)", "fig_mobility_success",
             "Authentication success versus vehicle speed"),
            ("mean_latency_ms", "Mean latency of successful runs (ms)", "fig_mobility_latency",
             "Authentication latency versus vehicle speed")):
        fig, ax = new_figure(6.4, 3.2)
        for (name, pts), c, m in zip(out["configs"].items(), colors, MARKERS):
            ax.plot(out["speeds"], [p[key] for p in pts], color=c, marker=m, label=name)
        ax.set_xlabel("Vehicle speed (km/h)")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.legend(loc="lower left" if key == "success_pct" else "upper left")
        save_figure(fig, fname)


if __name__ == "__main__":
    main()
