"""E5 - scalability and load balancing under a disaster hot-spot workload.

Authentication requests arrive as a Poisson process.  70 % of them come from
vehicles of Region-A (the disaster epicentre); the rest are split evenly over
the other regions.  Four deployments are compared:

* SELAP baseline - one TA serves everybody;
* HF-SELAP with 3 RTAs but static routing (each request goes to its home RTA);
* HF-SELAP with 2 and with 3 RTAs and the load balancer enabled.
"""

from __future__ import annotations

import numpy as np

from common import (BLUE, ORANGE, AQUA, YELLOW, MARKERS, REGIONS, build_federation,
                    new_figure, save_figure, save_json)
from hfselap.simulation import Simulation

CONFIGS = [
    ("SELAP (single TA)", 1, "lb"),
    ("HF-SELAP, 3 RTAs, static routing", 3, "home"),
    ("HF-SELAP, 2 RTAs, load-balanced", 2, "lb"),
    ("HF-SELAP, 3 RTAs, load-balanced", 3, "lb"),
]
HOTSPOT = 0.7


def build(n_tas, vehicles_per_region, uavs_per_region, seed):
    s = build_federation(n_tas, seed=seed)
    regions = REGIONS[:n_tas]
    pools = {r: [] for r in regions}
    uavs = {r: [] for r in regions}
    for r in regions:
        for i in range(vehicles_per_region if n_tas > 1 else vehicles_per_region * 2):
            v = s.register_vehicle(f"V-{r}-{i}", r)
            v.login()
            pools[r].append(v.name)
        for i in range(uavs_per_region if n_tas > 1 else uavs_per_region * 2):
            u = s.register_uav(f"U-{r}-{i}", r)
            u.login()
            uavs[r].append(u.name)
    return s, regions, pools, uavs


def run_point(n_tas, routing, rate, window_ms, seed, vpr, upr):
    s, regions, pools, uavs = build(n_tas, vpr, upr, seed)
    sim = Simulation(s, seed=seed, routing=routing)
    rng = np.random.default_rng(seed + 1000)
    weights = [1.0] if n_tas == 1 else [HOTSPOT] + [(1 - HOTSPOT) / (n_tas - 1)] * (n_tas - 1)
    t = 0.0
    while True:
        t += rng.exponential(1000.0 / rate)
        if t > window_ms:
            break
        r = regions[rng.choice(len(regions), p=weights)]
        sim.submit(t, pools[r][rng.integers(len(pools[r]))], uavs[r][rng.integers(len(uavs[r]))])
    horizon = window_ms + 6000.0
    sim.run(horizon)
    sim.finalize(horizon)
    summ = sim.summary()
    summ["offered_rate"] = rate
    summ["throughput_per_s"] = summ["successes"] / (window_ms / 1000.0)
    return summ


def averaged(n, routing, rate, window_ms, seeds, vpr, upr):
    """Run one load point with several independent seeds and average the metrics."""
    runs = [run_point(n, routing, rate, window_ms, sd, vpr, upr) for sd in seeds]
    keys = ("success_rate", "mean_latency_ms", "p95_latency_ms", "jain_fairness",
            "throughput_per_s", "mean_attempts", "delegated_fraction")
    out = {k: sum(r[k] for r in runs) / len(runs) for k in keys}
    out.update(offered_rate=rate, repeats=len(runs),
               success_rate_min=min(r["success_rate"] for r in runs),
               success_rate_max=max(r["success_rate"] for r in runs),
               requests=sum(r["requests"] for r in runs))
    return out


def main(rates=(500, 1000, 1500, 2000, 2500, 3000), window_ms=2000.0,
         vehicles_per_region=1500, uavs_per_region=20, repeats=2):
    out = {"rates": list(rates), "window_ms": window_ms, "hotspot_share": HOTSPOT,
           "repeats": repeats, "configs": {}}
    for name, n, routing in CONFIGS:
        points = []
        for i, rate in enumerate(rates):
            seeds = [100 + i + 1000 * k for k in range(repeats)]
            print(f"  running {name}, {rate} requests/s ({repeats} run(s))...", flush=True)
            p = averaged(n, routing, rate, window_ms, seeds, vehicles_per_region,
                         uavs_per_region)
            points.append(p)
            print(f"{name:36s} {rate:5d}/s  success {p['success_rate']:.3f}  "
                  f"mean {p['mean_latency_ms']:.1f} ms  p95 {p['p95_latency_ms']:.1f}  "
                  f"jain {p['jain_fairness']:.3f}", flush=True)
        out["configs"][name] = points
    save_json("e5_scalability", out)
    plot(out)
    return out


def plot(out):
    rates = out["rates"]
    colors = [BLUE, ORANGE, AQUA, YELLOW]
    fig, ax = new_figure(6.4, 3.4)
    for (name, pts), c, m in zip(out["configs"].items(), colors, MARKERS):
        ax.plot(rates, [100 * p["success_rate"] for p in pts], color=c, marker=m, label=name)
    ax.set_xlabel("Offered authentication load (requests/s)")
    ax.set_ylabel("Successful authentications (%)")
    ax.set_title("Authentication success rate under a 70 % hot-spot load")
    ax.set_ylim(0, 105)
    ax.legend(loc="lower left")
    save_figure(fig, "fig_scalability_success")

    fig, ax = new_figure(6.4, 3.4)
    for (name, pts), c, m in zip(out["configs"].items(), colors, MARKERS):
        ax.plot(rates, [p["p95_latency_ms"] for p in pts], color=c, marker=m, label=name)
    ax.set_yscale("log")
    ax.set_xlabel("Offered authentication load (requests/s)")
    ax.set_ylabel("95th-percentile latency of successful runs (ms, log scale)")
    ax.set_title("End-to-end authentication latency under load")
    ax.legend(loc="upper left")
    save_figure(fig, "fig_scalability_latency")


if __name__ == "__main__":
    main()
