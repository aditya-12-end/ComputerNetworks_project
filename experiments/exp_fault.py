"""E6 - fault tolerance: a Regional TA crashes and later recovers.

Timeline (simulated): requests arrive at a constant Poisson rate for 12 s;
RTA-1 fails at t = 4 s and recovers at t = 8 s.  Compared deployments:

* single-TA baseline (RTA-1 only, no federation);
* HF-SELAP with 3 RTAs but static home routing (no fail-over);
* HF-SELAP with 3 RTAs, heartbeat monitoring and load-balanced fail-over.

Success and latency are attributed to the time each request *started*.
"Timely" success means authenticated within DEADLINE_MS; requests that only
succeed after the failed TA comes back are counted as eventual successes.
"""

from __future__ import annotations

import numpy as np

from common import (BLUE, ORANGE, AQUA, MARKERS, REGIONS, build_federation, new_figure,
                    save_figure, save_json)
from hfselap.simulation import Simulation

CONFIGS = [("Single TA (no federation)", 1, "lb"),
           ("HF-SELAP, static routing", 3, "home"),
           ("HF-SELAP, heartbeat fail-over", 3, "lb")]
FAIL_AT, RECOVER_AT, DURATION, BIN = 4000.0, 8000.0, 12000.0, 250.0
DEADLINE_MS = 1000.0          # an emergency request is useful only if served within 1 s


def run(n_tas, routing, rate, seed=21):
    s = build_federation(n_tas, seed=seed)
    regions = REGIONS[:n_tas]
    pools, uavs = {}, {}
    for r in regions:
        pools[r] = []
        uavs[r] = []
        for i in range(9000 // n_tas):
            v = s.register_vehicle(f"V-{r}-{i}", r)
            v.login()
            pools[r].append(v.name)
        for i in range(max(30 // n_tas, 10)):
            u = s.register_uav(f"U-{r}-{i}", r)
            u.login()
            uavs[r].append(u.name)
    sim = Simulation(s, seed=seed, routing=routing)
    sim.fail_ta(FAIL_AT, "RTA-1")
    sim.recover_ta(RECOVER_AT, "RTA-1")
    rng = np.random.default_rng(seed)
    t = 0.0
    while True:
        t += rng.exponential(1000.0 / rate)
        if t > DURATION:
            break
        r = regions[rng.integers(len(regions))]
        sim.submit(t, pools[r][rng.integers(len(pools[r]))], uavs[r][rng.integers(len(uavs[r]))])
    horizon = DURATION + 8000.0
    sim.run(horizon)
    sim.finalize(horizon)
    bins = np.arange(0, DURATION + BIN, BIN)
    success, latency = [], []
    for lo, hi in zip(bins[:-1], bins[1:]):
        reqs = [q for q in sim.requests if lo <= q.t_start < hi]
        ok = [q for q in reqs if q.ok]
        timely = [q for q in ok if q.t_end - q.t_start <= DEADLINE_MS]
        success.append(100.0 * len(timely) / len(reqs) if reqs else None)
        latency.append(float(np.mean([q.t_end - q.t_start for q in ok])) if ok else None)
    outage = [q for q in sim.requests if FAIL_AT <= q.t_start < RECOVER_AT]
    detections = [(n, t - sim.t0) for n, t in s.monitor.detections]
    summ = sim.summary()
    return {
        "bins_ms": bins[:-1].tolist(), "success_pct": success, "mean_latency_ms": latency,
        "outage_success_pct": 100.0 * sum(q.ok for q in outage) / len(outage),
        "outage_timely_pct": 100.0 * sum(q.ok and q.t_end - q.t_start <= DEADLINE_MS
                                         for q in outage) / len(outage),
        "overall_timely_pct": 100.0 * sum(q.ok and q.t_end - q.t_start <= DEADLINE_MS
                                          for q in sim.requests) / len(sim.requests),
        "overall_success_pct": 100.0 * summ["success_rate"],
        "outage_mean_latency_ms": float(np.mean([q.t_end - q.t_start for q in outage if q.ok]))
        if any(q.ok for q in outage) else None,
        "outage_max_latency_ms": float(max((q.t_end - q.t_start for q in outage if q.ok),
                                           default=0.0)),
        "detections_ms": detections,
        "heartbeats": summ["heartbeats"], "requests": summ["requests"],
        "skipped_busy_vehicle": summ["skipped_busy_vehicle"],
    }


def main(rate: float = 300.0):
    out = {"rate": rate, "fail_at_ms": FAIL_AT, "recover_at_ms": RECOVER_AT,
           "deadline_ms": DEADLINE_MS, "configs": {}}
    for name, n, routing in CONFIGS:
        res = run(n, routing, rate)
        out["configs"][name] = res
        print(f"{name:32s} outage timely {res['outage_timely_pct']:.1f}%  eventual "
              f"{res['outage_success_pct']:.1f}%  overall "
              f"{res['overall_success_pct']:.1f}%  detections {res['detections_ms']}")
    save_json("e6_fault", out)
    plot(out)
    return out


def plot(out):
    colors = [BLUE, ORANGE, AQUA]
    for key, ylabel, fname, title in (
            ("success_pct", "Authenticated within 1 s (%)", "fig_fault_success",
             "Success rate around a Regional TA failure (RTA-1 down 4-8 s)"),
            ("mean_latency_ms", "Mean latency of successful runs (ms)", "fig_fault_latency",
             "Authentication latency around the failure")):
        fig, ax = new_figure(6.4, 3.2)
        ax.axvspan(out["fail_at_ms"] / 1000, out["recover_at_ms"] / 1000, color="#f1f0ec", lw=0)
        ax.text((out["fail_at_ms"] + out["recover_at_ms"]) / 2000, 0.40, "RTA-1 down",
                transform=ax.get_xaxis_transform(), fontsize=8, color="#52514e",
                ha="center", va="center")
        for (name, res), c, m in zip(out["configs"].items(), colors, MARKERS):
            x = [b / 1000 for b, v in zip(res["bins_ms"], res[key]) if v is not None]
            y = [v for v in res[key] if v is not None]
            ax.plot(x, y, color=c, marker=m, markersize=3.5, label=name, linewidth=1.6)
        ax.set_xlabel("Request start time (s)")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        if key == "success_pct":
            ax.set_ylim(0, 105)
            ax.legend(loc="lower left")
        else:
            ax.set_yscale("log")
            ax.legend(loc="upper left")
        save_figure(fig, fname)


if __name__ == "__main__":
    main()
