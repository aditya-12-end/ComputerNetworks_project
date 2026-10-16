"""E2/E11/E12 - per-entity computation cost, post-quantum mode and energy.

Every AKA step is timed individually on the real implementation:
vehicle (A-1 + A-6), UAV (A-4) and serving TA (A-2/A-3 + A-5).  The TA
column of the federated scenarios includes the write-through TID
synchronisation with the root (the cost HF-SELAP adds to SELAP).
"""

from __future__ import annotations

import gc
import secrets
import time

import numpy as np

from common import (BLUE, ORANGE, AQUA, YELLOW, PI5_POWER_W, build_federation,
                    load_config, new_figure, save_figure, save_json, stats)
from hfselap.primitives import METER


def timed(fn, *args):
    t = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - t) * 1000.0


def one_run(s, v, u, ta):
    sid = secrets.randbits(32)
    m1, tv1 = timed(v.start, u.id_u)
    (m2, f1), tt1 = timed(s.run_ta_step, ta, ta.handle_msg1, m1, sid)
    m3, tu = timed(u.respond, m2, sid)
    (m4, f2), tt2 = timed(s.run_ta_step, ta, ta.handle_msg3, m3, sid)
    sk, tv2 = timed(v.finish, m4)
    aka_ops = METER.snapshot()                        # operations of the AKA itself
    _, tsync = timed(ta.flush_federation)             # asynchronous, off the AKA path
    all_ops = METER.snapshot()
    sync_ops = {a: {op: n - aka_ops.get(a, {}).get(op, 0) for op, n in ops.items()
                    if n - aka_ops.get(a, {}).get(op, 0)}
                for a, ops in all_ops.items()}
    assert sk == u.session_keys.pop(sid)
    s.clock.advance(1.0)
    return {"vehicle": tv1 + tv2, "uav": tu, "ta": tt1 + tt2, "sync": tsync,
            "fetches": f1 + f2, "aka_ops": aka_ops,
            "sync_ops": {a: o for a, o in sync_ops.items() if o}}


SCENARIOS = [("SELAP baseline (single TA)", 1, False, False),
             ("HF-SELAP intra-region", 3, False, False),
             ("HF-SELAP cross-region (delegated)", 3, False, True),
             ("HF-SELAP post-quantum (Ascon-80pq)", 3, True, False)]


def setup(n_tas, pq, cross):
    cfg = load_config()
    cfg.protocol.pq_mode = pq
    s = build_federation(n_tas, cfg, seed=3, monitor_mode="oracle")
    vs = [s.register_vehicle(f"V{i}", "Region-A") for i in range(8)]
    u = s.register_uav("U", "Region-B" if cross else "Region-A")
    for e in vs + [u]:
        e.login()
    ta = s.root.tas["RTA-1"]
    st = {"s": s, "vs": vs, "u": u, "ta": ta,
          "traffic_before": {k: list(v) for k, v in s.root.traffic.items()}}
    METER.reset()
    st["first"] = one_run(s, vs[0], u, ta)            # may include the cold fetch
    st["ops_first"] = METER.snapshot()
    METER.reset()
    steady = one_run(s, vs[1], u, ta)
    st["ops_steady"], st["ops_sync"] = steady["aka_ops"], steady["sync_ops"]
    st["samples"] = {"vehicle": [], "uav": [], "ta": [], "sync": []}
    return st


def summarise(name, st):
    res = {k: stats(v) for k, v in st["samples"].items()}
    res["total_ms"] = sum(res[k]["mean"] for k in ("vehicle", "uav", "ta"))
    res["energy_mJ"] = {k: PI5_POWER_W * res[k]["mean"] for k in ("vehicle", "uav", "ta")}
    res["energy_mJ"]["total"] = sum(res["energy_mJ"].values())
    res["ops_steady"] = st["ops_steady"]
    res["ops_async_sync"] = st["ops_sync"]
    res["ops_first_run"] = st["ops_first"]
    res["first_run"] = {k: st["first"][k] for k in ("vehicle", "uav", "ta", "sync", "fetches")}
    res["traffic"] = {k: v for k, v in st["s"].root.traffic.items()
                      if v != st["traffic_before"].get(k)}
    print(f"{name:38s} V {res['vehicle']['mean']:.3f}  U {res['uav']['mean']:.3f}  "
          f"TA {res['ta']['mean']:.3f}  sync {res['sync']['mean']:.3f}  "
          f"total {res['total_ms']:.3f} ms")
    return res


def main(runs: int = 400, warmup: int = 150):
    """Scenarios are measured round-robin so CPU frequency drift affects all equally."""
    states = {name: setup(n, pq, cross) for name, n, pq, cross in SCENARIOS}
    gc.collect()
    gc.disable()                                      # keep GC pauses out of the timings
    try:
        for i in range(warmup + runs):
            for st in states.values():
                r = one_run(st["s"], st["vs"][i % len(st["vs"])], st["u"], st["ta"])
                if i >= warmup:
                    for k in st["samples"]:
                        st["samples"][k].append(r[k])
            if i % 50 == 0:
                gc.enable()
                gc.collect()
                gc.disable()
    finally:
        gc.enable()
    out = {name: summarise(name, st) for name, st in states.items()}
    out["_meta"] = {"runs": runs, "warmup_runs": warmup, "interleaved": True,
                    "power_model_W": PI5_POWER_W}
    save_json("e2_cost", out)
    plot(out)
    return out


def plot(out):
    names = [k for k in out if not k.startswith("_")]
    labels = ["SELAP (single TA)", "HF-SELAP intra-region", "HF-SELAP cross-region",
              "HF-SELAP post-quantum"]
    entities = [("vehicle", "Vehicle"), ("uav", "UAV"), ("ta", "Serving TA")]
    fig, ax = new_figure(6.4, 3.3)
    width = 0.19
    x = np.arange(len(entities))
    for i, (name, label, color) in enumerate(zip(names, labels, [BLUE, ORANGE, AQUA, YELLOW])):
        means = [out[name][e]["mean"] for e, _ in entities]
        errs = [1.96 * out[name][e]["sd"] / np.sqrt(out[name][e]["n"]) for e, _ in entities]
        ax.bar(x + (i - 1.5) * (width + 0.02), means, width, color=color, label=label,
               yerr=errs, error_kw={"elinewidth": 0.8, "ecolor": "#52514e", "capsize": 2})
    ax.set_xticks(x, [lbl for _, lbl in entities])
    ax.set_ylabel("Computation time per AKA run (ms)")
    ax.set_title("Per-entity computation cost of one authentication")
    ax.set_ylim(0, max(out[n][e]["mean"] for n in names for e, _ in entities) * 1.15)
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.12), fontsize=7.5)
    ax.grid(axis="x", visible=False)
    save_figure(fig, "fig_cost_per_entity")


if __name__ == "__main__":
    main()
