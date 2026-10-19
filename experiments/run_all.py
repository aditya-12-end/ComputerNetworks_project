"""Run the experiments and regenerate results/*.json and results/figures/*.png.

Usage (from the project root):
    python experiments/run_all.py                 # full run (about 30-40 minutes)
    python experiments/run_all.py --quick         # reduced sizes for a fast check
    python experiments/run_all.py --only E5 E7    # run (or resume) selected experiments

The full and quick runs write the same result files, so run only ONE of them
before building the report (a later --quick run overwrites full results).
"""

from __future__ import annotations

import argparse
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common                                                     # noqa: E402
import exp_cost, exp_fault, exp_mobility, exp_overhead, exp_primitives  # noqa: E402,E401
import exp_cl, exp_revocation, exp_scalability, exp_security       # noqa: E402,E401


def main():
    ap = argparse.ArgumentParser(description="Run the HF-SELAP experiments.")
    ap.add_argument("--quick", action="store_true", help="smaller workloads (about 5 min)")
    ap.add_argument("--only", nargs="+", metavar="EXP",
                    help="run only these experiments, e.g. --only E5 E7")
    args = ap.parse_args()
    q = args.quick
    started = time.time()
    steps = [
        (("E1",), "E1 primitives", lambda: exp_primitives.main(300 if q else 2000)),
        (("E2",), "E2 computation cost", lambda: exp_cost.main(80 if q else 400)),
        (("E3", "E4"), "E3/E4 communication and storage", exp_overhead.main),
        (("E8",), "E8 certificateless key management", lambda: exp_cl.main(
            200 if q else 1000, 60 if q else 300)),
        (("E9",), "E9 revocation and recovery",
         lambda: exp_revocation.main((100, 300) if q else (100, 500, 1000, 2000))),
        (("E10",), "E10 security scenarios", exp_security.main),
        (("E6",), "E6 fault tolerance", exp_fault.main),
        (("E5",), "E5 scalability (slowest step, about 25 min)", lambda: exp_scalability.main(
            rates=(300, 1200, 2100) if q else (300, 600, 900, 1200, 1500, 1800, 2100),
            vehicles_per_region=600 if q else 1500, repeats=1 if q else 2)),
        (("E7",), "E7 mobility (about 8 min)", lambda: exp_mobility.main(
            speeds=(20, 80, 140) if q else (20, 40, 60, 80, 100, 120, 140),
            n_vehicles=2000 if q else 6000, duration_s=20.0 if q else 40.0)),
    ]
    if args.only:
        wanted = {x.upper() for x in args.only}
        known = {key for keys, _, _ in steps for key in keys}
        unknown = wanted - known
        if unknown:
            ap.error(f"unknown experiment(s) {', '.join(sorted(unknown))}; "
                     f"choose from {', '.join(sorted(known, key=lambda k: int(k[1:])))}")
        steps = [step for step in steps if wanted & set(step[0])]

    for _, name, fn in steps:
        t = time.time()
        print(f"\n=== {name} ===", flush=True)
        fn()
        print(f"--- {name} finished in {time.time() - t:.1f} s", flush=True)

    env_path = common.RESULTS / "environment.json"
    env = common.load_json("environment") if env_path.exists() else {}
    env.update({"python": sys.version.split()[0], "platform": platform.platform(),
                "processor": platform.processor(), "cpu_name": common.cpu_name(),
                "machine": platform.machine(), "quick_mode": q,
                "last_run_steps": [name for _, name, _ in steps],
                "last_run_runtime_s": time.time() - started})
    common.save_json("environment", env)
    print(f"\nDone in {time.time() - started:.0f} s; results are in results/", flush=True)


if __name__ == "__main__":
    main()
