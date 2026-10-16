"""E10 - executable attack scenarios (see hfselap/attacks.py)."""

from __future__ import annotations

from dataclasses import asdict

from common import save_json
from hfselap import attacks


def main():
    outcomes = attacks.all_scenarios()
    ablation = attacks.desynchronisation(dual_record=False)
    rows = [asdict(o) for o in outcomes]
    out = {"scenarios": rows, "ablation_without_dual_record": asdict(ablation),
           "blocked": sum(o.blocked for o in outcomes), "total": len(outcomes)}
    save_json("e10_security", out)
    for o in outcomes:
        print(("BLOCKED " if o.blocked else "FAILED  ") + o.attack)
    print(f"{out['blocked']}/{out['total']} attacks blocked; ablation blocked={ablation.blocked}")
    return out


if __name__ == "__main__":
    main()
