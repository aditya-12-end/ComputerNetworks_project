"""E8 - PUF quality and fuzzy-extractor reliability.

(a) Key-reproduction failure of one PUF read versus environmental noise for
    repetition factors 3/5/7/9 (Monte-Carlo with majority-voted enrolment,
    plus the analytical bound for a noise-free reference).
(b) Intra-device (same chip, repeated reads) versus inter-device (different
    chips, same challenge) fractional Hamming distance.
(c) End-to-end UAV authentication failure with 1 versus 3 allowed PUF reads.
"""

from __future__ import annotations

import os

import numpy as np

from common import (BLUE, ORANGE, AQUA, YELLOW, MARKERS, build_federation, load_config,
                    new_figure, save_figure, save_json)
from hfselap.puf import ArbiterPUF, FuzzyExtractor, block_failure_probability

NOISES = [0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.10, 0.12]
REPS = [3, 5, 7, 9]


def fe_failure(noise, rep, trials, rng):
    fe = FuzzyExtractor(rep)
    fails = 0
    for d in range(trials // 20):
        puf = ArbiterPUF(fe.n_bits, noise, rng)
        ch = os.urandom(16)
        key, helper = fe.gen(puf.enrol_response(ch, 9), rng)
        for _ in range(20):
            fails += fe.rep_(puf.evaluate(ch), helper) != key
    return fails / (trials // 20 * 20)


def main(trials: int = 2000):
    rng = np.random.default_rng(8)
    curves = {}
    for rep in REPS:
        curves[rep] = {"empirical": [fe_failure(p, rep, trials, rng) for p in NOISES],
                       "analytic_single_read": [block_failure_probability(p, rep) for p in NOISES]}
        print(f"rep {rep}: " + " ".join(f"{x:.4f}" for x in curves[rep]["empirical"]))

    # (b) uniqueness and reliability on 896-bit responses
    fe = FuzzyExtractor(7)
    chips = [ArbiterPUF(fe.n_bits, 0.03, rng) for _ in range(40)]
    ch = os.urandom(16)
    ideal = [c.ideal_response(ch) for c in chips]
    inter = [float(np.mean(ideal[i] != ideal[j]))
             for i in range(len(chips)) for j in range(i + 1, len(chips))]
    intra = []
    for c in chips:
        ref = c.enrol_response(ch, 9)
        intra += [float(np.mean(ref != c.evaluate(ch))) for _ in range(20)]
    uniformity = float(np.mean([r.mean() for r in ideal]))

    # (c) end-to-end authentication with 1 vs 3 allowed reads at higher noise
    e2e = {}
    for noise in (0.03, 0.06, 0.09):
        for reads in (1, 3):
            cfg = load_config()
            cfg.protocol.puf_noise_rate = noise
            cfg.protocol.puf_max_reads = reads
            s = build_federation(1, cfg, seed=4, monitor_mode="oracle")
            v = s.register_vehicle("V", "Region-A")
            us = [s.register_uav(f"U{i}", "Region-A") for i in range(20)]
            for e in [v] + us:
                e.login()
            n = ok = 0
            for k in range(300):
                r = s.authenticate(v, us[k % len(us)])
                n += 1
                ok += r.ok
            e2e[f"noise={noise:.2f}, reads={reads}"] = 100.0 * (n - ok) / n
            print(f"e2e noise {noise} reads {reads}: failure {100.0 * (n - ok) / n:.2f}%")

    out = {"noises": NOISES, "curves": {str(k): v for k, v in curves.items()},
           "inter_hd": {"mean": float(np.mean(inter)), "sd": float(np.std(inter))},
           "intra_hd": {"mean": float(np.mean(intra)), "sd": float(np.std(intra))},
           "uniformity": uniformity, "inter_samples": inter, "intra_samples": intra,
           "e2e_failure_pct": e2e, "trials_per_point": trials}
    save_json("e8_puf", out)
    plot(out)
    return out


def plot(out):
    colors = [BLUE, ORANGE, AQUA, YELLOW]
    fig, ax = new_figure(6.4, 3.3)
    floor = 1.0 / out["trials_per_point"]
    for (rep, cur), c, m in zip(out["curves"].items(), colors, MARKERS):
        y = [max(v, floor / 2) for v in cur["empirical"]]
        ax.plot([100 * n for n in out["noises"]], y, color=c, marker=m, label=f"Repetition {rep}")
    ax.axhline(floor, color="#52514e", linewidth=0.8)
    ax.text(100 * out["noises"][0], floor * 1.25, "measurement floor (0 failures observed below)",
            fontsize=7, color="#52514e")
    ax.set_yscale("log")
    ax.set_xlabel("PUF bit-error rate per read (%)")
    ax.set_ylabel("Key-reproduction failure per read")
    ax.set_title("Fuzzy-extractor reliability versus PUF noise")
    ax.legend(loc="lower right")
    save_figure(fig, "fig_puf_reliability")

    fig, ax = new_figure(6.4, 3.0)
    bins = np.linspace(0, 0.7, 71)
    ax.hist(out["intra_samples"], bins=bins, color=BLUE, label="Intra-device (same UAV, re-read)",
            density=True, rwidth=0.85)
    ax.hist(out["inter_samples"], bins=bins, color=ORANGE, label="Inter-device (different UAVs)",
            density=True, rwidth=0.85)
    ax.set_xlabel("Fractional Hamming distance of 896-bit responses")
    ax.set_ylabel("Density")
    ax.set_title("PUF reliability and uniqueness")
    ax.legend(loc="upper center")
    save_figure(fig, "fig_puf_hamming")


if __name__ == "__main__":
    main()
