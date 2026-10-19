"""E8 - certificateless key management and the cost of the certificateless layer.

(a) Execution time of every certificateless operation: secret-value generation,
    partial-private-key extraction at the KGC, partial-key validation, full-key
    formation, verification-key derivation at the RTA, signing and verifying.
(b) Complete enrolment time of a vehicle and of a UAV (VR-1..VR-3 / UR-1..UR-3,
    including the KGC round trip and the escrow deposit).
(c) Composition of the per-entity authentication cost: measured primitive
    costs multiplied by the operation counts of one metered AKA run.
"""

from __future__ import annotations

import gc
import hashlib
import os
import time

from common import (BLUE, ORANGE, AQUA, build_federation, new_figure, save_figure, save_json,
                    stats)
from hfselap import ascon
from hfselap import certificateless as cl
from hfselap.primitives import METER


def bench(fn, runs: int) -> dict:
    for _ in range(min(30, runs)):                     # warm-up
        fn()
    times = []
    gc.collect()
    gc.disable()
    try:
        for _ in range(runs):
            t = time.perf_counter()
            fn()
            times.append((time.perf_counter() - t) * 1000.0)
    finally:
        gc.enable()
    return stats(times)


def main(runs: int = 1000, enrolments: int = 300):
    kgc = cl.KGC()
    kgc.public.mult(1)                                 # build the P_pub table once
    ident = os.urandom(32)
    x, x_pub = cl.new_secret_value()
    r_pub, d = kgc.extract_partial_key(ident, x_pub)
    sk = cl.full_private_key(ident, x, x_pub, r_pub, d, kgc.public)
    q = cl.verification_key(ident, x_pub, r_pub, kgc.public)
    key, ver = cl.signer(sk), cl.verifier(q)
    msg = os.urandom(90)
    sig = cl.sign(key, msg)

    ops = {
        "Secret value x_E, X_E = x_E G (entity)": bench(cl.new_secret_value, runs),
        "Partial private key R_E, D_E (KGC)": bench(
            lambda: kgc.extract_partial_key(ident, x_pub), runs),
        "Partial-key validation (entity)": bench(
            lambda: cl.partial_key_valid(ident, x_pub, r_pub, d, kgc.public), runs),
        "Full private key SK_E = x_E + D_E (entity)": bench(
            lambda: cl.signer(((x + d) % cl.N).to_bytes(32, "big")), runs),
        "Verification key Q_E (RTA)": bench(
            lambda: cl.verification_key(ident, x_pub, r_pub, kgc.public), runs),
        "Sign sigma_E (entity, per AKA)": bench(lambda: cl.sign(key, msg), runs),
        "Verify sigma_E (RTA, per AKA)": bench(lambda: cl.verify(ver, sig, msg), runs),
    }
    for name, st in ops.items():
        print(f"{name:46s} {st['mean']:.4f} ms")

    # (b) complete enrolment inside a 3-RTA federation
    s = build_federation(3, seed=8, monitor_mode="oracle")
    s.root.kgc.public.mult(1)
    t_v, t_u = [], []
    for i in range(enrolments):
        t = time.perf_counter()
        s.register_vehicle(f"V{i}", "Region-A")
        t_v.append((time.perf_counter() - t) * 1000.0)
        t = time.perf_counter()
        s.register_uav(f"U{i}", "Region-A")
        t_u.append((time.perf_counter() - t) * 1000.0)
    enrol = {"vehicle": stats(t_v), "uav": stats(t_u)}
    print(f"enrolment: vehicle {enrol['vehicle']['mean']:.3f} ms, UAV {enrol['uav']['mean']:.3f} ms")

    # (c) cost composition of one authentication
    v, u = s.vehicles["V0"], s.uavs["U0"]
    v.login()
    u.login()
    s.authenticate(v, u)                               # warm caches
    METER.reset()
    assert s.authenticate(v, u).ok
    counts = METER.snapshot()
    k16, iv, ad, pt = os.urandom(16), os.urandom(16), os.urandom(16), os.urandom(80)
    data = os.urandom(96)
    unit = {"hash": bench(lambda: hashlib.sha256(data).digest(), runs)["mean"],
            "ascon": bench(lambda: ascon.encrypt(k16, iv, ad, pt), runs)["mean"],
            "sign": ops["Sign sigma_E (entity, per AKA)"]["mean"],
            "verify": ops["Verify sigma_E (RTA, per AKA)"]["mean"]}
    composition = {}
    for who in ("vehicle", "uav", "ta"):
        c = counts.get(who, {})
        ascon_ops = c.get("ascon", 0) - (1 if who == "ta" else 0)   # exclude async TID sync
        composition[who] = {"hash": c.get("hash", 0) * unit["hash"],
                            "ascon": ascon_ops * unit["ascon"],
                            "certificateless": c.get("sign", 0) * unit["sign"]
                            + c.get("verify", 0) * unit["verify"],
                            "counts": c}
    out = {"runs": runs, "operations": ops, "enrolment": enrol, "enrolments": enrolments,
           "unit_costs_ms": unit, "composition_ms": composition,
           "sizes_bytes": {"public value X_E / R_E / Q_E": cl.POINT_BYTES,
                           "partial private key D_E": cl.SCALAR_BYTES,
                           "full private key SK_E": cl.SCALAR_BYTES,
                           "signature sigma_E": cl.SIG_BYTES}}
    save_json("e8_cl", out)
    plot(out)
    return out


SHORT = {
    "Secret value x_E, X_E = x_E G (entity)": "Secret value x, X = xG",
    "Partial private key R_E, D_E (KGC)": "Partial key R, D (KGC)",
    "Partial-key validation (entity)": "Partial-key validation",
    "Full private key SK_E = x_E + D_E (entity)": "Full key SK = x + D",
    "Verification key Q_E (RTA)": "Verification key Q (RTA)",
    "Sign sigma_E (entity, per AKA)": "Sign (per AKA)",
    "Verify sigma_E (RTA, per AKA)": "Verify (per AKA)",
}


def plot(out):
    ops = out["operations"]
    names = [SHORT.get(k, k) for k in ops] + ["Vehicle enrolment (total)", "UAV enrolment (total)"]
    vals = [v["mean"] for v in ops.values()] + [out["enrolment"]["vehicle"]["mean"],
                                                out["enrolment"]["uav"]["mean"]]
    colors = [BLUE] * 5 + [ORANGE] * 2 + [AQUA] * 2
    fig, ax = new_figure(6.4, 3.4)
    ax.barh(names, vals, color=colors, height=0.6)
    for y, val in enumerate(vals):
        ax.text(val * 1.04, y, f"{val:.3f}", va="center", fontsize=7.5, color="#52514e")
    ax.invert_yaxis()
    ax.set_xlabel("Mean execution time (ms)")
    ax.set_title("Cost of the certificateless operations")
    ax.set_xlim(0, max(vals) * 1.18)
    ax.grid(axis="y", visible=False)
    save_figure(fig, "fig_cl_operations")

    comp = out["composition_ms"]
    labels = [("vehicle", "Vehicle"), ("uav", "UAV"), ("ta", "Serving RTA")]
    fig, ax = new_figure(6.4, 3.0)
    left = [0.0] * len(labels)
    for key, lab, color in (("hash", "SHA-256 hashing", BLUE), ("ascon", "ASCON AEAD", ORANGE),
                            ("certificateless", "Certificateless sign / verify", AQUA)):
        vals = [comp[w][key] for w, _ in labels]
        ax.barh([lbl for _, lbl in labels], vals, left=left, color=color, label=lab, height=0.55)
        left = [a + b for a, b in zip(left, vals)]
    ax.invert_yaxis()
    ax.set_xlabel("Estimated computation per authentication (ms)")
    ax.set_title("Where the authentication cost goes")
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.2))
    ax.grid(axis="y", visible=False)
    save_figure(fig, "fig_cl_composition")


if __name__ == "__main__":
    main()
