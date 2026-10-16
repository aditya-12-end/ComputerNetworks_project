"""E1 - execution time of every cryptographic primitive used by HF-SELAP."""

from __future__ import annotations

import gc
import hashlib
import os
import time

import numpy as np

from common import save_json, stats
from hfselap import ascon
from hfselap.puf import ArbiterPUF, FuzzyExtractor


def bench(fn, runs: int) -> dict:
    for _ in range(min(50, runs)):                     # warm-up
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


def main(runs: int = 2000):
    k16, k20, iv, ad = os.urandom(16), os.urandom(20), os.urandom(16), os.urandom(16)
    pt = os.urandom(64)                                # largest SELAP plaintext block
    c, tag = ascon.encrypt(k16, iv, ad, pt)
    fe = FuzzyExtractor(7)
    rng = np.random.default_rng(0)
    puf = ArbiterPUF(fe.n_bits, 0.03, rng)
    ch = os.urandom(16)
    ref = puf.enrol_response(ch, 9)
    _, helper = fe.gen(ref, rng)
    noisy = puf.evaluate(ch)                           # Rep timed without the PUF read
    data = os.urandom(96)

    results = {
        "SHA-256 hash (Th)": bench(lambda: hashlib.sha256(data).digest(), runs),
        "Ascon-128 encryption, 64 B (Ta)": bench(lambda: ascon.encrypt(k16, iv, ad, pt), runs),
        "Ascon-128 decryption, 64 B (Ta)": bench(lambda: ascon.decrypt(k16, iv, ad, c, tag), runs),
        "Ascon-80pq encryption, 64 B": bench(
            lambda: ascon.encrypt(k20, iv, ad, pt, "Ascon-80pq"), runs),
        "PUF evaluation, 896-bit response (Tp)": bench(lambda: puf.evaluate(ch), runs),
        "Fuzzy extractor Gen": bench(lambda: fe.gen(ref, rng), runs),
        "Fuzzy extractor Rep (Tf)": bench(lambda: fe.rep_(noisy, helper), runs),
    }
    out = {"runs": runs, "primitives": results}
    save_json("e1_primitives", out)
    for name, s in results.items():
        print(f"{name:42s} {s['mean']:.4f} ms (sd {s['sd']:.4f})")
    return out


if __name__ == "__main__":
    main()
