"""E1 - execution time of every cryptographic primitive used by HF-SELAP."""

from __future__ import annotations

import gc
import hashlib
import os
import time

from common import save_json, stats
from hfselap import ascon
from hfselap import certificateless as cl


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
    data = os.urandom(96)
    sk = cl.random_scalar().to_bytes(32, "big")
    key = cl.signer(sk)
    ver = cl.verifier(cl.encode_point(cl.base_mult(int.from_bytes(sk, "big"))))
    msg = os.urandom(90)                               # size of the signed vehicle input
    sig = cl.sign(key, msg)

    results = {
        "SHA-256 hash (Th)": bench(lambda: hashlib.sha256(data).digest(), runs),
        "Ascon-128 encryption, 64 B (Ta)": bench(lambda: ascon.encrypt(k16, iv, ad, pt), runs),
        "Ascon-128 decryption, 64 B (Ta)": bench(lambda: ascon.decrypt(k16, iv, ad, c, tag), runs),
        "Ascon-80pq encryption, 64 B": bench(
            lambda: ascon.encrypt(k20, iv, ad, pt, "Ascon-80pq"), runs),
        "ECDSA P-256 signing (Ts)": bench(lambda: cl.sign(key, msg), runs),
        "ECDSA P-256 verification (Tv)": bench(lambda: cl.verify(ver, sig, msg), runs),
    }
    out = {"runs": runs, "primitives": results}
    save_json("e1_primitives", out)
    for name, s in results.items():
        print(f"{name:42s} {s['mean']:.4f} ms (sd {s['sd']:.4f})")
    return out


if __name__ == "__main__":
    main()
