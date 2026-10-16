"""Simulated arbiter PUF and code-offset fuzzy extractor.

PUF model
---------
Each UAV owns an arbiter PUF described by the additive linear delay model:
65 device-specific delay parameters ``w`` (manufacturing variation, drawn once
from N(0, 1)).  A 128-bit challenge C is expanded with SHAKE-256 into
``n`` 64-stage sub-challenges; response bit i is ``sign(w . phi(c_i))`` where
``phi`` is the standard parity feature transform.  Environmental noise
(temperature / voltage) is modelled as independent bit flips with probability
``noise_rate`` per evaluation (a binary symmetric channel).

Fuzzy extractor
---------------
Code-offset construction with a repetition code ``REP(rep)``:

* ``Gen(R)``  : pick random secret s (128 bits), c = Enc(s), helper H = R xor c,
                key K = SHA-256("FE" || R).
* ``Rep(R',H)``: s' = Dec(R' xor H) by majority vote, R = Enc(s') xor H,
                K = SHA-256("FE" || R).

``Rep`` returns the original K whenever no repetition block has more than
floor(rep/2) flipped bits.  A wrong key is detected one step later, because
the ASCON tag of Msg2 then fails to verify (the UAV may re-measure the PUF).
"""

from __future__ import annotations

import hashlib

import numpy as np

from .primitives import METER

STAGES = 64
SECRET_BITS = 128


def _subchallenge_features(challenge: bytes, n_bits: int) -> np.ndarray:
    stream = hashlib.shake_256(b"HF-SELAP-PUF" + challenge).digest(n_bits * STAGES // 8)
    bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8)).reshape(n_bits, STAGES)
    signs = 1 - 2 * bits.astype(np.int8)                      # 0 -> +1, 1 -> -1
    phi = np.cumprod(signs[:, ::-1], axis=1)[:, ::-1]         # phi_i = prod_{j>=i}
    return np.hstack([phi, np.ones((n_bits, 1), dtype=np.int8)]).astype(np.float64)


class ArbiterPUF:
    def __init__(self, n_bits: int, noise_rate: float = 0.03,
                 rng: np.random.Generator | None = None):
        self.rng = rng if rng is not None else np.random.default_rng()
        self.n_bits = n_bits
        self.noise_rate = noise_rate
        self.weights = self.rng.normal(0.0, 1.0, STAGES + 1)
        self.tampered = False

    def ideal_response(self, challenge: bytes) -> np.ndarray:
        """Noise-free response bits (used only for analysis, never by protocol)."""
        delay = _subchallenge_features(challenge, self.n_bits) @ self.weights
        return (delay > 0).astype(np.uint8)

    def evaluate(self, challenge: bytes) -> np.ndarray:
        """One physical PUF measurement RS = PUF(C) +/- noise."""
        METER.add("puf")
        if self.tampered:
            # invasive tampering irreversibly changes the delay characteristics
            return self.rng.integers(0, 2, self.n_bits, dtype=np.uint8)
        response = self.ideal_response(challenge)
        flips = self.rng.random(self.n_bits) < self.noise_rate
        return response ^ flips.astype(np.uint8)

    def enrol_response(self, challenge: bytes, reads: int) -> np.ndarray:
        """Reference response for enrolment: bitwise majority of ``reads`` reads."""
        votes = sum(self.evaluate(challenge).astype(np.int32) for _ in range(reads))
        return (votes > reads // 2).astype(np.uint8)

    def tamper(self):
        self.tampered = True


class FuzzyExtractor:
    def __init__(self, rep: int = 7, secret_bits: int = SECRET_BITS):
        if rep < 1 or rep % 2 == 0:
            raise ValueError("repetition factor must be a positive odd number")
        self.rep = rep
        self.secret_bits = secret_bits
        self.n_bits = rep * secret_bits

    @property
    def helper_bytes(self) -> int:
        return self.n_bits // 8

    @staticmethod
    def _key(response: np.ndarray) -> bytes:
        return hashlib.sha256(b"FE" + np.packbits(response).tobytes()).digest()

    def gen(self, response: np.ndarray, rng: np.random.Generator | None = None):
        """Return (K, H): a 256-bit key and the public helper data (bytes)."""
        METER.add("fe")
        rng = rng if rng is not None else np.random.default_rng()
        secret = rng.integers(0, 2, self.secret_bits, dtype=np.uint8)
        codeword = np.repeat(secret, self.rep)
        helper = np.packbits(response ^ codeword).tobytes()
        return self._key(response), helper

    def rep_(self, noisy: np.ndarray, helper: bytes) -> bytes:
        """Reproduce K from a noisy response and helper data."""
        METER.add("fe")
        offset = np.unpackbits(np.frombuffer(helper, dtype=np.uint8))[: self.n_bits]
        votes = (noisy ^ offset).reshape(self.secret_bits, self.rep).sum(axis=1)
        secret = (votes > self.rep // 2).astype(np.uint8)
        recovered = np.repeat(secret, self.rep) ^ offset
        return self._key(recovered)


def block_failure_probability(noise: float, rep: int, blocks: int = SECRET_BITS) -> float:
    """Analytical probability that Rep() fails for one PUF read (for plots)."""
    from math import comb
    t = rep // 2
    p_block = sum(comb(rep, i) * noise ** i * (1 - noise) ** (rep - i)
                  for i in range(t + 1, rep + 1))
    return 1 - (1 - p_block) ** blocks
