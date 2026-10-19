"""Shared cryptographic helpers, simulated clock and operation metering.

Every protocol module calls the helpers in this file (and the signature
helpers of ``certificateless.py``) instead of hashlib / ascon directly, so that
the number of hash, ASCON, signing and verification operations executed by each
party can be counted (``OpMeter``).  The report compares those counts with the
analytical cost model of the base SELAP paper (e.g. vehicle = 5 Th + 2 Ta).
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import secrets
import time
from collections import defaultdict

from . import ascon

NONCE = 16          # 128-bit nonces, identities, credentials, TIDs
HASH = 32           # 256-bit SHA-256 output
TS = 4              # 32-bit timestamps
TAG = ascon.TAG_BYTES

# ----------------------------------------------------------------- metering
_actor: contextvars.ContextVar[str | None] = contextvars.ContextVar("actor", default=None)


class OpMeter:
    """Counts primitive operations per actor (vehicle / uav / ta / root)."""

    def __init__(self):
        self.counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.enabled = True

    def add(self, op: str, n: int = 1):
        actor = _actor.get()
        if self.enabled and actor is not None:
            self.counts[actor][op] += n

    def reset(self):
        self.counts.clear()

    def snapshot(self) -> dict[str, dict[str, int]]:
        return {a: dict(ops) for a, ops in self.counts.items()}


METER = OpMeter()


@contextlib.contextmanager
def acting_as(actor: str):
    """Attribute every primitive call inside the block to ``actor``."""
    token = _actor.set(actor)
    try:
        yield
    finally:
        _actor.reset(token)


# --------------------------------------------------------------- primitives
def h(*parts: bytes) -> bytes:
    """One-way hash h(.) = SHA-256 over the concatenation of fixed-size fields."""
    METER.add("hash")
    return hashlib.sha256(b"".join(parts)).digest()


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR operands must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def rand(n: int = NONCE) -> bytes:
    return secrets.token_bytes(n)


class AeadParams:
    """IV, AD and key derived from a 256-bit credential M (SELAP Remark 2).

    IV = M^a, AD = M^b and k = M^a XOR M^b, where M^a / M^b are the two
    128-bit halves of M.  In post-quantum mode the 160-bit Ascon-80pq key is
    k = Trunc160(SHA-256("HF-SELAP-PQ" || M)); IV and AD are unchanged.
    """

    __slots__ = ("iv", "ad", "key", "variant")

    def __init__(self, m: bytes, pq: bool = False):
        if len(m) != HASH:
            raise ValueError("credential M must be 32 bytes")
        self.iv, self.ad = m[:16], m[16:]
        if pq:
            self.key = hashlib.sha256(b"HF-SELAP-PQ" + m).digest()[:20]
            self.variant = "Ascon-80pq"
        else:
            self.key = xor(self.iv, self.ad)
            self.variant = "Ascon-128"


def seal(params: AeadParams, plaintext: bytes) -> tuple[bytes, bytes]:
    METER.add("ascon")
    return ascon.encrypt(params.key, params.iv, params.ad, plaintext, params.variant)


def open_(params: AeadParams, ciphertext: bytes, tag: bytes) -> bytes:
    """ASCON decryption; raises ``ascon.AsconAuthError`` on a bad tag."""
    METER.add("ascon")
    return ascon.decrypt(params.key, params.iv, params.ad, ciphertext, tag, params.variant)


def key_verifier(sk: bytes) -> bytes:
    """Session-key verifier SKV = SK^a XOR SK^b (128 bits)."""
    return xor(sk[:16], sk[16:])


# -------------------------------------------------------------------- clock
class Clock:
    """Millisecond clock.  ``SimClock`` is driven by the event simulator."""

    def now_ms(self) -> float:
        return time.time() * 1000.0


class SimClock(Clock):
    def __init__(self, start_ms: float = 1_000_000.0):
        self.t = start_ms

    def now_ms(self) -> float:
        return self.t

    def set(self, t_ms: float):
        self.t = t_ms

    def advance(self, dt_ms: float):
        self.t += dt_ms


def encode_ts(t_ms: float) -> bytes:
    """32-bit timestamp: milliseconds modulo 2^32."""
    return (int(t_ms) & 0xFFFFFFFF).to_bytes(TS, "big")


def ts_age_ms(now_ms: float, ts: bytes) -> int:
    """Age of a 32-bit timestamp, wrap-around safe (|T_R - T| in the paper)."""
    sent = int.from_bytes(ts, "big")
    now = int(now_ms) & 0xFFFFFFFF
    diff = (now - sent) & 0xFFFFFFFF
    if diff >= 0x80000000:          # timestamp lies in the future
        diff -= 0x100000000
    return diff


def fresh(now_ms: float, ts: bytes, delta_t_ms: float) -> bool:
    return abs(ts_age_ms(now_ms, ts)) <= delta_t_ms
