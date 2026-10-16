"""Pure-Python implementation of the ASCON v1.2 AEAD family.

Two variants are provided, both with a 64-bit rate and 6/12 permutation
rounds:

* ``Ascon-128``  - 128-bit key, used by the classical HF-SELAP mode.
* ``Ascon-80pq`` - 160-bit key, used by the post-quantum hardened mode
  (larger key space against Grover-style quantum key search).

The code follows the ASCON v1.2 specification (Dobraunig et al., Journal of
Cryptology, 2021). Correctness is checked in ``tests/test_ascon.py`` against
the independent reference implementation published on PyPI (``ascon==0.0.9``).
"""

from __future__ import annotations

_MASK = 0xFFFFFFFFFFFFFFFF
_RATE = 8           # bytes absorbed per permutation call (Ascon-128 / 80pq)
_ROUNDS_A = 12      # initialisation / finalisation rounds
_ROUNDS_B = 6       # data-processing rounds

VARIANTS = {"Ascon-128": 16, "Ascon-80pq": 20}   # variant -> key length (bytes)
NONCE_BYTES = 16
TAG_BYTES = 16


class AsconAuthError(Exception):
    """Raised when an ASCON authentication tag does not verify."""


def _permutation(s0: int, s1: int, s2: int, s3: int, s4: int, rounds: int):
    for r in range(12 - rounds, 12):
        s2 ^= ((0x0F - r) << 4) | r                         # round constant
        # substitution layer (bit-sliced 5-bit S-box)
        s0 ^= s4; s4 ^= s3; s2 ^= s1
        t0 = (s0 ^ _MASK) & s1
        t1 = (s1 ^ _MASK) & s2
        t2 = (s2 ^ _MASK) & s3
        t3 = (s3 ^ _MASK) & s4
        t4 = (s4 ^ _MASK) & s0
        s0 ^= t1; s1 ^= t2; s2 ^= t3; s3 ^= t4; s4 ^= t0
        s1 ^= s0; s0 ^= s4; s3 ^= s2; s2 ^= _MASK
        # linear diffusion layer
        s0 ^= ((s0 >> 19) | (s0 << 45)) & _MASK ^ ((s0 >> 28) | (s0 << 36)) & _MASK
        s1 ^= ((s1 >> 61) | (s1 << 3)) & _MASK ^ ((s1 >> 39) | (s1 << 25)) & _MASK
        s2 ^= ((s2 >> 1) | (s2 << 63)) & _MASK ^ ((s2 >> 6) | (s2 << 58)) & _MASK
        s3 ^= ((s3 >> 10) | (s3 << 54)) & _MASK ^ ((s3 >> 17) | (s3 << 47)) & _MASK
        s4 ^= ((s4 >> 7) | (s4 << 57)) & _MASK ^ ((s4 >> 41) | (s4 << 23)) & _MASK
    return s0, s1, s2, s3, s4


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _initialise(key: bytes, nonce: bytes, ad: bytes):
    k = len(key)
    iv = bytes([k * 8, _RATE * 8, _ROUNDS_A, _ROUNDS_B]) + bytes(20 - k)
    block = iv + key + nonce                                   # 40 bytes
    s = [_int(block[i:i + 8]) for i in range(0, 40, 8)]
    s = list(_permutation(*s, _ROUNDS_A))
    zk = bytes(40 - k) + key
    for i in range(5):
        s[i] ^= _int(zk[8 * i:8 * i + 8])
    if ad:
        padded = ad + b"\x80" + bytes(_RATE - (len(ad) % _RATE) - 1)
        for i in range(0, len(padded), _RATE):
            s[0] ^= _int(padded[i:i + 8])
            s = list(_permutation(*s, _ROUNDS_B))
    s[4] ^= 1                                                  # domain separation
    return s


def _finalise(s: list, key: bytes) -> bytes:
    s[1] ^= _int(key[0:8])
    s[2] ^= _int(key[8:16])
    s[3] ^= _int(key[16:] + bytes(24 - len(key)))
    s = list(_permutation(*s, _ROUNDS_A))
    s[3] ^= _int(key[-16:-8])
    s[4] ^= _int(key[-8:])
    return s[3].to_bytes(8, "big") + s[4].to_bytes(8, "big")


def _check(key: bytes, nonce: bytes, variant: str):
    if variant not in VARIANTS:
        raise ValueError(f"Unsupported ASCON variant: {variant}")
    if len(key) != VARIANTS[variant]:
        raise ValueError(f"{variant} needs a {VARIANTS[variant]}-byte key")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("ASCON nonce/IV must be 16 bytes")


def encrypt(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes,
            variant: str = "Ascon-128") -> tuple[bytes, bytes]:
    """Return ``(ciphertext, tag)`` for the given key, nonce (IV) and AD."""
    _check(key, nonce, variant)
    s = _initialise(key, nonce, ad)
    last = len(plaintext) % _RATE
    padded = plaintext + b"\x80" + bytes(_RATE - last - 1)
    out = bytearray()
    for i in range(0, len(padded) - _RATE, _RATE):
        s[0] ^= _int(padded[i:i + 8])
        out += s[0].to_bytes(8, "big")
        s = list(_permutation(*s, _ROUNDS_B))
    s[0] ^= _int(padded[-_RATE:])
    out += s[0].to_bytes(8, "big")[:last]
    return bytes(out), _finalise(s, key)


def decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes, tag: bytes,
            variant: str = "Ascon-128") -> bytes:
    """Return the plaintext, or raise :class:`AsconAuthError` if the tag fails."""
    _check(key, nonce, variant)
    s = _initialise(key, nonce, ad)
    last = len(ciphertext) % _RATE
    full = len(ciphertext) - last
    out = bytearray()
    for i in range(0, full, _RATE):
        c = _int(ciphertext[i:i + 8])
        out += (s[0] ^ c).to_bytes(8, "big")
        s[0] = c
        s = list(_permutation(*s, _ROUNDS_B))
    keystream = s[0].to_bytes(8, "big")
    tail = bytes(a ^ b for a, b in zip(ciphertext[full:], keystream))
    out += tail
    s[0] ^= _int(tail + b"\x80" + bytes(_RATE - last - 1))
    expected = _finalise(s, key)
    # constant-time comparison of the authentication tag
    diff = len(expected) ^ len(tag)
    for a, b in zip(expected, tag):
        diff |= a ^ b
    if diff:
        raise AsconAuthError("ASCON tag verification failed")
    return bytes(out)
