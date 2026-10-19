"""Pairing-free certificateless public-key authentication on NIST P-256.

HF-SELAP authenticates vehicles and UAVs with certificateless public-key
cryptography (CL-PKC) in the model of Al-Riyami and Paterson.  A Key
Generation Centre (KGC), run by the Root/Federation TA, holds the master
secret s and publishes P_pub = s*G.  It issues only a *partial* private key;
every entity adds a secret value of its own, so the KGC never knows the
complete private key and no certificates are needed.

    entity  : x_E random,  X_E = x_E*G                          (secret value)
    KGC     : r_E random,  R_E = r_E*G,
              h_E = H1(ID_E || X_E || R_E || P_pub) mod n,
              D_E = r_E + h_E*s mod n                            (partial key)
    entity  : accept only if D_E*G = R_E + h_E*P_pub,
              SK_E = x_E + D_E mod n                             (full key)
    public  : PK_E = (X_E, R_E); any verifier derives
              Q_E = X_E + R_E + h_E*P_pub   (= SK_E*G)

X_E is an input of h_E, so replacing an entity's public key (Type-I
adversary) changes h_E and the partial key no longer fits; the KGC (Type-II
adversary) never learns x_E and therefore cannot sign for the entity.

Authentication proofs are ECDSA signatures (P-256, SHA-256) under (SK_E, Q_E),
computed by the ``cryptography`` package (OpenSSL).  The curve arithmetic
needed only at enrolment (point addition and h*P_pub) is implemented below in
pure Python and cross-checked against OpenSSL by the unit tests.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

from .primitives import METER, h

# NIST P-256 (NIST SP 800-186; SEC 2 secp256r1)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

POINT_BYTES = 33        # SEC1 compressed encoding
SCALAR_BYTES = 32
SIG_BYTES = 64          # ECDSA (r || s)

_CURVE = ec.SECP256R1()
_ECDSA = ec.ECDSA(hashes.SHA256())


class EnrolmentError(Exception):
    """A partial private key or public key failed validation."""


# ------------------------------------------------------- curve arithmetic
# Points are affine tuples (x, y); None is the point at infinity.  Internally
# Jacobian coordinates (X, Y, Z) avoid one inversion per addition.
_INF = (0, 1, 0)


def _jdouble(X1, Y1, Z1):
    if Z1 == 0 or Y1 == 0:
        return _INF
    delta = Z1 * Z1 % P                                  # dbl-2001-b, a = -3
    gamma = Y1 * Y1 % P
    beta = X1 * gamma % P
    alpha = 3 * (X1 - delta) * (X1 + delta) % P
    X3 = (alpha * alpha - 8 * beta) % P
    Z3 = ((Y1 + Z1) * (Y1 + Z1) - gamma - delta) % P
    Y3 = (alpha * (4 * beta - X3) - 8 * gamma * gamma) % P
    return X3, Y3, Z3


def _jadd_affine(X1, Y1, Z1, x2, y2):
    """Jacobian + affine point (mixed addition)."""
    if Z1 == 0:
        return x2, y2, 1
    Z1Z1 = Z1 * Z1 % P
    U2 = x2 * Z1Z1 % P
    S2 = y2 * Z1 * Z1Z1 % P
    H = (U2 - X1) % P
    r = (S2 - Y1) % P
    if H == 0:
        return _jdouble(X1, Y1, Z1) if r == 0 else _INF
    HH = H * H % P
    HHH = H * HH % P
    V = X1 * HH % P
    X3 = (r * r - HHH - 2 * V) % P
    Y3 = (r * (V - X3) - Y1 * HHH) % P
    return X3, Y3, Z1 * H % P


def _to_affine(X, Y, Z):
    if Z == 0:
        return None
    zi = pow(Z, -1, P)
    zi2 = zi * zi % P
    return X * zi2 % P, Y * zi2 * zi % P


def on_curve(pt) -> bool:
    if pt is None:
        return False
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    return _to_affine(*_jadd_affine(p1[0], p1[1], 1, p2[0], p2[1]))


def point_neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def scalar_mult(k: int, pt):
    """Variable-base k*pt (left-to-right double-and-add; enrolment and tests only)."""
    k %= N
    if k == 0 or pt is None:
        return None
    acc = _INF
    for bit in bin(k)[2:]:
        acc = _jdouble(*acc)
        if bit == "1":
            acc = _jadd_affine(*acc, pt[0], pt[1])
    return _to_affine(*acc)


def base_mult(k: int):
    """k*G computed natively by OpenSSL."""
    k %= N
    if k == 0:
        return None
    nums = ec.derive_private_key(k, _CURVE).public_key().public_numbers()
    return nums.x, nums.y


class FixedBase:
    """4-bit fixed-window table for a point that is multiplied many times (P_pub)."""

    WINDOWS = 64

    def __init__(self, pt):
        self.point = pt
        rows = []
        base = (pt[0], pt[1], 1)
        for _ in range(self.WINDOWS):
            row = [None]
            acc = _INF
            for _ in range(15):
                acc = _jadd_affine(*acc, *_to_affine(*base))
                row.append(_to_affine(*acc))
            rows.append(row)
            for _ in range(4):
                base = _jdouble(*base)
        self.rows = rows

    def mult(self, k: int):
        k %= N
        acc = _INF
        for row in self.rows:
            d = k & 15
            if d:
                acc = _jadd_affine(*acc, *row[d])
            k >>= 4
        return _to_affine(*acc)


# ---------------------------------------------------------------- encoding
def encode_point(pt) -> bytes:
    if pt is None:
        raise ValueError("cannot encode the point at infinity")
    return bytes([2 | (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def decode_point(data: bytes):
    if len(data) != POINT_BYTES or data[0] not in (2, 3):
        raise EnrolmentError("malformed point encoding")
    x = int.from_bytes(data[1:], "big")
    if x >= P:
        raise EnrolmentError("point coordinate out of range")
    rhs = (x * x * x + A * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)                       # P = 3 (mod 4)
    if y * y % P != rhs:
        raise EnrolmentError("point is not on P-256")
    if (y & 1) != (data[0] & 1):
        y = P - y
    return x, y


def random_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


# ------------------------------------------------------------ KGC and keys
class KGCPublic:
    """Public parameters every party uses: P_pub (with a precomputed table)."""

    def __init__(self, p_pub):
        self.p_pub = p_pub
        self.encoded = encode_point(p_pub)
        self._table: FixedBase | None = None

    def mult(self, k: int):
        if self._table is None:
            self._table = FixedBase(self.p_pub)
        return self._table.mult(k)


class KGC:
    """Key Generation Centre: issues partial private keys D_E (hosted by the Root TA)."""

    def __init__(self):
        self._s = random_scalar()
        self.public = KGCPublic(base_mult(self._s))

    def extract_partial_key(self, ident: bytes, x_pub: bytes) -> tuple[bytes, int]:
        """Return (R_E, D_E) for identity ``ident`` and the entity's public value X_E."""
        decode_point(x_pub)                              # reject invalid X_E
        r = random_scalar()
        r_pub = encode_point(base_mult(r))
        d = (r + h1(ident, x_pub, r_pub, self.public) * self._s) % N
        return r_pub, d


def h1(ident: bytes, x_pub: bytes, r_pub: bytes, kgc: KGCPublic) -> int:
    """h_E = H1(ID_E || X_E || R_E || P_pub) mod n."""
    return int.from_bytes(h(b"HF-SELAP-CL", ident, x_pub, r_pub, kgc.encoded), "big") % N


def new_secret_value() -> tuple[int, bytes]:
    """Entity side: secret value x_E and public value X_E = x_E*G."""
    x = random_scalar()
    return x, encode_point(base_mult(x))


def partial_key_valid(ident: bytes, x_pub: bytes, r_pub: bytes, d: int,
                      kgc: KGCPublic) -> bool:
    """Entity side: D_E*G == R_E + h_E*P_pub."""
    if not 0 < d < N:
        return False
    try:
        r_pt = decode_point(r_pub)
    except EnrolmentError:
        return False
    rhs = point_add(r_pt, kgc.mult(h1(ident, x_pub, r_pub, kgc)))
    return base_mult(d) == rhs


def full_private_key(ident: bytes, x: int, x_pub: bytes, r_pub: bytes, d: int,
                     kgc: KGCPublic) -> bytes:
    """SK_E = x_E + D_E mod n, after validating the partial private key."""
    if not partial_key_valid(ident, x_pub, r_pub, d, kgc):
        raise EnrolmentError("partial private key failed validation")
    sk = (x + d) % N
    if sk == 0:
        raise EnrolmentError("degenerate private key")
    return sk.to_bytes(SCALAR_BYTES, "big")


def verification_key(ident: bytes, x_pub: bytes, r_pub: bytes, kgc: KGCPublic) -> bytes:
    """Verifier side: Q_E = X_E + R_E + h_E*P_pub, from the registered PK_E = (X_E, R_E)."""
    q = point_add(point_add(decode_point(x_pub), decode_point(r_pub)),
                  kgc.mult(h1(ident, x_pub, r_pub, kgc)))
    if q is None:
        raise EnrolmentError("public key derives the point at infinity")
    return encode_point(q)


# -------------------------------------------------------------- signatures
def signer(sk: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(sk, "big"), _CURVE)


def verifier(q: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, q)


def sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """sigma = Sign(SK_E, M) as a fixed 64-byte (r || s) string."""
    METER.add("sign")
    r, s = decode_dss_signature(key.sign(message, _ECDSA))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(key: ec.EllipticCurvePublicKey, sigma: bytes, message: bytes) -> bool:
    """Verify(ID, PK, sigma, M) = 1 ?"""
    METER.add("verify")
    if len(sigma) != SIG_BYTES:
        return False
    r, s = int.from_bytes(sigma[:32], "big"), int.from_bytes(sigma[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    try:
        key.verify(encode_dss_signature(r, s), message, _ECDSA)
        return True
    except InvalidSignature:
        return False
