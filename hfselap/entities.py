"""Vehicles (OBU + smart card) and UAVs (onboard processor + smart card + PUF).

Step labels (VR-3, UR-4, VL-2, UL-2, A-1, A-4, A-6) follow the SELAP base
protocol; HF-SELAP keeps these computations unchanged so that the end
devices pay no extra cost for the federated trust layer.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .ascon import AsconAuthError
from .config import ProtocolConfig
from .messages import ProtocolMessage
from .primitives import (AeadParams, Clock, HASH, NONCE, acting_as, encode_ts,
                         fresh, h, key_verifier, open_, rand, seal, xor)
from .puf import ArbiterPUF, FuzzyExtractor


class LoginError(Exception):
    pass


class AuthError(Exception):
    """Raised by any party that rejects a protocol message."""


# ----------------------------------------------------------------- vehicles
@dataclass
class VehicleSmartCard:
    tid: bytes
    m_vr2: bytes
    c_t: bytes
    tag_t: bytes
    max_attempts: int = 5
    failed_attempts: int = 0

    @classmethod
    def issue(cls, id_v: bytes, pw: bytes, tid: bytes, n_vr1: bytes, n_vr2: bytes,
              pq: bool = False, max_attempts: int = 5) -> "VehicleSmartCard":
        """VR-3: bind the password to the TA-issued credentials."""
        n_vr3 = rand(HASH)
        m_vr2 = xor(n_vr3, h(id_v, pw))
        m_vr3 = h(id_v, pw, n_vr3)
        c_t, tag_t = seal(AeadParams(m_vr3, pq), n_vr1 + n_vr2)
        return cls(tid, m_vr2, c_t, tag_t, max_attempts)

    def login(self, id_v: bytes, pw: bytes, pq: bool = False) -> tuple[bytes, bytes]:
        """VL-2: return (N_VR1, N_VR2) or raise LoginError."""
        if self.failed_attempts >= self.max_attempts:
            raise LoginError("smart card locked after repeated wrong passwords")
        n_vr3 = xor(self.m_vr2, h(id_v, pw))
        m_v1 = h(id_v, pw, n_vr3)
        try:
            p_t = open_(AeadParams(m_v1, pq), self.c_t, self.tag_t)
        except AsconAuthError:
            self.failed_attempts += 1
            raise LoginError("wrong identity or password") from None
        self.failed_attempts = 0
        return p_t[:NONCE], p_t[NONCE:]

    @property
    def storage_bits(self) -> int:
        return 8 * (len(self.tid) + len(self.m_vr2) + len(self.c_t) + len(self.tag_t))


@dataclass
class _VehiclePending:
    n_a1: bytes
    t1: bytes
    tid: bytes
    pid: bytes


class Vehicle:
    def __init__(self, id_v: bytes, pw: bytes, card: VehicleSmartCard, clock: Clock,
                 cfg: ProtocolConfig, name: str, region: str):
        self.id_v, self.pw, self.card, self.clock, self.cfg = id_v, pw, card, clock, cfg
        self.name, self.region, self.home_region = name, region, region
        self.home_ta: str | None = None
        self.handle: bytes | None = None
        self._creds: tuple[bytes, bytes] | None = None
        self._pending: _VehiclePending | None = None
        self.session_key: bytes | None = None

    def login(self):
        with acting_as("vehicle"):
            self._creds = self.card.login(self.id_v, self.pw, self.cfg.pq_mode)

    def start(self, id_u: bytes) -> ProtocolMessage:
        """A-1: build Msg1 = {TID_V, C_A1, Tag_A1, T1}."""
        if self._creds is None:
            self.login()
        n_vr1, n_vr2 = self._creds
        with acting_as("vehicle"):
            pid = h(self.id_v, n_vr1)
            n_a1 = rand()
            t1 = encode_ts(self.clock.now_ms())
            m_a1 = h(pid, n_vr2, t1)
            c, tag = seal(AeadParams(m_a1, self.cfg.pq_mode), n_a1 + id_u)
        self._pending = _VehiclePending(n_a1, t1, self.card.tid, pid)
        return ProtocolMessage(1, c, tag, t1, self.card.tid)

    def finish(self, msg4: ProtocolMessage) -> bytes:
        """A-6: verify Msg4, derive SK_VU, check SKV and adopt TID_new."""
        pend = self._pending
        if pend is None:
            raise AuthError("no authentication in progress")
        pid = pend.pid
        with acting_as("vehicle"):
            if not fresh(self.clock.now_ms(), msg4.t, self.cfg.delta_t_ms):
                raise AuthError("Msg4 timestamp outside Delta T")
            m_a11 = h(pid, pend.tid, pend.n_a1, msg4.t)
            try:
                p = open_(AeadParams(m_a11, self.cfg.pq_mode), msg4.c, msg4.tag)
            except AsconAuthError:
                raise AuthError("Msg4 failed ASCON verification") from None
            n_a2, tid_new, m_a9, skv = p[:16], p[16:32], p[32:64], p[64:80]
            sk = h(pend.n_a1, h(pid, n_a2, pend.t1), m_a9)
            if key_verifier(sk) != skv:
                raise AuthError("session-key verifier mismatch")
        self.card.tid = tid_new
        self._pending = None
        self.session_key = sk
        return sk


# --------------------------------------------------------------------- UAVs
@dataclass
class UAVSmartCard:
    m_ur2: bytes
    c_k: bytes
    tag_k: bytes
    max_attempts: int = 5
    failed_attempts: int = 0

    @classmethod
    def issue(cls, id_u: bytes, pw: bytes, c_u: bytes, helper: bytes,
              pq: bool = False, max_attempts: int = 5) -> "UAVSmartCard":
        """UR-4: protect (C_U, H_U) under the UAV operator's password."""
        n_ur1 = rand(HASH)
        m_ur2 = xor(n_ur1, h(id_u, pw))
        m_ur3 = h(id_u, pw, n_ur1)
        c_k, tag_k = seal(AeadParams(m_ur3, pq), c_u + helper)
        return cls(m_ur2, c_k, tag_k, max_attempts)

    def login(self, id_u: bytes, pw: bytes, pq: bool = False) -> tuple[bytes, bytes]:
        """UL-2: return (C_U, H_U) or raise LoginError."""
        if self.failed_attempts >= self.max_attempts:
            raise LoginError("smart card locked after repeated wrong passwords")
        n_ur1 = xor(self.m_ur2, h(id_u, pw))
        m_u1 = h(id_u, pw, n_ur1)
        try:
            p = open_(AeadParams(m_u1, pq), self.c_k, self.tag_k)
        except AsconAuthError:
            self.failed_attempts += 1
            raise LoginError("wrong identity or password") from None
        self.failed_attempts = 0
        return p[:NONCE], p[NONCE:]

    @property
    def storage_bits(self) -> int:
        return 8 * (len(self.m_ur2) + len(self.c_k) + len(self.tag_k))


class UAV:
    def __init__(self, id_u: bytes, pw: bytes, card: UAVSmartCard, puf: ArbiterPUF,
                 fe: FuzzyExtractor, clock: Clock, cfg: ProtocolConfig, name: str,
                 region: str):
        self.id_u, self.pw, self.card, self.puf, self.fe = id_u, pw, card, puf, fe
        self.clock, self.cfg, self.name, self.region = clock, cfg, name, region
        self.home_ta: str | None = None
        self.handle: bytes | None = None
        self._creds: tuple[bytes, bytes] | None = None
        self.session_keys: dict[int, bytes] = {}
        self.seen_tags: dict[bytes, float] = {}
        self.puf_reads_last = 0

    def login(self):
        with acting_as("uav"):
            self._creds = self.card.login(self.id_u, self.pw, self.cfg.pq_mode)

    def respond(self, msg2: ProtocolMessage, sid: int) -> ProtocolMessage:
        """A-4: authenticate TA via Msg2, derive SK_UV and return Msg3."""
        if self._creds is None:
            self.login()
        c_u, helper = self._creds
        now = self.clock.now_ms()
        with acting_as("uav"):
            if not fresh(now, msg2.t, self.cfg.delta_t_ms):
                raise AuthError("Msg2 timestamp outside Delta T")
            if self.cfg.replay_cache:
                self._expire(now)
                if msg2.tag in self.seen_tags:
                    raise AuthError("Msg2 replay detected")
            # PUF read + fuzzy-extractor reproduction; re-measure if the
            # noisy response could not be corrected (tag check fails).
            payload = None
            self.puf_reads_last = 0
            for _ in range(self.cfg.puf_max_reads):
                self.puf_reads_last += 1
                k_u = self.fe.rep_(self.puf.evaluate(c_u), helper)
                pid = h(self.id_u, k_u)
                m_a5 = h(pid, c_u, msg2.t)
                try:
                    payload = open_(AeadParams(m_a5, self.cfg.pq_mode), msg2.c, msg2.tag)
                    break
                except AsconAuthError:
                    continue
            if payload is None:
                raise AuthError("Msg2 failed ASCON verification (TA not authentic "
                                "or PUF response not reproducible)")
            n_a1, n_a2, m_a3 = payload[:16], payload[16:32], payload[32:64]
            n_a3 = rand()
            t3 = encode_ts(now)
            m_a6 = h(pid, n_a3, t3)
            sk = h(n_a1, m_a3, m_a6)
            skv = key_verifier(sk)
            m_a7 = h(pid, n_a2, t3)
            c, tag = seal(AeadParams(m_a7, self.cfg.pq_mode), n_a3 + skv)
        if self.cfg.replay_cache:
            self.seen_tags[msg2.tag] = now + self.cfg.delta_t_ms
        self.session_keys[sid] = sk
        return ProtocolMessage(3, c, tag, t3)

    def _expire(self, now: float):
        if len(self.seen_tags) > 512:
            self.seen_tags = {t: e for t, e in self.seen_tags.items() if e >= now}
        else:
            for t in [t for t, e in self.seen_tags.items() if e < now]:
                del self.seen_tags[t]
