"""Regional Trusted Authority (RTA) of HF-SELAP.

An RTA runs the TA side of the protocol (steps A-2, A-3 and A-5) for

* its *own* entities - symmetric credentials kept exactly as in SELAP
  (M_VR1 = PID_V xor h(N_VR2 || k_TA) and M_UR1 = PID_U xor h(ID_U || C_U || k_TA))
  plus the certificateless verification key Q derived from the registered
  public key PK = (X, R);
* *foreign* entities registered at another RTA - credentials obtained from the
  Root/Federation TA over an ASCON-protected inter-TA link and cached
  (delegated authentication, used for cross-region service, load balancing
  and fail-over).

Handlers never change state before they have everything they need: if a
credential is missing they raise :class:`NeedRecord`, the caller fetches it
from the federation and simply calls the handler again.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import certificateless as cl
from .ascon import AsconAuthError
from .config import Config
from .entities import AuthError, refreshed_tid
from .messages import ProtocolMessage, uav_proof_input, vehicle_proof_input
from .primitives import (AeadParams, Clock, acting_as, encode_ts, fresh, h, open_,
                         rand, seal, xor)

if TYPE_CHECKING:                                    # pragma: no cover
    from .federation import RootTA


class NeedRecord(Exception):
    """The RTA lacks a credential record and must fetch it from the root."""

    def __init__(self, kind: str, key: bytes):
        super().__init__(f"{kind} record not available locally")
        self.kind, self.key = kind, key


class TAUnavailable(Exception):
    pass


@dataclass
class VehicleRecord:
    handle: bytes
    tid_o: bytes | None
    tid_c: bytes
    n_vr2: bytes
    home_ta: str
    pk: bytes                         # certificateless verification key Q_V
    version: int = 0
    m_vr1: bytes | None = None        # present at the home RTA only
    pid: bytes | None = None          # present in delegated copies only
    expires: float = math.inf
    verifier: object = field(default=None, repr=False, compare=False)


@dataclass
class UAVRecord:
    handle: bytes
    id_u: bytes
    c_u: bytes
    home_ta: str
    pk: bytes                         # certificateless verification key Q_U
    m_ur1: bytes | None = None
    pid: bytes | None = None
    expires: float = math.inf
    verifier: object = field(default=None, repr=False, compare=False)


@dataclass
class _Session:
    vrec: VehicleRecord
    urec: UAVRecord
    pid_v: bytes
    pid_u: bytes
    n_a1: bytes
    n_a2: bytes
    tid: bytes
    tid_new: bytes
    uav_id: bytes
    expires: float


@dataclass
class TAStats:
    msg1_ok: int = 0
    msg3_ok: int = 0
    rejected: int = 0
    delegated: int = 0
    fetches: int = 0


class RegionalTA:
    def __init__(self, name: str, region: str, cfg: Config, clock: Clock, root: "RootTA"):
        self.name, self.region, self.cfg, self.clock, self.root = name, region, cfg, clock, root
        self.ident = rand()                           # public identity ID_TA (128 bits)
        self.k_ta = rand(32)                          # private master key k_TA
        self.operational = True
        self.vehicles: dict[bytes, VehicleRecord] = {}     # TID -> record
        self.by_handle: dict[bytes, VehicleRecord] = {}    # handle -> record
        self.uavs: dict[bytes, UAVRecord] = {}             # ID_U -> record
        self.revoked: set[bytes] = set()
        self.revocation_version = 0
        self.seen_tags: dict[bytes, float] = {}
        self.pending: dict[int, _Session] = {}
        self.stats = TAStats()
        self.queue_len = 0                            # maintained by the simulator
        self.link = None                              # SecureLink, set by RootTA.add_ta
        self.outbox: list[VehicleRecord] = []         # TID updates awaiting sync

    # ------------------------------------------------------- registration
    def register_vehicle(self, pid_v: bytes, x_pub: bytes):
        """VR-2: issue TID_V and N_VR2, obtain the partial private key from the KGC,
        derive Q_V and store <TID_o, TID_c, N_VR2, M_VR1, Q_V>."""
        self._require_up()
        r_pub, d = self.root.issue_partial_key(self, pid_v, x_pub)
        with acting_as("ta"):
            tid = self._unique_tid()
            n_vr2 = rand()
            m_vr1 = xor(pid_v, h(n_vr2, self.k_ta))
            q = cl.verification_key(pid_v, x_pub, r_pub, self.root.kgc.public)
        rec = VehicleRecord(rand(), None, tid, n_vr2, self.name, q, 0, m_vr1=m_vr1)
        self._index_vehicle(rec)
        self.root.deposit_vehicle(self, rec, pid_v)
        return tid, n_vr2, r_pub, d, rec

    def check_uav_identity(self, id_u: bytes):
        """UR-1: reject identities already registered in the federation."""
        self._require_up()
        if self.root.uav_known(id_u):
            raise ValueError("UAV identity already registered in the federation")

    def register_uav(self, id_u: bytes, pid_u: bytes, x_pub: bytes):
        """UR-2: issue the credential C_U, obtain the partial private key, derive Q_U and
        store <ID_U, M_UR1, C_U, Q_U> with M_UR1 = PID_U xor h(ID_U || C_U || k_TA)."""
        self.check_uav_identity(id_u)
        r_pub, d = self.root.issue_partial_key(self, id_u, x_pub)
        with acting_as("ta"):
            c_u = rand()
            m_ur1 = xor(pid_u, h(id_u, c_u, self.k_ta))
            q = cl.verification_key(id_u, x_pub, r_pub, self.root.kgc.public)
        rec = UAVRecord(rand(), id_u, c_u, self.name, q, m_ur1=m_ur1)
        self.uavs[id_u] = rec
        self.root.deposit_uav(self, rec, pid_u)
        return c_u, r_pub, d, rec

    # ------------------------------------------------------------- AKA
    def handle_msg1(self, msg1: ProtocolMessage, sid: int) -> ProtocolMessage:
        """A-2 + A-3: authenticate the vehicle and build Msg2 for the UAV."""
        self._require_up()
        now = self.clock.now_ms()
        dt = self.cfg.protocol.delta_t_ms
        with acting_as("ta"):
            if not fresh(now, msg1.t, dt):
                self._reject("Msg1 timestamp outside Delta T")
            if self.cfg.protocol.replay_cache:
                self._expire(now)
                if msg1.tag in self.seen_tags:
                    self._reject("Msg1 replay detected")
            vrec = self._vehicle(msg1.tid, now)
            if vrec.handle in self.revoked:                 # RevCheck(ID_V)
                self._reject("vehicle credentials are revoked")
            pid_v = vrec.pid if vrec.pid is not None else xor(vrec.m_vr1, h(vrec.n_vr2, self.k_ta))
            m_a2 = h(pid_v, vrec.n_vr2, msg1.t)
            try:
                p = open_(AeadParams(m_a2, self.cfg.protocol.pq_mode), msg1.c, msg1.tag)
            except AsconAuthError:
                self._reject("Msg1 failed ASCON verification")
            n_a1, id_u, sigma_v = p[:16], p[16:32], p[32:96]
            # certificateless proof, checked before any foreign record is fetched
            if not cl.verify(self._verifier(vrec), sigma_v,
                             vehicle_proof_input(msg1.tid, n_a1, id_u, self.ident, msg1.t)):
                self._reject("vehicle certificateless signature is invalid")
            urec = self._uav(id_u, now)
            if urec.handle in self.revoked:                 # RevCheck(ID_U)
                self._reject("UAV credentials are revoked")
            pid_u = urec.pid if urec.pid is not None else xor(urec.m_ur1, h(id_u, urec.c_u, self.k_ta))
            n_a2 = rand()
            t2 = encode_ts(now)
            m_a3 = h(pid_v, n_a2, msg1.t)
            tid_new = refreshed_tid(msg1.tid, n_a2, msg1.t)
            if tid_new in self.vehicles or self.root.tid_known(tid_new):
                self._reject("identity refresh collision")  # probability ~2^-128
            m_a4 = h(pid_u, urec.c_u, t2)
            c, tag = seal(AeadParams(m_a4, self.cfg.protocol.pq_mode),
                          n_a1 + n_a2 + m_a3 + self.ident)
        # ---- commit (nothing above this line changed TA state)
        if self.cfg.protocol.replay_cache:
            self.seen_tags[msg1.tag] = now + dt
        self.pending[sid] = _Session(vrec, urec, pid_v, pid_u, n_a1, n_a2, msg1.tid, tid_new,
                                     id_u, now + 2 * dt)
        self.stats.msg1_ok += 1
        if vrec.home_ta != self.name or urec.home_ta != self.name:
            self.stats.delegated += 1
        return ProtocolMessage(2, c, tag, t2)

    def handle_msg3(self, msg3: ProtocolMessage, sid: int) -> ProtocolMessage:
        """A-5: authenticate the UAV, refresh TID_V and build Msg4."""
        self._require_up()
        now = self.clock.now_ms()
        st = self.pending.pop(sid, None)
        with acting_as("ta"):
            if st is None or now > st.expires:
                self._reject("no matching pending session for Msg3")
            if not fresh(now, msg3.t, self.cfg.protocol.delta_t_ms):
                self._reject("Msg3 timestamp outside Delta T")
            m_a8 = h(st.pid_u, st.n_a2, msg3.t)
            try:
                p = open_(AeadParams(m_a8, self.cfg.protocol.pq_mode), msg3.c, msg3.tag)
            except AsconAuthError:
                self._reject("Msg3 failed ASCON verification")
            n_a3, skv, sigma_u = p[:16], p[16:32], p[32:96]
            if not cl.verify(self._verifier(st.urec), sigma_u,
                             uav_proof_input(st.uav_id, st.n_a1, st.n_a2, n_a3, skv,
                                             self.ident, msg3.t)):
                self._reject("UAV certificateless signature is invalid")
            m_a9 = h(st.pid_u, n_a3, msg3.t)
            t4 = encode_ts(now)
            m_a10 = h(st.pid_v, st.tid, st.n_a1, t4)
            c, tag = seal(AeadParams(m_a10, self.cfg.protocol.pq_mode),
                          st.n_a2 + n_a3 + m_a9 + skv)
        # ---- commit: dual-record identity update + federation write-through
        rec = st.vrec
        self._unindex_vehicle(rec)
        if self.cfg.protocol.dual_record:
            rec.tid_o, rec.tid_c = st.tid, st.tid_new
        else:
            rec.tid_o, rec.tid_c = None, st.tid_new
        rec.version += 1
        self._index_vehicle(rec)
        if self.root.federated:
            self.outbox.append(rec)                # asynchronous write-through
        self.stats.msg3_ok += 1
        return ProtocolMessage(4, c, tag, t4)

    # ------------------------------------------------- federation hooks
    def flush_federation(self) -> int:
        """Send queued TID updates to the root (off the authentication path)."""
        sent = 0
        while self.outbox and self.operational:
            self.root.sync_tid(self, self.outbox.pop(0))
            sent += 1
        return sent

    def fetch(self, kind: str, key: bytes):
        """Obtain a delegated credential from the root and cache it."""
        self._require_up()
        self.stats.fetches += 1
        rec = self.root.fetch(self, kind, key)          # raises AuthError on refusal
        rec.expires = self.clock.now_ms() + self.cfg.federation.cache_ttl_ms
        if kind == "vehicle":
            self._index_vehicle(rec)
        else:
            self.uavs[rec.id_u] = rec

    def apply_sync(self, handle: bytes, tid_o: bytes | None, tid_c: bytes, version: int):
        """Apply a TID update pushed by the root (made at another RTA)."""
        rec = self.by_handle.get(handle)
        if rec is None or version <= rec.version:
            return
        self._unindex_vehicle(rec)
        rec.tid_o, rec.tid_c, rec.version = tid_o, tid_c, version
        self._index_vehicle(rec)

    def apply_revocation(self, handle: bytes, version: int):
        self.revoked.add(handle)
        self.revocation_version = max(self.revocation_version, version)
        rec = self.by_handle.pop(handle, None)
        if rec is not None:
            self._unindex_vehicle(rec)
        for id_u in [i for i, r in self.uavs.items() if r.handle == handle]:
            del self.uavs[id_u]

    def fail(self):
        self.operational = False
        self.pending.clear()

    def recover(self):
        self.operational = True
        self.root.resync(self)
        self.flush_federation()

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _verifier(rec):
        """Loaded verification key Q (cached on the record after first use)."""
        if rec.verifier is None:
            rec.verifier = cl.verifier(rec.pk)
        return rec.verifier

    def _vehicle(self, tid: bytes, now: float) -> VehicleRecord:
        rec = self.vehicles.get(tid)
        if rec is None or rec.expires < now:
            raise NeedRecord("vehicle", tid)
        return rec

    def _uav(self, id_u: bytes, now: float) -> UAVRecord:
        rec = self.uavs.get(id_u)
        if rec is None or rec.expires < now:
            raise NeedRecord("uav", id_u)
        return rec

    def _index_vehicle(self, rec: VehicleRecord):
        old = self.by_handle.get(rec.handle)
        if old is not None and old is not rec:
            self._unindex_vehicle(old)
        self.by_handle[rec.handle] = rec
        self.vehicles[rec.tid_c] = rec
        if rec.tid_o is not None and self.cfg.protocol.dual_record:
            self.vehicles[rec.tid_o] = rec

    def _unindex_vehicle(self, rec: VehicleRecord):
        for tid in (rec.tid_o, rec.tid_c):
            if tid is not None and self.vehicles.get(tid) is rec:
                del self.vehicles[tid]

    def _unique_tid(self) -> bytes:
        while True:
            tid = rand()
            if tid not in self.vehicles and not self.root.tid_known(tid):
                return tid

    def _expire(self, now: float):
        for t in [t for t, e in self.seen_tags.items() if e < now]:
            del self.seen_tags[t]
        for sid in [s for s, st in self.pending.items() if st.expires < now]:
            del self.pending[sid]

    def _require_up(self):
        if not self.operational:
            raise TAUnavailable(f"{self.name} is not operational")

    def _reject(self, reason: str):
        self.stats.rejected += 1
        raise AuthError(f"{self.name}: {reason}")

    @property
    def storage_bits_per_vehicle(self) -> int:
        # <TID_o, TID_c, N_VR2, M_VR1> as in SELAP + Q_V (compressed point)
        return 8 * (16 + 16 + 16 + 32 + cl.POINT_BYTES)

    @property
    def storage_bits_per_uav(self) -> int:
        # <ID_U, M_UR1, C_U> + Q_U
        return 8 * (16 + 32 + 16 + cl.POINT_BYTES)
