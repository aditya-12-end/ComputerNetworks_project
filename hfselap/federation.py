"""Root / Federation Trusted Authority and the secure inter-TA links.

Responsibilities (Case Study 2, "Federation / Root TA" block):

* provisions one ASCON-128 link key per Regional TA (authenticated, replay-
  protected inter-TA channel, :class:`SecureLink`);
* hosts the Key Generation Centre (KGC) of the certificateless scheme and
  issues partial private keys D_E during enrolment;
* keeps the inter-TA trust matrix (Trust_new = alpha Trust_old + (1 - alpha) S)
  and a reliability score per RTA;
* escrows every entity's credential record (sealed under the root key) so
  that a trusted RTA can serve a foreign entity (cross-region service, load
  sharing, fail-over) without the entity re-registering;
* keeps the federated TID directory consistent (write-through TID sync);
* owns the revocation registry and pushes revocations to every RTA.

All inter-TA traffic is real serialised bytes; :attr:`RootTA.traffic`
records bits per message type for the communication-overhead results.
"""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import ascon
from . import certificateless as cl
from .ascon import AsconAuthError
from .config import Config
from .entities import AuthError
from .messages import (DEPOSIT_UAV, DEPOSIT_VEHICLE, FETCH_UAV, FETCH_VEHICLE, HEARTBEAT,
                       INTER_HEADER, NACK, PARTIAL_KEY, PARTIAL_KEY_REQUEST, RECORD_UAV,
                       RECORD_VEHICLE, REVOKE, TID_SYNC, TID_SYNC_BODY, UAV_RECORD,
                       VEHICLE_RECORD)
from .primitives import METER, Clock, acting_as, encode_ts, fresh, rand

if TYPE_CHECKING:                                    # pragma: no cover
    from .ta import RegionalTA, UAVRecord, VehicleRecord

MSG_NAMES = {FETCH_VEHICLE: "fetch_vehicle", FETCH_UAV: "fetch_uav",
             RECORD_VEHICLE: "record_vehicle", RECORD_UAV: "record_uav",
             TID_SYNC: "tid_sync", REVOKE: "revoke", HEARTBEAT: "heartbeat",
             DEPOSIT_VEHICLE: "deposit_vehicle", DEPOSIT_UAV: "deposit_uav", NACK: "nack",
             PARTIAL_KEY_REQUEST: "partial_key_request", PARTIAL_KEY: "partial_key"}
_ZERO16 = bytes(16)


class LinkError(Exception):
    pass


class SecureLink:
    """ASCON-128 protected channel between one RTA and the root.

    Wire format: header(13 B) | nonce(16 B) | ciphertext | tag(16 B), where the
    header (sender, receiver, type, sequence number, timestamp) is the AEAD
    associated data.  Sequence numbers must strictly increase per sender.
    """

    def __init__(self, key: bytes, ta_id: int, clock: Clock, delta_t_ms: float):
        self.key, self.ta_id, self.clock, self.delta_t = key, ta_id, clock, delta_t_ms
        self._seq = {0: 0, ta_id: 0}
        self._last_seen = {0: -1, ta_id: -1}

    def seal(self, sender: int, mtype: int, body: bytes) -> bytes:
        receiver = self.ta_id if sender == 0 else 0
        self._seq[sender] += 1
        header = INTER_HEADER.pack(sender, receiver, mtype, self._seq[sender],
                                   encode_ts(self.clock.now_ms()))
        nonce = rand()
        METER.add("ascon")
        c, tag = ascon.encrypt(self.key, nonce, header, body)
        return header + nonce + c + tag

    def open(self, raw: bytes, expected_receiver: int) -> tuple[int, bytes]:
        hl = INTER_HEADER.size
        if len(raw) < hl + 32:
            raise LinkError("inter-TA message too short")
        header, nonce, c, tag = raw[:hl], raw[hl:hl + 16], raw[hl + 16:-16], raw[-16:]
        sender, receiver, mtype, seq, ts = INTER_HEADER.unpack(header)
        if receiver != expected_receiver or sender not in self._last_seen:
            raise LinkError("inter-TA message mis-addressed")
        METER.add("ascon")
        try:
            body = ascon.decrypt(self.key, nonce, header, c, tag)
        except AsconAuthError:
            raise LinkError("inter-TA message failed authentication") from None
        if seq <= self._last_seen[sender]:
            raise LinkError("inter-TA replay (sequence number reused)")
        if not fresh(self.clock.now_ms(), ts, self.delta_t):
            raise LinkError("inter-TA message is stale")
        self._last_seen[sender] = seq
        return mtype, body


@dataclass
class Revocation:
    version: int
    reason: str
    time_ms: float


class RootTA:
    def __init__(self, cfg: Config, clock: Clock):
        self.cfg, self.clock = cfg, clock
        self.k_root = rand(16)
        self.kgc = cl.KGC()                    # master secret s, P_pub = s*G
        self.tas: dict[str, "RegionalTA"] = {}
        self.ta_ids: dict[str, int] = {}
        self.trust: dict[tuple[str, str], float] = {}
        self.reliability: dict[str, float] = {}
        self.escrow: dict[bytes, tuple[bytes, bytes, bytes]] = {}   # handle -> (nonce, c, tag)
        self.kind: dict[bytes, str] = {}
        self.home: dict[bytes, str] = {}
        self.v_tids: dict[bytes, tuple[bytes | None, bytes]] = {}
        self.tid_dir: dict[bytes, bytes] = {}
        self.uav_dir: dict[bytes, bytes] = {}
        self.versions: dict[bytes, int] = {}
        self.subscribers: dict[bytes, set[str]] = defaultdict(set)
        self.revoked: dict[bytes, Revocation] = {}
        self.revocation_version = 0
        self.dirty: dict[str, set[bytes]] = defaultdict(set)
        self.traffic: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # name -> [count, bits]
        self.audit_log: list[dict] = []

    # --------------------------------------------------------- topology
    def add_ta(self, ta: "RegionalTA"):
        if ta.name in self.tas:
            raise ValueError("duplicate TA name")
        ta_id = len(self.tas) + 1
        self.tas[ta.name] = ta
        self.ta_ids[ta.name] = ta_id
        self.reliability[ta.name] = 1.0
        ta.link = SecureLink(rand(16), ta_id, self.clock, self.cfg.protocol.delta_t_ms)
        self._audit("ta_added", ta=ta.name, region=ta.region)

    def set_trust(self, a: str, b: str, value: float, symmetric: bool = True):
        if not 0 <= value <= 1:
            raise ValueError("trust must lie in [0, 1]")
        if a == b:
            raise ValueError("trust is defined between distinct TAs")
        self.trust[(a, b)] = value
        if symmetric:
            self.trust[(b, a)] = value
        self._audit("trust_set", a=a, b=b, value=value)

    def trusted(self, home: str, serving: str) -> bool:
        if home == serving:
            return True
        return self.trust.get((home, serving), 0.0) >= self.cfg.federation.trust_threshold

    def observe(self, ta_name: str, ok: bool, homes=()):
        """Record one service outcome S of ``ta_name``.

        Reliability R_i (used by the load balancer) and the trust of every home
        RTA in ``homes`` towards the serving RTA follow the same update
        X_new = alpha * X_old + (1 - alpha) * S, with alpha = trust_history_weight.
        """
        a = self.cfg.federation.trust_history_weight
        sample = 1.0 if ok else 0.0
        self.reliability[ta_name] = a * self.reliability[ta_name] + (1 - a) * sample
        for home in homes:
            key = (home, ta_name)
            if home != ta_name and key in self.trust:
                self.trust[key] = a * self.trust[key] + (1 - a) * sample

    @property
    def federated(self) -> bool:
        """A single-TA deployment is plain SELAP: no inter-TA synchronisation."""
        return len(self.tas) > 1

    def uav_known(self, id_u: bytes) -> bool:
        handle = self.uav_dir.get(id_u)
        return handle is not None and handle not in self.revoked

    def tid_known(self, tid: bytes) -> bool:
        return tid in self.tid_dir

    # ---------------------------------------------------- link plumbing
    def _send_to_root(self, ta: "RegionalTA", mtype: int, body: bytes) -> tuple[int, bytes]:
        with acting_as("ta"):
            raw = ta.link.seal(self.ta_ids[ta.name], mtype, body)
        self._count(mtype, raw)
        with acting_as("root"):
            try:
                return ta.link.open(raw, expected_receiver=0)
            except LinkError as exc:
                raise AuthError(f"root rejected inter-TA message: {exc}") from None

    def _send_to_ta(self, ta: "RegionalTA", mtype: int, body: bytes) -> tuple[int, bytes]:
        with acting_as("root"):
            raw = ta.link.seal(0, mtype, body)
        self._count(mtype, raw)
        with acting_as("ta"):
            try:
                return ta.link.open(raw, expected_receiver=self.ta_ids[ta.name])
            except LinkError as exc:
                raise AuthError(f"{ta.name} rejected inter-TA message: {exc}") from None

    def _count(self, mtype: int, raw: bytes):
        entry = self.traffic[MSG_NAMES[mtype]]
        entry[0] += 1
        entry[1] += 8 * len(raw)

    def heartbeat_bits(self) -> int:
        ta = next(iter(self.tas.values()))
        return 8 * len(ta.link.seal(self.ta_ids[ta.name], HEARTBEAT, b""))

    def _escrow_put(self, handle: bytes, record: bytes):
        nonce = rand()
        with acting_as("root"):
            METER.add("ascon")
            c, tag = ascon.encrypt(self.k_root, nonce, handle, record)
        self.escrow[handle] = (nonce, c, tag)

    def _escrow_get(self, handle: bytes) -> bytes:
        nonce, c, tag = self.escrow[handle]
        with acting_as("root"):
            METER.add("ascon")
            return ascon.decrypt(self.k_root, nonce, handle, c, tag)

    def escrow_bits(self, handle: bytes) -> int:
        nonce, c, tag = self.escrow[handle]
        return 8 * (len(nonce) + len(c) + len(tag))

    # -------------------------------------------------- key generation
    def issue_partial_key(self, ta: "RegionalTA", ident: bytes, x_pub: bytes) -> tuple[bytes, int]:
        """KGC: partial private key (R_E, D_E) for an entity enrolling at ``ta``.

        The request carries ID_E and X_E; the answer carries R_E and D_E.  Both
        travel over the ASCON inter-TA link, and the RTA hands D_E to the entity
        over the secure enrolment channel.
        """
        _, body = self._send_to_root(ta, PARTIAL_KEY_REQUEST,
                                     bytes([len(ident)]) + ident + x_pub)
        ident, x_pub = body[1:1 + body[0]], body[1 + body[0]:]
        with acting_as("root"):
            r_pub, d = self.kgc.extract_partial_key(ident, x_pub)
        _, body = self._send_to_ta(ta, PARTIAL_KEY, r_pub + d.to_bytes(cl.SCALAR_BYTES, "big"))
        self._audit("partial_key_issued", ta=ta.name)
        return body[:cl.POINT_BYTES], int.from_bytes(body[cl.POINT_BYTES:], "big")

    # -------------------------------------------------------- deposits
    def deposit_vehicle(self, ta: "RegionalTA", rec: "VehicleRecord", pid: bytes):
        body = VEHICLE_RECORD.pack(rec.handle, rec.tid_o or _ZERO16, rec.tid_c, rec.n_vr2, pid,
                                   rec.pk, self.ta_ids[ta.name], rec.version)
        _, body = self._send_to_root(ta, DEPOSIT_VEHICLE, body)
        handle = body[:16]
        self._escrow_put(handle, body)
        self.kind[handle], self.home[handle], self.versions[handle] = "vehicle", ta.name, rec.version
        self._set_tids(handle, rec.tid_o, rec.tid_c)
        self._audit("vehicle_deposited", ta=ta.name)

    def deposit_uav(self, ta: "RegionalTA", rec: "UAVRecord", pid: bytes):
        body = UAV_RECORD.pack(rec.handle, rec.id_u, pid, rec.c_u, rec.pk, self.ta_ids[ta.name])
        _, body = self._send_to_root(ta, DEPOSIT_UAV, body)
        handle, id_u = body[:16], body[16:32]
        self._escrow_put(handle, body)
        self.kind[handle], self.home[handle] = "uav", ta.name
        self.uav_dir[id_u] = handle
        self._audit("uav_deposited", ta=ta.name)

    # ------------------------------------------------ delegated fetch
    def fetch(self, ta: "RegionalTA", kind: str, key: bytes):
        from .ta import UAVRecord, VehicleRecord
        mtype = FETCH_VEHICLE if kind == "vehicle" else FETCH_UAV
        _, key = self._send_to_root(ta, mtype, key)
        handle = (self.tid_dir if kind == "vehicle" else self.uav_dir).get(key)
        reason = None
        if handle is None:
            reason = f"unknown {kind}"
        elif handle in self.revoked:
            reason = f"{kind} credentials are revoked"
        elif not self.trusted(self.home[handle], ta.name):
            reason = f"{ta.name} is not trusted by {self.home[handle]}"
        elif kind == "vehicle" and key not in self.v_tids[handle]:
            reason = "stale temporary identity"
        if reason is not None:
            self._send_to_ta(ta, NACK, reason.encode())
            self._audit("fetch_refused", ta=ta.name, reason=reason)
            raise AuthError(f"federation refused delegation: {reason}")
        record = self._escrow_get(handle)
        if kind == "vehicle":
            _, body = self._send_to_ta(ta, RECORD_VEHICLE, record)
            h_, tid_o, tid_c, n_vr2, pid, q, home_id, ver = VEHICLE_RECORD.unpack(body)
            rec = VehicleRecord(h_, None if tid_o == _ZERO16 else tid_o, tid_c, n_vr2,
                                self.home[h_], q, ver, pid=pid)
        else:
            _, body = self._send_to_ta(ta, RECORD_UAV, record)
            h_, id_u, pid, c_u, q, home_id = UAV_RECORD.unpack(body)
            rec = UAVRecord(h_, id_u, c_u, self.home[h_], q, pid=pid)
        if self.home[handle] != ta.name:
            self.subscribers[handle].add(ta.name)
        self._audit("fetch_granted", ta=ta.name, kind=kind)
        return rec

    # ------------------------------------------------------ TID sync
    def sync_tid(self, ta: "RegionalTA", rec: "VehicleRecord"):
        body = TID_SYNC_BODY.pack(rec.handle, rec.tid_o or _ZERO16, rec.tid_c, rec.version)
        _, body = self._send_to_root(ta, TID_SYNC, body)
        handle, tid_o, tid_c, version = TID_SYNC_BODY.unpack(body)
        tid_o = None if tid_o == _ZERO16 else tid_o
        if tid_o is not None and tid_o not in self.v_tids.get(handle, ()):
            self._audit("stale_sync_ignored", ta=ta.name)  # update not based on current state
            return
        version = max(version, self.versions.get(handle, 0) + 1)
        self.versions[handle] = version
        stored = bytearray(self._escrow_get(handle))
        stored[16:48] = (tid_o or _ZERO16) + tid_c
        stored[-4:] = struct.pack(">I", version)
        self._escrow_put(handle, bytes(stored))
        self._set_tids(handle, tid_o, tid_c)
        targets = ({self.home[handle]} | self.subscribers[handle]) - {ta.name}
        for name in targets:
            self._push_sync(self.tas[name], handle)

    def _push_sync(self, target: "RegionalTA", handle: bytes):
        if not target.operational:
            self.dirty[target.name].add(handle)
            return
        tid_o, tid_c = self.v_tids[handle]
        body = TID_SYNC_BODY.pack(handle, tid_o or _ZERO16, tid_c, self.versions[handle])
        _, body = self._send_to_ta(target, TID_SYNC, body)
        h_, o, c, v = TID_SYNC_BODY.unpack(body)
        target.apply_sync(h_, None if o == _ZERO16 else o, c, v)

    def _set_tids(self, handle: bytes, tid_o: bytes | None, tid_c: bytes):
        for old in self.v_tids.get(handle, (None, None)):
            if old is not None and self.tid_dir.get(old) == handle:
                del self.tid_dir[old]
        if not self.cfg.protocol.dual_record:
            tid_o = None
        self.v_tids[handle] = (tid_o, tid_c)
        self.tid_dir[tid_c] = handle
        if tid_o is not None:
            self.tid_dir[tid_o] = handle

    # ---------------------------------------------------- revocation
    def revoke(self, handle: bytes, reason: str) -> int:
        """Revoke an entity federation-wide; returns the number of RTAs notified."""
        if handle not in self.kind:
            raise KeyError("unknown entity handle")
        if handle in self.revoked:
            return 0
        self.revocation_version += 1
        self.revoked[handle] = Revocation(self.revocation_version, reason, self.clock.now_ms())
        notified = 0
        for ta in self.tas.values():
            if ta.operational:
                self._push_revocation(ta, handle)
                notified += 1
        self._audit("entity_revoked", kind=self.kind[handle], reason=reason)
        return notified

    def _push_revocation(self, ta: "RegionalTA", handle: bytes):
        version = self.revoked[handle].version
        _, body = self._send_to_ta(ta, REVOKE, handle + struct.pack(">I", version))
        ta.apply_revocation(body[:16], struct.unpack(">I", body[16:20])[0])

    def resync(self, ta: "RegionalTA"):
        """Bring a recovered RTA up to date (missed revocations and TID updates)."""
        for handle, rev in sorted(self.revoked.items(), key=lambda kv: kv[1].version):
            if rev.version > ta.revocation_version:
                self._push_revocation(ta, handle)
        for handle in self.dirty.pop(ta.name, set()):
            self._push_sync(ta, handle)
        self._audit("ta_resynchronised", ta=ta.name)

    def _audit(self, event: str, **fields):
        self.audit_log.append({"t_ms": self.clock.now_ms(), "event": event, **fields})
