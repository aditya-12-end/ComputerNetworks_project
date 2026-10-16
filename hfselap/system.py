"""HF-SELAP system facade: builds the federation and runs complete protocol flows.

``HFSELAP.authenticate`` executes one full SELAP run (Msg1..Msg4) through a
:class:`Channel`.  The channel can be given an adversary ``tap`` that sees
every serialised message and may drop, modify, replace or record it - this
is how the attack experiments are performed.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Callable

import numpy as np

from .config import Config
from .entities import (AuthError, LoginError, UAV, UAVSmartCard, Vehicle,
                       VehicleSmartCard)
from .federation import RootTA
from .loadbalancer import HealthMonitor, LoadBalancer, NoTAAvailable
from .messages import MalformedMessage, ProtocolMessage
from .primitives import Clock, SimClock, acting_as, h, rand
from .puf import ArbiterPUF
from .ta import NeedRecord, RegionalTA, TAUnavailable

Tap = Callable[[str, bytes], "bytes | None"]


@dataclass
class AuthResult:
    ok: bool
    reason: str = ""
    ta: str = ""
    sid: int = 0
    sk_vehicle: bytes | None = None
    sk_uav: bytes | None = None
    bits: dict = field(default_factory=dict)
    transcript: dict = field(default_factory=dict)
    delegated: bool = False
    fetches: int = 0


class HFSELAP:
    def __init__(self, cfg: Config | None = None, clock: Clock | None = None,
                 seed: int | None = None, monitor_mode: str = "oracle"):
        self.cfg = cfg or Config()
        self.clock = clock or SimClock()
        self.rng = np.random.default_rng(seed)
        self.root = RootTA(self.cfg, self.clock)
        self.monitor = HealthMonitor(self.cfg, self.root.tas, monitor_mode)
        self.lb = LoadBalancer(self.cfg, self.root, self.monitor)
        self.vehicles: dict[str, Vehicle] = {}
        self.uavs: dict[str, UAV] = {}

    # ---------------------------------------------------------- topology
    def add_ta(self, name: str, region: str) -> RegionalTA:
        ta = RegionalTA(name, region, self.cfg, self.clock, self.root,
                        np.random.default_rng(self.rng.integers(2**63)))
        self.root.add_ta(ta)
        self.monitor.beat(name, self.clock.now_ms())
        return ta

    def trust(self, a: str, b: str, value: float):
        self.root.set_trust(a, b, value)

    def _home_ta(self, region: str, ta: str | None) -> RegionalTA:
        if ta is not None:
            return self.root.tas[ta]
        local = [t for t in self.root.tas.values() if t.region == region and t.operational]
        if not local:
            raise NoTAAvailable(f"no operational TA in {region} for enrolment")
        return min(local, key=lambda t: (len(t.by_handle) + len(t.uavs), t.name))

    # ------------------------------------------------------ registration
    def register_vehicle(self, name: str, region: str, password: bytes | None = None,
                         ta: str | None = None) -> Vehicle:
        """VR-1 .. VR-3 (secure enrolment channel)."""
        if name in self.vehicles:
            raise ValueError("vehicle name already used")
        home = self._home_ta(region, ta)
        id_v, pw = rand(), password or secrets.token_bytes(12)
        p = self.cfg.protocol
        with acting_as("vehicle"):
            n_vr1 = rand()
            pid = h(id_v, n_vr1)                                   # VR-1
        tid, n_vr2, rec = home.register_vehicle(pid)               # VR-2
        with acting_as("vehicle"):
            card = VehicleSmartCard.issue(id_v, pw, tid, n_vr1, n_vr2, p.pq_mode,
                                          p.smartcard_max_attempts)  # VR-3
        v = Vehicle(id_v, pw, card, self.clock, p, name, region)
        v.home_ta, v.handle = home.name, rec.handle
        self.vehicles[name] = v
        return v

    def register_uav(self, name: str, region: str, password: bytes | None = None,
                     ta: str | None = None, puf: ArbiterPUF | None = None) -> UAV:
        """UR-1 .. UR-4 (secure enrolment channel)."""
        if name in self.uavs:
            raise ValueError("UAV name already used")
        home = self._home_ta(region, ta)
        p = self.cfg.protocol
        id_u, pw = rand(), password or secrets.token_bytes(12)
        puf = puf or ArbiterPUF(home.fe.n_bits, p.puf_noise_rate,
                                np.random.default_rng(self.rng.integers(2**63)))
        c_u = home.uav_challenge(id_u)                             # UR-1, UR-2
        with acting_as("uav"):
            rs = puf.enrol_response(c_u, p.puf_enrol_reads)        # UR-3 (UAV side)
        helper, rec = home.register_uav(id_u, c_u, rs)             # UR-3 (TA side)
        with acting_as("uav"):
            card = UAVSmartCard.issue(id_u, pw, c_u, helper, p.pq_mode,
                                      p.smartcard_max_attempts)    # UR-4
        u = UAV(id_u, pw, card, puf, home.fe, self.clock, p, name, region)
        u.home_ta, u.handle = home.name, rec.handle
        self.uavs[name] = u
        return u

    # ----------------------------------------------------- authentication
    def select_ta(self, vehicle: Vehicle, exclude=()) -> RegionalTA:
        handle = self.root.tid_dir.get(vehicle.card.tid)
        home = self.root.home.get(handle) if handle else vehicle.home_ta
        return self.lb.select(home, vehicle.region, self.clock.now_ms(), exclude)

    def run_ta_step(self, ta: RegionalTA, handler, msg, sid) -> tuple[ProtocolMessage, int]:
        """Call an RTA handler, fetching missing delegated records on demand."""
        fetches = 0
        while True:
            try:
                return handler(msg, sid), fetches
            except NeedRecord as need:
                if fetches >= 2:
                    raise AuthError("delegated credential could not be resolved")
                ta.fetch(need.kind, need.key)
                fetches += 1

    def authenticate(self, vehicle: Vehicle, uav: UAV, ta: str | None = None,
                     tap: Tap | None = None) -> AuthResult:
        sid = secrets.randbits(32)
        res = AuthResult(False, sid=sid)
        tap = tap or (lambda stage, raw: raw)
        try:
            serving = self.root.tas[ta] if ta else self.select_ta(vehicle)
            res.ta = serving.name
            m1 = vehicle.start(uav.id_u)
            m1 = self._through(tap, "msg1", m1, res)
            m2, f1 = self.run_ta_step(serving, serving.handle_msg1, m1, sid)
            m2 = self._through(tap, "msg2", m2, res)
            m3 = uav.respond(m2, sid)
            m3 = self._through(tap, "msg3", m3, res)
            m4, f2 = self.run_ta_step(serving, serving.handle_msg3, m3, sid)
            serving.flush_federation()
            m4 = self._through(tap, "msg4", m4, res)
            sk_v = vehicle.finish(m4)
            sk_u = uav.session_keys.get(sid)
            res.fetches = f1 + f2
            res.delegated = serving.name != vehicle.home_ta or serving.name != uav.home_ta
            if sk_u is None or sk_u != sk_v:
                raise AuthError("vehicle and UAV derived different session keys")
            res.ok, res.sk_vehicle, res.sk_uav = True, sk_v, sk_u
            self.root.observe(serving.name, True)
        except TAUnavailable as exc:
            res.reason = str(exc)
            self.root.observe(res.ta, False)
        except (AuthError, LoginError, NoTAAvailable, MalformedMessage, _Dropped) as exc:
            res.reason = str(exc)
        return res

    @staticmethod
    def _through(tap: Tap, stage: str, msg: ProtocolMessage, res: AuthResult) -> ProtocolMessage:
        raw = msg.to_bytes()
        res.bits[stage] = 8 * len(raw)
        out = tap(stage, raw)
        if out is None:
            raise _Dropped(f"{stage} lost in transit")
        res.transcript[stage] = out
        return ProtocolMessage.from_bytes(msg.kind, out)

    # ------------------------------------------- revocation and recovery
    def revoke(self, entity: Vehicle | UAV, reason: str = "compromised") -> int:
        return self.root.revoke(entity.handle, reason)

    def reenrol_vehicle(self, vehicle: Vehicle, password: bytes | None = None,
                        ta: str | None = None) -> Vehicle:
        """Revoke the old credentials and issue new ones; nothing else changes."""
        if vehicle.handle not in self.root.revoked:
            self.revoke(vehicle, "credential recovery")
        del self.vehicles[vehicle.name]
        return self.register_vehicle(vehicle.name, vehicle.region,
                                     password or vehicle.pw, ta)

    def reenrol_uav(self, uav: UAV, password: bytes | None = None,
                    ta: str | None = None, new_hardware: bool = False) -> UAV:
        """Revoke the old record, issue a fresh PUF challenge and helper data."""
        if uav.handle not in self.root.revoked:
            self.revoke(uav, "credential recovery")
        del self.uavs[uav.name]
        puf = None if new_hardware else uav.puf
        if puf is not None and puf.tampered:
            raise ValueError("tampered PUF cannot be re-enrolled; replace the hardware")
        return self.register_uav(uav.name, uav.region, password or uav.pw, ta, puf)


class _Dropped(Exception):
    pass
