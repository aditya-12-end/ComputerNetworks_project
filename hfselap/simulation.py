"""Discrete-event simulation of HF-SELAP over a lossy, delayed network.

Every authentication request in the simulation executes the *real* protocol
code (ASCON, SHA-256, PUF, fuzzy extractor, federation messages).  The CPU
time measured for each computation becomes the service time of that step, so
queueing at Regional TAs and UAVs emerges from measured costs rather than
assumed constants.  Network hops add latency + Gaussian jitter and may lose
messages; the vehicle retries after a timeout, choosing another TA.

Simulated time is in milliseconds and drives the protocol's SimClock, so
timestamp freshness (Delta T) is checked against simulated delays,
including queueing delay.
"""

from __future__ import annotations

import gc
import heapq
import itertools
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

import numpy as np

from .entities import AuthError, LoginError, UAV, Vehicle
from .loadbalancer import NoTAAvailable
from .messages import ProtocolMessage
from .primitives import SimClock
from .system import HFSELAP
from .ta import NeedRecord, RegionalTA, TAUnavailable


@dataclass
class RequestRecord:
    rid: int
    vehicle: str
    uav: str
    t_start: float
    t_end: float | None = None
    ok: bool = False
    attempts: int = 0
    reason: str = ""
    tas: list = field(default_factory=list)
    delegated: bool = False


@dataclass
class _Attempt:
    req: RequestRecord
    vehicle: Vehicle
    uav: UAV
    ta: RegionalTA
    sid: int
    excluded: set
    done: bool = False


class _Server:
    """FIFO single server (one CPU worker) for a TA or a UAV."""

    def __init__(self, capacity: int | None = None):
        self.queue: deque = deque()
        self.busy = False
        self.capacity = capacity
        self.epoch = 0                 # incremented on failure to void in-flight jobs
        self.busy_ms = 0.0
        self.jobs = 0

    def __len__(self):
        return len(self.queue) + (1 if self.busy else 0)


class Simulation:
    def __init__(self, system: HFSELAP, seed: int = 0, heartbeats: bool = True,
                 loss_fn: Callable[[str, "Vehicle | None"], float] | None = None,
                 cpu_scale: float = 1.0, routing: str = "lb"):
        if not isinstance(system.clock, SimClock):
            raise TypeError("Simulation requires a system built with SimClock")
        self.sys, self.cfg = system, system.cfg
        self.clock: SimClock = system.clock
        self.t0 = self.clock.now_ms()
        self.rng = np.random.default_rng(seed)
        self.events: list = []
        self._seq = itertools.count()
        self.ta_srv = {name: _Server(self.cfg.network.ta_queue_capacity) for name in system.root.tas}
        self.uav_srv: dict[str, _Server] = {}
        self.requests: list[RequestRecord] = []
        self.busy_vehicles: set[str] = set()
        self.loss_fn = loss_fn or (lambda link, veh: self.cfg.network.loss_rate)
        self.cpu_scale = cpu_scale
        if routing not in {"lb", "home"}:
            raise ValueError("routing must be 'lb' (load balancer) or 'home' (static)")
        self.routing = routing
        self.heartbeats = heartbeats
        self.heartbeat_count = 0
        self.hb_epoch = {name: 0 for name in system.root.tas}
        self.lost_messages = 0
        self.skipped = 0
        self.federation_ms = 0.0               # CPU spent on asynchronous inter-TA sync
        self.msg_bits = 0
        if heartbeats:
            for name in system.root.tas:
                self._at(0.0, self._heartbeat, name, 0)

    # ---------------------------------------------------------- engine
    def _at(self, t_rel: float, fn, *args):
        heapq.heappush(self.events, (self.t0 + t_rel, next(self._seq), fn, args))

    def _after(self, delay: float, fn, *args):
        heapq.heappush(self.events, (self.clock.now_ms() + delay, next(self._seq), fn, args))

    def run(self, until_rel: float):
        end = self.t0 + until_rel
        # Garbage-collection pauses would otherwise be billed to whichever
        # protocol step happens to be timed, distorting the service times.
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            while self.events and self.events[0][0] <= end:
                t, _, fn, args = heapq.heappop(self.events)
                self.clock.set(t)
                fn(*args)
        finally:
            if was_enabled:
                gc.enable()
        self.clock.set(end)

    def now_rel(self) -> float:
        return self.clock.now_ms() - self.t0

    def _measure(self, fn, *args):
        """Run real protocol code; return (result, exception, elapsed simulated ms)."""
        start = time.perf_counter()
        try:
            out, err = fn(*args), None
        except Exception as exc:              # protocol failures are data here
            out, err = None, exc
        return out, err, (time.perf_counter() - start) * 1000.0 * self.cpu_scale

    # --------------------------------------------------------- network
    def _latency(self, a_region: str, b_region: str) -> float:
        n = self.cfg.network
        base = n.access_local_ms if a_region == b_region else n.access_remote_ms
        return base + abs(self.rng.normal(0.0, n.jitter_ms))

    def _backhaul(self) -> float:
        n = self.cfg.network
        return n.backhaul_ms + abs(self.rng.normal(0.0, n.jitter_ms))

    def _lost(self, link: str, vehicle: Vehicle | None) -> bool:
        p = self.loss_fn(link, vehicle)
        if p > 0 and self.rng.random() < p:
            self.lost_messages += 1
            return True
        return False

    # -------------------------------------------------------- workload
    def submit(self, t_rel: float, vehicle_name: str, uav_name: str,
               region: str | None = None):
        """Schedule a request; ``region`` is the vehicle's position at that time."""
        self._at(t_rel, self._new_request, vehicle_name, uav_name, region)

    def fail_ta(self, t_rel: float, name: str):
        self._at(t_rel, self._fail, name)

    def recover_ta(self, t_rel: float, name: str):
        self._at(t_rel, self._recover, name)

    def _fail(self, name: str):
        ta = self.sys.root.tas[name]
        ta.fail()
        srv = self.ta_srv[name]
        srv.queue.clear()
        srv.busy = False
        srv.epoch += 1
        ta.queue_len = 0

    def _recover(self, name: str):
        self.sys.root.tas[name].recover()
        if self.heartbeats:
            self.hb_epoch[name] += 1
            self._heartbeat(name, self.hb_epoch[name])

    def _heartbeat(self, name: str, epoch: int):
        ta = self.sys.root.tas[name]
        if ta.operational and epoch == self.hb_epoch[name]:
            self.heartbeat_count += 1
            self._after(self._backhaul(), self.sys.monitor.beat, name, self.clock.now_ms())
            self._after(self.cfg.federation.heartbeat_interval_ms, self._heartbeat, name, epoch)

    # ------------------------------------------------- request lifecycle
    def _new_request(self, vehicle_name: str, uav_name: str, region: str | None = None):
        if region is not None and vehicle_name not in self.busy_vehicles:
            self.sys.vehicles[vehicle_name].region = region
        if vehicle_name in self.busy_vehicles:
            self.skipped += 1                        # one outstanding request per vehicle
            return
        req = RequestRecord(len(self.requests), vehicle_name, uav_name, self.now_rel())
        self.requests.append(req)
        self.busy_vehicles.add(vehicle_name)
        self._start_attempt(req, set())

    def _start_attempt(self, req: RequestRecord, excluded: set):
        if req.attempts >= self.cfg.network.max_attempts:
            return self._finish(req, False, req.reason or "attempts exhausted")
        vehicle = self.sys.vehicles[req.vehicle]
        uav = self.sys.uavs[req.uav]
        try:
            if self.routing == "home":                # static: always the home RTA
                if not self.sys.monitor.is_up(vehicle.home_ta, self.clock.now_ms()):
                    raise NoTAAvailable("home RTA unavailable")
                ta = self.sys.root.tas[vehicle.home_ta]
            else:
                ta = self.sys.select_ta(vehicle, exclude=excluded)
        except NoTAAvailable:
            if excluded:                             # allow re-trying earlier TAs
                return self._start_attempt(req, set())
            req.attempts += 1
            req.reason = "no Regional TA available"
            return self._after(self.cfg.network.attempt_timeout_ms, self._start_attempt, req, set())
        req.attempts += 1
        req.tas.append(ta.name)
        att = _Attempt(req, vehicle, uav, ta, secrets.randbits(32), set(excluded))
        msg1, err, dt = self._measure(vehicle.start, uav.id_u)
        if err is not None:
            return self._finish(req, False, f"vehicle: {err}")
        self._after(self.cfg.network.attempt_timeout_ms, self._timeout, att)
        self._send(att, dt, "v2ta", vehicle.region, ta.region, self._ta_arrival,
                   att, ta, "msg1", msg1)

    def _send(self, att, compute_ms, link, a_region, b_region, fn, *args):
        msg = args[-1]
        self.msg_bits += msg.bits
        if self._lost(link, att.vehicle):
            return
        self._after(compute_ms + self._latency(a_region, b_region), fn, *args)

    def _timeout(self, att: _Attempt):
        if att.done or att.req.t_end is not None:
            return
        att.done = True
        # fast failure suspicion: a timeout plus at least one missed heartbeat
        now = self.clock.now_ms()
        last = self.sys.monitor.last_beat.get(att.ta.name, now)
        if self.heartbeats and now - last > self.cfg.federation.heartbeat_interval_ms:
            self.sys.monitor.suspect(att.ta.name, now)
        att.req.reason = att.req.reason or "timeout"
        self._start_attempt(att.req, att.excluded | {att.ta.name})

    # ---------------------------------------------------- TA processing
    def _ta_arrival(self, att: _Attempt, ta: RegionalTA, stage: str, msg: ProtocolMessage):
        if att.done or not ta.operational:
            return
        srv = self.ta_srv[ta.name]
        if stage == "msg1" and len(srv) >= srv.capacity:
            # overload: explicit busy reply so the vehicle retries elsewhere at once
            att.done = True
            att.req.reason = "TA overloaded"
            self._after(self._latency(ta.region, att.vehicle.region),
                        self._start_attempt, att.req, att.excluded | {ta.name})
            return
        srv.queue.append((att, stage, msg))
        ta.queue_len = len(srv)
        if not srv.busy:
            self._ta_serve(ta)

    def _ta_serve(self, ta: RegionalTA):
        srv = self.ta_srv[ta.name]
        if not srv.queue or not ta.operational:
            srv.busy = False
            ta.queue_len = len(srv)
            return
        srv.busy = True
        att, stage, msg = srv.queue.popleft()
        handler = ta.handle_msg1 if stage == "msg1" else ta.handle_msg3
        out, err, dt = self._measure(handler, msg, att.sid)
        srv.busy_ms += dt
        srv.jobs += 1
        self._after(dt, self._ta_done, ta, srv.epoch, att, stage, msg, out, err)

    def _ta_done(self, ta, epoch, att, stage, msg, out, err):
        srv = self.ta_srv[ta.name]
        if epoch != srv.epoch:                      # TA failed during service
            return
        if isinstance(err, NeedRecord):
            # fetch the delegated credential from the root asynchronously, then requeue
            rtt = self._backhaul() + self._backhaul()
            self._after(rtt, self._fetch_done, ta, epoch, att, stage, msg, err)
        elif err is None and not att.done:
            if stage == "msg1":
                self._send(att, 0.0, "ta2u", ta.region, att.uav.region,
                           self._uav_arrival, att, out)
            else:
                self._send(att, 0.0, "ta2v", ta.region, att.vehicle.region,
                           self._vehicle_arrival, att, out)
                _, ferr, fdt = self._measure(ta.flush_federation)
                if ferr is not None:
                    raise ferr
                self.federation_ms += fdt
        elif err is not None and not isinstance(err, (AuthError, TAUnavailable)):
            raise err
        elif err is not None:
            att.req.reason = str(err)
        self._ta_serve(ta)

    def _fetch_done(self, ta, epoch, att, stage, msg, need: NeedRecord):
        if epoch != self.ta_srv[ta.name].epoch or not ta.operational or att.done:
            return
        try:
            ta.fetch(need.kind, need.key)
        except AuthError as exc:
            att.req.reason = str(exc)
            return                                   # vehicle will time out
        self._ta_arrival(att, ta, stage, msg)

    # ------------------------------------------------- UAV and vehicle
    def _uav_arrival(self, att: _Attempt, msg2: ProtocolMessage):
        srv = self.uav_srv.setdefault(att.uav.name, _Server())
        srv.queue.append((att, msg2))
        if not srv.busy:
            self._uav_serve(att.uav)

    def _uav_serve(self, uav: UAV):
        srv = self.uav_srv[uav.name]
        if not srv.queue:
            srv.busy = False
            return
        srv.busy = True
        att, msg2 = srv.queue.popleft()
        out, err, dt = self._measure(uav.respond, msg2, att.sid)
        srv.busy_ms += dt
        srv.jobs += 1
        self._after(dt, self._uav_done, uav, att, out, err)

    def _uav_done(self, uav, att, out, err):
        if err is None and not att.done:
            self._send(att, 0.0, "u2ta", uav.region, att.ta.region,
                       self._ta_arrival, att, att.ta, "msg3", out)
        elif err is not None:
            att.req.reason = str(err)
        self._uav_serve(uav)

    def _vehicle_arrival(self, att: _Attempt, msg4: ProtocolMessage):
        if att.done:
            return
        sk, err, dt = self._measure(att.vehicle.finish, msg4)
        if err is not None:
            att.req.reason = str(err)
            return
        att.done = True
        ok = att.uav.session_keys.pop(att.sid, None) == sk
        self.sys.root.observe(att.ta.name, True)
        att.req.delegated = (att.ta.name != att.vehicle.home_ta
                             or att.ta.name != att.uav.home_ta)
        self._after(dt, self._finish, att.req, ok, "" if ok else "session key mismatch")

    def _finish(self, req: RequestRecord, ok: bool, reason: str):
        if req.t_end is not None:
            return
        req.t_end, req.ok = self.now_rel(), ok
        if ok:
            req.reason = ""
        else:
            req.reason = reason
        self.busy_vehicles.discard(req.vehicle)

    # ------------------------------------------------------------ results
    def finalize(self, horizon_rel: float):
        """Mark requests still open at the end of the run as failures."""
        for req in self.requests:
            if req.t_end is None:
                req.t_end, req.ok = horizon_rel, False
                req.reason = req.reason or "unfinished at end of run"

    def summary(self) -> dict:
        done = [r for r in self.requests if r.t_end is not None]
        ok = [r for r in done if r.ok]
        lat = np.array([r.t_end - r.t_start for r in ok]) if ok else np.array([0.0])
        jobs = {name: s.jobs for name, s in self.ta_srv.items()}
        loads = np.array([s.busy_ms for s in self.ta_srv.values()], dtype=float)
        jain = float(loads.sum() ** 2 / (len(loads) * (loads ** 2).sum())) if loads.any() else 1.0
        return {
            "requests": len(self.requests),
            "successes": len(ok),
            "success_rate": len(ok) / len(done) if done else 0.0,
            "mean_latency_ms": float(lat.mean()),
            "p95_latency_ms": float(np.percentile(lat, 95)),
            "mean_attempts": float(np.mean([r.attempts for r in done])) if done else 0.0,
            "delegated_fraction": float(np.mean([r.delegated for r in ok])) if ok else 0.0,
            "ta_jobs": jobs,
            "ta_busy_ms": {n: s.busy_ms for n, s in self.ta_srv.items()},
            "jain_fairness": jain,
            "heartbeats": self.heartbeat_count,
            "lost_messages": self.lost_messages,
            "skipped_busy_vehicle": self.skipped,
            "federation_sync_ms": self.federation_ms,
        }
