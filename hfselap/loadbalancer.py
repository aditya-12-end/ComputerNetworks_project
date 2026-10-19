"""Load balancing and fault tolerance for the federated TA layer.

``HealthMonitor`` decides whether an RTA is usable and estimates its availability:

* ``oracle`` mode (synchronous demo / tests): uses the RTA's real state;
* ``heartbeat`` mode (event simulation): an RTA is up while its last
  heartbeat is younger than ``heartbeat_interval_ms * heartbeat_misses``;
  a request timeout additionally marks it *suspected* until it beats again.
  Availability A_i is the share of the recent window (``availability_window_ms``)
  not covered by heartbeat gaps.

``LoadBalancer`` implements the dynamic Regional-TA selection of HF-SELAP:

    L_i        = Q_i / C_i                              (queue / capacity)
    D_i^score  = (D_max - D_i) / (D_max - D_min)        (normalised delay)
    Score(TA_i) = w1 (1 - L_i) + w2 A_i + w3 R_i + w4 D_i^score
    TA*        = argmax Score(TA_i)  over operational RTAs trusted by the home RTA

where R_i is the reliability kept by the Root TA.  RTAs with L_i > L_max are
bypassed while another candidate is available.  Ties prefer the home RTA,
then the earlier-registered RTA, so runs are reproducible.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Iterable

from .config import Config

if TYPE_CHECKING:                                    # pragma: no cover
    from .federation import RootTA
    from .ta import RegionalTA


class NoTAAvailable(Exception):
    pass


class HealthMonitor:
    def __init__(self, cfg: Config, tas: dict, mode: str = "oracle"):
        if mode not in {"oracle", "heartbeat"}:
            raise ValueError("mode must be 'oracle' or 'heartbeat'")
        self.cfg, self.tas, self.mode = cfg, tas, mode
        self.last_beat: dict[str, float] = {}
        self.history: dict[str, deque] = {}
        self.suspected: set[str] = set()
        self.detections: list[tuple[str, float]] = []

    def beat(self, name: str, now: float):
        self.last_beat[name] = now
        self.suspected.discard(name)
        hist = self.history.setdefault(name, deque())
        hist.append(now)
        lo = now - self.cfg.federation.availability_window_ms
        while len(hist) > 1 and hist[1] < lo:          # keep one beat before the window
            hist.popleft()

    def suspect(self, name: str, now: float):
        if name not in self.suspected:
            self.suspected.add(name)
            self.detections.append((name, now))

    def is_up(self, name: str, now: float) -> bool:
        if self.mode == "oracle":
            return self.tas[name].operational
        if name in self.suspected:
            return False
        f = self.cfg.federation
        last = self.last_beat.get(name)
        return last is not None and now - last <= f.heartbeat_interval_ms * f.heartbeat_misses

    def availability(self, name: str, now: float) -> float:
        """A_i in [0, 1]: fraction of the recent window without a heartbeat outage."""
        if self.mode == "oracle":
            return 1.0 if self.tas[name].operational else 0.0
        hist = self.history.get(name)
        if not hist:
            return 0.0
        f = self.cfg.federation
        lo = now - f.availability_window_ms
        grace = 1.5 * f.heartbeat_interval_ms             # one late beat is not an outage
        down, prev = 0.0, None
        for t in list(hist) + [now]:
            if prev is not None:
                gap_start = max(prev + grace, lo)
                if t > gap_start:
                    down += t - gap_start
            prev = t
        span = min(f.availability_window_ms, now - hist[0])
        return 1.0 if span <= 0 else max(0.0, 1.0 - down / span)


class LoadBalancer:
    def __init__(self, cfg: Config, root: "RootTA", monitor: HealthMonitor):
        self.cfg, self.root, self.monitor = cfg, root, monitor

    def candidates(self, home_ta: str | None, now: float,
                   exclude: Iterable[str] = ()) -> list["RegionalTA"]:
        """Operational RTAs (Status = 1) trusted by the home RTA (Trust >= T_min)."""
        excluded = set(exclude)
        return [ta for name, ta in self.root.tas.items()
                if name not in excluded and self.monitor.is_up(name, now)
                and (home_ta is None or self.root.trusted(home_ta, name))]

    def load(self, ta: "RegionalTA") -> float:
        """L_i = Q_i / C_i."""
        return min(ta.queue_len / self.cfg.network.ta_queue_capacity, 1.0)

    def delay(self, ta: "RegionalTA", region: str) -> float:
        """D_i: expected access delay between the requesting vehicle and TA_i."""
        n = self.cfg.network
        return n.access_local_ms if ta.region == region else n.access_remote_ms

    def score(self, ta: "RegionalTA", now: float, d: float, d_min: float, d_max: float) -> float:
        w = self.cfg.federation.lb_weights
        d_score = 1.0 if d_max == d_min else (d_max - d) / (d_max - d_min)
        return (w["load"] * (1.0 - self.load(ta))
                + w["availability"] * self.monitor.availability(ta.name, now)
                + w["reliability"] * self.root.reliability[ta.name]
                + w["delay"] * d_score)

    def select(self, home_ta: str | None, region: str, now: float,
               exclude: Iterable[str] = ()) -> "RegionalTA":
        cands = self.candidates(home_ta, now, exclude)
        if not cands:
            raise NoTAAvailable("no operational and trusted Regional TA")
        below = [ta for ta in cands if self.load(ta) <= self.cfg.federation.max_load]
        cands = below or cands                       # L_i > L_max -> redirect if possible
        delays = {ta.name: self.delay(ta, region) for ta in cands}
        d_min, d_max = min(delays.values()), max(delays.values())
        return max(cands, key=lambda ta: (self.score(ta, now, delays[ta.name], d_min, d_max),
                                          ta.name == home_ta))
