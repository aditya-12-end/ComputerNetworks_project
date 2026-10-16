"""Load balancing and fault tolerance for the federated TA layer.

``HealthMonitor`` decides whether an RTA is usable:

* ``oracle`` mode (synchronous demo / tests): uses the RTA's real state;
* ``heartbeat`` mode (event simulation): an RTA is up while its last
  heartbeat is younger than ``heartbeat_interval_ms * heartbeat_misses``;
  a request timeout additionally marks it *suspected* until it beats again.

``LoadBalancer`` scores every usable, trusted RTA

    score = w_load * (1 - queue/capacity) + w_trust * reliability
          + w_latency * (local_latency / expected_latency) + w_home * [home RTA]

and returns the best one.  Ties are broken by name so runs are reproducible.
"""

from __future__ import annotations

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
        self.suspected: set[str] = set()
        self.detections: list[tuple[str, float]] = []

    def beat(self, name: str, now: float):
        self.last_beat[name] = now
        self.suspected.discard(name)

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


class LoadBalancer:
    def __init__(self, cfg: Config, root: "RootTA", monitor: HealthMonitor):
        self.cfg, self.root, self.monitor = cfg, root, monitor

    def candidates(self, home_ta: str | None, now: float,
                   exclude: Iterable[str] = ()) -> list["RegionalTA"]:
        excluded = set(exclude)
        return [ta for name, ta in self.root.tas.items()
                if name not in excluded and self.monitor.is_up(name, now)
                and (home_ta is None or self.root.trusted(home_ta, name))]

    def score(self, ta: "RegionalTA", home_ta: str | None, region: str) -> float:
        w = self.cfg.federation.lb_weights
        n = self.cfg.network
        util = min(ta.queue_len / n.ta_queue_capacity, 1.0)
        latency = n.access_local_ms if ta.region == region else n.access_remote_ms
        return (w["load"] * (1.0 - util)
                + w["trust"] * self.root.reliability[ta.name]
                + w["latency"] * (n.access_local_ms / latency)
                + w["home"] * (1.0 if ta.name == home_ta else 0.0))

    def select(self, home_ta: str | None, region: str, now: float,
               exclude: Iterable[str] = ()) -> "RegionalTA":
        cands = self.candidates(home_ta, now, exclude)
        if not cands:
            raise NoTAAvailable("no operational and trusted Regional TA")
        return max(cands, key=lambda ta: (self.score(ta, home_ta, region), ta.name))
