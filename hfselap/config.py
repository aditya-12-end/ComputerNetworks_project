"""Configuration for HF-SELAP (validated dataclasses loaded from config.json)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, asdict
from pathlib import Path


@dataclass
class ProtocolConfig:
    delta_t_ms: float = 2000.0          # maximum accepted message age (Delta T)
    pq_mode: bool = False               # True -> Ascon-80pq (160-bit keys)
    dual_record: bool = True            # SELAP <TID_o, TID_c> desync defence
    replay_cache: bool = True           # reject duplicates inside Delta T
    smartcard_max_attempts: int = 5     # wrong-password lockout threshold


@dataclass
class FederationConfig:
    trust_threshold: float = 0.6        # T_min: minimum inter-TA trust for delegation
    trust_history_weight: float = 0.9   # alpha: weight of the old trust / reliability value
    cache_ttl_ms: float = 60_000.0      # lifetime of delegated credential cache
    heartbeat_interval_ms: float = 500.0
    heartbeat_misses: int = 3           # missed beats before a TA is declared down
    availability_window_ms: float = 10_000.0   # window of the availability estimate A_i
    max_load: float = 0.9               # L_max: TAs above this load are bypassed
    lb_weights: dict = field(default_factory=lambda: {   # w1..w4 of Score(TA_i)
        "load": 0.45, "availability": 0.15, "reliability": 0.20, "delay": 0.20})


@dataclass
class NetworkConfig:
    access_local_ms: float = 10.0       # vehicle/UAV <-> TA in the same region (5G)
    access_remote_ms: float = 25.0      # vehicle/UAV <-> TA in another region
    backhaul_ms: float = 8.0            # TA <-> root / TA <-> TA
    jitter_ms: float = 2.0              # std-dev of Gaussian jitter per hop
    loss_rate: float = 0.0              # per-message loss probability
    ta_queue_capacity: int = 200        # requests a TA can hold before dropping
    attempt_timeout_ms: float = 1500.0  # vehicle waits this long for Msg4
    max_attempts: int = 3               # authentication attempts per request


@dataclass
class Config:
    protocol: ProtocolConfig = field(default_factory=ProtocolConfig)
    federation: FederationConfig = field(default_factory=FederationConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)

    def __post_init__(self):
        p, f, n = self.protocol, self.federation, self.network
        if p.delta_t_ms <= 0:
            raise ValueError("delta_t_ms must be positive")
        if p.smartcard_max_attempts < 1:
            raise ValueError("smartcard_max_attempts must be >= 1")
        if not 0 <= f.trust_threshold <= 1 or not 0 <= f.trust_history_weight <= 1:
            raise ValueError("trust values must lie in [0, 1]")
        if set(f.lb_weights) != {"load", "availability", "reliability", "delay"}:
            raise ValueError("lb_weights needs keys load, availability, reliability, delay")
        if min(f.lb_weights.values()) < 0 or abs(sum(f.lb_weights.values()) - 1.0) > 1e-9:
            raise ValueError("lb_weights must be non-negative and sum to 1")
        if f.heartbeat_interval_ms <= 0 or f.heartbeat_misses < 1:
            raise ValueError("invalid heartbeat settings")
        if f.availability_window_ms <= f.heartbeat_interval_ms or not 0 < f.max_load <= 1:
            raise ValueError("invalid availability window or max_load")
        if not 0 <= n.loss_rate < 1 or n.ta_queue_capacity < 1 or n.max_attempts < 1:
            raise ValueError("invalid network settings")

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        def build(kind, values):
            known = {f.name for f in fields(kind)}
            unknown = set(values) - known
            if unknown:
                raise ValueError(f"Unknown {kind.__name__} keys: {sorted(unknown)}")
            return kind(**values)
        return cls(build(ProtocolConfig, data.get("protocol", {})),
                   build(FederationConfig, data.get("federation", {})),
                   build(NetworkConfig, data.get("network", {})))

    @classmethod
    def load(cls, path: str | Path = "config.json") -> "Config":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8-sig")))

    def to_dict(self) -> dict:
        return asdict(self)
