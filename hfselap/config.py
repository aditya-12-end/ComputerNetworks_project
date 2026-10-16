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
    puf_noise_rate: float = 0.03        # per-bit flip probability of the PUF
    fe_repetition: int = 7              # repetition factor of the fuzzy extractor
    puf_max_reads: int = 3              # PUF re-measurements before aborting
    puf_enrol_reads: int = 9            # majority-voted reads used at enrolment
    smartcard_max_attempts: int = 5     # wrong-password lockout threshold


@dataclass
class FederationConfig:
    trust_threshold: float = 0.6        # minimum inter-TA trust for delegation
    trust_history_weight: float = 0.9   # EWMA weight of old trust value
    cache_ttl_ms: float = 60_000.0      # lifetime of delegated credential cache
    heartbeat_interval_ms: float = 500.0
    heartbeat_misses: int = 3           # missed beats before a TA is declared down
    lb_weights: dict = field(default_factory=lambda: {
        "load": 0.45, "trust": 0.25, "latency": 0.20, "home": 0.10})


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
        if not 0 <= p.puf_noise_rate < 0.5:
            raise ValueError("puf_noise_rate must be in [0, 0.5)")
        if p.fe_repetition < 1 or p.fe_repetition % 2 == 0:
            raise ValueError("fe_repetition must be a positive odd integer")
        if p.puf_max_reads < 1 or p.smartcard_max_attempts < 1:
            raise ValueError("puf_max_reads and smartcard_max_attempts must be >= 1")
        if p.puf_enrol_reads < 1 or p.puf_enrol_reads % 2 == 0:
            raise ValueError("puf_enrol_reads must be a positive odd integer")
        if not 0 <= f.trust_threshold <= 1 or not 0 <= f.trust_history_weight <= 1:
            raise ValueError("trust values must lie in [0, 1]")
        if set(f.lb_weights) != {"load", "trust", "latency", "home"}:
            raise ValueError("lb_weights needs keys load, trust, latency, home")
        if abs(sum(f.lb_weights.values()) - 1.0) > 1e-9:
            raise ValueError("lb_weights must sum to 1")
        if f.heartbeat_interval_ms <= 0 or f.heartbeat_misses < 1:
            raise ValueError("invalid heartbeat settings")
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
