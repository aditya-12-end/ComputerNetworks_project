from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class SecurityConfig:
    timestamp_tolerance_seconds: int
    minimum_federation_trust: float
    trust_history_weight: float
    selection_weights: dict[str, float]
    aead_key_bytes: int
    pseudonym_bytes: int

    def __post_init__(self):
        if self.timestamp_tolerance_seconds <= 0:
            raise ValueError("timestamp_tolerance_seconds must be positive")
        if not 0 <= self.minimum_federation_trust <= 1:
            raise ValueError("minimum_federation_trust must be between 0 and 1")
        if not 0 <= self.trust_history_weight <= 1:
            raise ValueError("trust_history_weight must be between 0 and 1")
        if set(self.selection_weights) != {"capacity", "availability", "reliability", "delay"}:
            raise ValueError("selection_weights must define capacity, availability, reliability, delay")
        if any(not 0 <= v <= 1 for v in self.selection_weights.values()):
            raise ValueError("selection weights must be between 0 and 1")
        if abs(sum(self.selection_weights.values()) - 1.0) > 1e-9:
            raise ValueError("selection weights must sum to 1")
        if self.aead_key_bytes != 32:
            raise ValueError("This implementation requires 32-byte AES-256-GCM keys")
        if self.pseudonym_bytes < 8:
            raise ValueError("pseudonym_bytes must be at least 8")

    @classmethod
    def load(cls, path: str = "config.json"):
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return cls(**data)
