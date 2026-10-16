from dataclasses import dataclass, field


@dataclass
class Entity:
    identity: str
    kind: str
    region: str
    signing_private_key: object
    signing_public_key: object
    pseudonym: str
    revoked: bool = False


@dataclass
class RegionalTA:
    name: str
    region: str
    capacity: int
    availability: float
    reliability: float
    delay_ms: float
    signing_private_key: object
    signing_public_key: object
    operational: bool = True
    active: int = 0
    total_requests: int = 0
    registry: dict[str, object] = field(default_factory=dict)

    def __post_init__(self):
        if self.capacity <= 0:
            raise ValueError("TA capacity must be positive")
        if not 0 <= self.availability <= 1 or not 0 <= self.reliability <= 1:
            raise ValueError("Availability and reliability must be between 0 and 1")
        if self.delay_ms < 0:
            raise ValueError("Delay cannot be negative")

    @property
    def load(self) -> float:
        return min(self.active / self.capacity, 1.0)

    @property
    def delay_score(self) -> float:
        return 1.0 / (1.0 + self.delay_ms / 100.0)
