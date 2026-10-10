import time
from .crypto import canonical_json, sign, verify


class Federation:
    def __init__(self, config):
        self.config = config
        self.trust: dict[tuple[str, str], float] = {}
        self.audit_log: list[dict] = []

    def set_trust(self, source: str, destination: str, value: float):
        if source == destination:
            raise ValueError("Inter-TA trust is only for distinct TAs")
        if not 0 <= value <= 1:
            raise ValueError("Trust must be between 0 and 1")
        self.trust[(source, destination)] = value
        self.audit("trust_set", source=source, destination=destination, trust=value)

    def update_trust(self, source: str, destination: str, observation: float) -> float:
        if not 0 <= observation <= 1:
            raise ValueError("Observation must be between 0 and 1")
        if (source, destination) not in self.trust:
            raise PermissionError("Unknown TA relationship defaults to untrusted; bootstrap it explicitly")
        alpha = self.config.trust_history_weight
        new_value = alpha * self.trust[(source, destination)] + (1 - alpha) * observation
        self.trust[(source, destination)] = new_value
        self.audit("trust_updated", source=source, destination=destination, trust=round(new_value, 5))
        return new_value

    def trusted(self, source: str, destination: str) -> bool:
        if source == destination:
            return True
        return self.trust.get((source, destination), 0.0) >= self.config.minimum_federation_trust

    def cross_region_allowed(self, source_tas: list, destination_tas: list) -> bool:
        return any(self.trusted(src.name, dst.name)
                   for src in source_tas for dst in destination_tas)

    def sign_message(self, sender_ta, payload: dict) -> dict:
        body = canonical_json(payload)
        return {
            "sender": sender_ta.name,
            "payload": payload,
            "signature": sign(sender_ta.signing_private_key, body),
        }

    def verify_message(self, message: dict, known_tas: dict) -> bool:
        sender = known_tas.get(message.get("sender"))
        if sender is None or not isinstance(message.get("payload"), dict):
            return False
        return verify(sender.signing_public_key,
                      canonical_json(message["payload"]),
                      message.get("signature", b""))

    def select_ta(self, tas: list, weights: dict, source_tas: list | None = None):
        candidates = []
        for ta in tas:
            if not ta.operational or ta.availability <= 0 or ta.active >= ta.capacity:
                continue
            if source_tas:
                if not any(self.trusted(source.name, ta.name) for source in source_tas):
                    continue
            score = (
                weights["capacity"] * (1 - ta.load)
                + weights["availability"] * ta.availability
                + weights["reliability"] * ta.reliability
                + weights["delay"] * ta.delay_score
            )
            candidates.append((score, ta.name, ta))
        if not candidates:
            raise RuntimeError("No eligible trusted Regional TA is available")
        return max(candidates, key=lambda item: (item[0], item[1]))[2]

    def audit(self, event: str, **fields):
        self.audit_log.append({"timestamp": time.time(), "event": event, **fields})
