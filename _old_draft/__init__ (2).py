import hashlib
import hmac
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field

from .crypto import (
    canonical_json, generate_signing_keypair, generate_agreement_keypair,
    public_bytes, sign, verify, derive_session_key, encrypt, decrypt,
)
from .federation import Federation
from .models import Entity, RegionalTA


@dataclass
class Session:
    session_id: str
    vehicle_pseudonym: str
    uav_pseudonym: str
    ta_name: str
    key: bytes
    created_at: float


@dataclass
class HFSELAP:
    config: object
    federation: Federation
    tas: dict[str, RegionalTA] = field(default_factory=dict)
    entities: dict[str, Entity] = field(default_factory=dict)
    pseudonym_index: dict[str, str] = field(default_factory=dict)
    revoked_ids: set[str] = field(default_factory=set)
    seen_nonces: set[tuple[str, str]] = field(default_factory=set)
    sessions: dict[str, Session] = field(default_factory=dict)
    delays_ms: list[float] = field(default_factory=list)
    message_bytes: list[int] = field(default_factory=list)
    successes: int = 0
    failures: int = 0

    def add_ta(self, name: str, region: str, capacity: int,
               availability: float, reliability: float, delay_ms: float):
        if name in self.tas:
            raise ValueError("TA name already exists")
        private, public = generate_signing_keypair()
        self.tas[name] = RegionalTA(
            name, region, capacity, availability, reliability, delay_ms, private, public
        )

    def register(self, identity: str, kind: str, region: str) -> Entity:
        if not identity or identity in self.entities:
            raise ValueError("Identity must be non-empty and unique")
        if kind not in {"vehicle", "uav"}:
            raise ValueError("Entity kind must be vehicle or uav")
        if not any(ta.region == region for ta in self.tas.values()):
            raise ValueError("No Regional TA is configured for this region")
        private, public = generate_signing_keypair()
        pseudonym = self._new_pseudonym()
        entity = Entity(identity, kind, region, private, public, pseudonym)
        self.entities[identity] = entity
        self.pseudonym_index[pseudonym] = identity
        for ta in self.tas.values():
            if ta.region == region:
                ta.registry[pseudonym] = public
        self.federation.audit("entity_registered", kind=kind, region=region, pseudonym=pseudonym)
        return entity

    def revoke(self, identity: str, reason: str = "unspecified"):
        entity = self.entities.get(identity)
        if entity is None:
            raise KeyError("Unknown entity")
        entity.revoked = True
        self.revoked_ids.add(identity)
        for ta in self.tas.values():
            ta.registry.pop(entity.pseudonym, None)
        self.federation.audit("entity_revoked", pseudonym=entity.pseudonym, reason=reason)

    def reenroll(self, identity: str, region: str):
        if identity not in self.entities:
            raise KeyError("Unknown entity")
        if not any(ta.region == region for ta in self.tas.values()):
            raise ValueError("No Regional TA is configured for that region")
        old = self.entities[identity]
        self.revoke(identity, "credential_rotation")
        self.pseudonym_index.pop(old.pseudonym, None)
        private, public = generate_signing_keypair()
        entity = Entity(identity, old.kind, region, private, public, self._new_pseudonym())
        self.entities[identity] = entity
        self.revoked_ids.discard(identity)
        self.pseudonym_index[entity.pseudonym] = identity
        for ta in self.tas.values():
            if ta.region == region:
                ta.registry[entity.pseudonym] = public
        self.federation.audit("entity_reenrolled", region=region, pseudonym=entity.pseudonym)
        return entity

    def authenticate(self, vehicle_id: str, uav_id: str, source_ta_name: str | None = None) -> Session:
        started = time.perf_counter()
        ta = None
        overhead = 0
        try:
            vehicle = self._active_entity(vehicle_id, "vehicle")
            uav = self._active_entity(uav_id, "uav")
            source_tas = [t for t in self.tas.values() if t.region == vehicle.region]
            destination_tas = [t for t in self.tas.values() if t.region == uav.region]

            if vehicle.region != uav.region:
                if not self.federation.cross_region_allowed(source_tas, destination_tas):
                    raise PermissionError("Cross-region federation trust failed")
            if source_ta_name:
                requested_ta = self.tas.get(source_ta_name)
                if requested_ta is None:
                    raise PermissionError("Unknown source TA")
                if requested_ta.region != vehicle.region and not any(
                    self.federation.trusted(src.name, requested_ta.name) for src in source_tas
                ):
                    raise PermissionError("Requested TA is not trusted by the source region")
                ta = requested_ta
                if not ta.operational or ta.availability <= 0 or ta.active >= ta.capacity:
                    ta = None
            if ta is None:
                if vehicle.region == uav.region:
                    eligible = [t for t in self.tas.values() if t.region == vehicle.region]
                    ta = self.federation.select_ta(eligible, self.config.selection_weights)
                else:
                    eligible = [t for t in destination_tas]
                    ta = self.federation.select_ta(
                        eligible, self.config.selection_weights, source_tas
                    )

            if ta.region != vehicle.region and not any(
                self.federation.trusted(src.name, ta.name) for src in source_tas
            ):
                raise PermissionError("Selected TA is not trusted by vehicle's region")

            ta.active += 1
            ta.total_requests += 1
            now = time.time()
            nonce_v = secrets.token_hex(24)
            nonce_u = secrets.token_hex(24)
            request = {
                "protocol": "HF-SELAP-v1",
                "vehicle_pseudonym": vehicle.pseudonym,
                "uav_pseudonym": uav.pseudonym,
                "vehicle_nonce": nonce_v,
                "uav_nonce": nonce_u,
                "timestamp": now,
                "ta": ta.name,
                "vehicle_region": vehicle.region,
                "uav_region": uav.region,
            }
            request_bytes = canonical_json(request)
            signature_v = sign(vehicle.signing_private_key, request_bytes)
            overhead += len(request_bytes) + len(signature_v)

            registered_vehicle_key = next(
                (authority.registry.get(vehicle.pseudonym)
                 for authority in self.tas.values()
                 if authority.region == vehicle.region and vehicle.pseudonym in authority.registry),
                None,
            )
            if registered_vehicle_key is None or not verify(registered_vehicle_key, request_bytes, signature_v):
                raise PermissionError("Vehicle signature verification failed")
            if abs(time.time() - now) > self.config.timestamp_tolerance_seconds:
                raise PermissionError("Authentication timestamp expired")
            nonce_key = (vehicle.pseudonym, nonce_v)
            if nonce_key in self.seen_nonces:
                raise PermissionError("Replay detected")
            self.seen_nonces.add(nonce_key)

            uav_body = canonical_json({
                "protocol": "HF-SELAP-v1",
                "vehicle_pseudonym": vehicle.pseudonym,
                "uav_pseudonym": uav.pseudonym,
                "vehicle_nonce": nonce_v,
                "uav_nonce": nonce_u,
                "timestamp": now,
                "ta": ta.name,
            })
            signature_u = sign(uav.signing_private_key, uav_body)
            overhead += len(uav_body) + len(signature_u)
            registered_uav_key = next(
                (authority.registry.get(uav.pseudonym)
                 for authority in self.tas.values()
                 if authority.region == uav.region and uav.pseudonym in authority.registry),
                None,
            )
            if registered_uav_key is None or not verify(registered_uav_key, uav_body, signature_u):
                raise PermissionError("UAV signature verification failed")

            vehicle_ephemeral_private, vehicle_ephemeral_public = generate_agreement_keypair()
            uav_ephemeral_private, uav_ephemeral_public = generate_agreement_keypair()
            transcript = (
                request_bytes + signature_v + signature_u
                + public_bytes(vehicle_ephemeral_public)
                + public_bytes(uav_ephemeral_public)
            )
            key_v = derive_session_key(vehicle_ephemeral_private, uav_ephemeral_public, transcript,
                                       self.config.aead_key_bytes)
            key_u = derive_session_key(uav_ephemeral_private, vehicle_ephemeral_public, transcript,
                                       self.config.aead_key_bytes)
            if not hmac.compare_digest(key_v, key_u):
                raise RuntimeError("Session-key agreement failed")

            session_id = str(uuid.uuid4())
            session = Session(session_id, vehicle.pseudonym, uav.pseudonym, ta.name, key_v, now)
            self.sessions[session_id] = session
            self._refresh_pseudonym(vehicle)
            self._refresh_pseudonym(uav)
            self.successes += 1
            self.federation.audit("authentication_success", ta=ta.name, session_id=session_id)
            return session
        except (ValueError, PermissionError, RuntimeError, KeyError):
            self.failures += 1
            raise
        finally:
            if ta is not None and ta.active > 0:
                ta.active -= 1
            self.delays_ms.append((time.perf_counter() - started) * 1000)
            self.message_bytes.append(overhead)

    def encrypt_emergency_data(self, session_id: str, plaintext: bytes) -> dict:
        session = self._get_session(session_id)
        aad = f"{session.session_id}|{session.ta_name}".encode()
        packet = encrypt(session.key, plaintext, aad)
        packet.update({"session_id": session.session_id, "ta": session.ta_name})
        return packet

    def decrypt_emergency_data(self, packet: dict) -> bytes:
        session = self._get_session(packet["session_id"])
        if packet.get("ta") != session.ta_name:
            raise PermissionError("Session TA context mismatch")
        aad = f"{session.session_id}|{session.ta_name}".encode()
        return decrypt(session.key, packet["nonce"], packet["ciphertext"], aad)

    def signed_federation_message(self, ta_name: str, payload: dict) -> dict:
        ta = self.tas.get(ta_name)
        if ta is None or not ta.operational:
            raise PermissionError("Unknown or unavailable TA")
        return self.federation.sign_message(ta, payload)

    def verify_federation_message(self, message: dict) -> bool:
        return self.federation.verify_message(message, self.tas)

    def fail_ta(self, ta_name: str, operational: bool):
        if ta_name not in self.tas:
            raise KeyError("Unknown TA")
        self.tas[ta_name].operational = operational
        self.federation.audit("ta_status_changed", ta=ta_name, operational=operational)

    def _active_entity(self, identity: str, expected_kind: str) -> Entity:
        entity = self.entities.get(identity)
        if entity is None or entity.revoked or identity in self.revoked_ids:
            raise PermissionError("Unknown or revoked entity")
        if entity.kind != expected_kind:
            raise PermissionError(f"Expected a {expected_kind}")
        return entity

    def _get_session(self, session_id: str) -> Session:
        session = self.sessions.get(session_id)
        if session is None:
            raise PermissionError("Unknown session")
        return session

    def _new_pseudonym(self) -> str:
        while True:
            value = "PID-" + secrets.token_hex(self.config.pseudonym_bytes)
            if value not in self.pseudonym_index:
                return value

    def _refresh_pseudonym(self, entity: Entity):
        old = entity.pseudonym
        self.pseudonym_index.pop(old, None)
        for ta in self.tas.values():
            ta.registry.pop(old, None)
        entity.pseudonym = self._new_pseudonym()
        self.pseudonym_index[entity.pseudonym] = entity.identity
        for ta in self.tas.values():
            if ta.region == entity.region:
                ta.registry[entity.pseudonym] = entity.signing_public_key

    def evaluate(self) -> dict:
        counts = [ta.total_requests for ta in self.tas.values()]
        avg = sum(counts) / len(counts) if counts else 0.0
        imbalance = (sum((count - avg) ** 2 for count in counts) / len(counts)) ** 0.5 if counts else 0.0
        return {
            "attempts": self.successes + self.failures,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate_percent": 100 * self.successes / (self.successes + self.failures)
                if self.successes + self.failures else 0.0,
            "mean_protocol_latency_ms": sum(self.delays_ms) / len(self.delays_ms) if self.delays_ms else 0.0,
            "mean_tracked_message_bytes": sum(self.message_bytes) / len(self.message_bytes) if self.message_bytes else 0.0,
            "ta_request_counts": {name: ta.total_requests for name, ta in self.tas.items()},
            "ta_load_imbalance_stddev": imbalance,
        }
