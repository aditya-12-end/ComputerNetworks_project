import hashlib
import json
import os
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def generate_signing_keypair():
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def generate_agreement_keypair():
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def public_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message)


def verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def derive_session_key(private_key: X25519PrivateKey,
                       peer_public_key: X25519PublicKey,
                       transcript: bytes,
                       key_bytes: int = 32) -> bytes:
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=key_bytes,
        salt=hashlib.sha256(transcript).digest(),
        info=b"HF-SELAP/session-key/v1",
    ).derive(shared_secret)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    return {"nonce": nonce, "ciphertext": AESGCM(key).encrypt(nonce, plaintext, aad)}


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise PermissionError("Encrypted message authentication failed") from exc
