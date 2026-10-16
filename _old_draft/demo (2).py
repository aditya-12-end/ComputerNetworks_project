# HF-SELAP Corrected Reference Implementation

## Run (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python demo.py
python -m unittest discover -s tests -v
```

## Security functions

- Ed25519 entity signatures and signed inter-TA messages.
- X25519 ephemeral key agreement and HKDF-SHA-256 session-key derivation.
- AES-256-GCM authenticated encryption for emergency payloads.
- Configurable TA-selection weights, trust threshold, timestamp tolerance, and pseudonym length.
- Federation trust checks, load-aware TA selection, failover eligibility, revocation, pseudonym refresh, and basic metrics.
- Tests for encryption/tampering, revocation, signed federation-message tampering, untrusted cross-region relationships, and TA failover.

## Limitations you must disclose

This is a local reference simulation, not a production-ready or formally verified HF-SELAP protocol. It creates entity and TA keys in process memory and models the authentication exchange in one Python process. It does not yet run a real vehicle/TA/UAV network protocol, use TLS/mTLS, persist replay/revocation state, implement the paper's exact certificateless cryptosystem, implement ASCON, implement PUF/fuzzy extraction, or provide post-quantum cryptography. X25519 is not post-quantum secure. Before production, implement authenticated enrollment, secure key storage/rotation, durable atomic replay and revocation storage, authenticated network transports, explicit session expiration and lifecycle, rate limiting, and independent cryptographic review.
