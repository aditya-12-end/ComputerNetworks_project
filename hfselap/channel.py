"""Post-authentication emergency data channel protected by the session key.

After SELAP the vehicle and UAV share SK (256 bits).  Rescue data is then sent
with ASCON-128 under k_data = Trunc128(SHA-256("HF-SELAP-DATA" || SK)), a
96-bit direction label + 32-bit counter as nonce (never reused), and the
sender/receiver roles as associated data.  Replays and reordering are rejected
by the strictly increasing counter.
"""

from __future__ import annotations

import hashlib

from . import ascon


class ChannelError(Exception):
    pass


class SecureDataChannel:
    def __init__(self, session_key: bytes, role: str):
        if role not in {"vehicle", "uav"}:
            raise ValueError("role must be 'vehicle' or 'uav'")
        self.key = hashlib.sha256(b"HF-SELAP-DATA" + session_key).digest()[:16]
        self.role = role
        self.peer = "uav" if role == "vehicle" else "vehicle"
        self.send_ctr = 0
        self.recv_ctr = 0

    @staticmethod
    def _nonce(direction: str, ctr: int) -> bytes:
        return hashlib.sha256(direction.encode()).digest()[:12] + ctr.to_bytes(4, "big")

    def seal(self, plaintext: bytes) -> bytes:
        self.send_ctr += 1
        direction = f"{self.role}->{self.peer}"
        c, tag = ascon.encrypt(self.key, self._nonce(direction, self.send_ctr),
                               direction.encode(), plaintext)
        return self.send_ctr.to_bytes(4, "big") + c + tag

    def open(self, packet: bytes) -> bytes:
        ctr = int.from_bytes(packet[:4], "big")
        if ctr <= self.recv_ctr:
            raise ChannelError("replayed or reordered packet")
        direction = f"{self.peer}->{self.role}"
        try:
            pt = ascon.decrypt(self.key, self._nonce(direction, ctr), direction.encode(),
                               packet[4:-16], packet[-16:])
        except ascon.AsconAuthError:
            raise ChannelError("packet failed authentication") from None
        self.recv_ctr = ctr
        return pt
