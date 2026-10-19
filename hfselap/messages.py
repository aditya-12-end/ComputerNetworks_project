"""Wire formats of the four HF-SELAP messages and of the inter-TA messages.

The radio messages keep SELAP's structure; the ASCON-protected payloads also
carry the certificateless signatures and the serving-TA identity, so their sizes
are measured from real serialised bytes:

    Msg1 = {TID_V, C_A1, Tag_A1, T1}   16 + 96 + 16 + 4 = 132 B (1056 bits)
           C_A1 = Enc(N_A1 || ID_U || sigma_V)
    Msg2 = {C_A3, Tag_A3, T2}          80 + 16 + 4      = 100 B  (800 bits)
           C_A3 = Enc(N_A1 || N_A2 || M_A3 || ID_TA)
    Msg3 = {C_A5, Tag_A5, T3}          96 + 16 + 4      = 116 B  (928 bits)
           C_A5 = Enc(N_A3 || SKV || sigma_U)
    Msg4 = {C_A7, Tag_A7, T4}          80 + 16 + 4      = 100 B  (800 bits)
           C_A7 = Enc(N_A2 || N_A3 || M_A9 || SKV)

The signatures travel inside the ciphertext, so an eavesdropper who knows an
entity's public key still cannot link its sessions.  Routing information
(source, destination, a random per-session handle ``sid``) belongs to the
transport layer, as in the base paper, and is kept in :class:`Envelope`
outside the counted protocol payload.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .primitives import NONCE, TAG, TS

CT_LEN = {1: 96, 2: 80, 3: 96, 4: 80}       # ciphertext length per message


class MalformedMessage(Exception):
    pass


@dataclass
class ProtocolMessage:
    kind: int                 # 1..4
    c: bytes
    tag: bytes
    t: bytes
    tid: bytes = b""          # only Msg1 carries TID_V

    def to_bytes(self) -> bytes:
        return (self.tid if self.kind == 1 else b"") + self.c + self.tag + self.t

    @classmethod
    def from_bytes(cls, kind: int, raw: bytes) -> "ProtocolMessage":
        ct = CT_LEN.get(kind)
        if ct is None:
            raise MalformedMessage("unknown message kind")
        expected = (NONCE if kind == 1 else 0) + ct + TAG + TS
        if len(raw) != expected:
            raise MalformedMessage(f"Msg{kind} must be {expected} bytes, got {len(raw)}")
        off = 0
        tid = b""
        if kind == 1:
            tid, off = raw[:NONCE], NONCE
        c = raw[off:off + ct]
        tag = raw[off + ct:off + ct + TAG]
        t = raw[off + ct + TAG:]
        return cls(kind, c, tag, t, tid)

    @property
    def bits(self) -> int:
        return len(self.to_bytes()) * 8


@dataclass
class Envelope:
    """Transport wrapper: who sends to whom, and the session routing handle."""
    src: str
    dst: str
    sid: int
    kind: int
    payload: bytes


# ------------------------------------------ inputs of the authentication proofs
def vehicle_proof_input(tid: bytes, n_a1: bytes, id_u: bytes, ta_id: bytes, t1: bytes) -> bytes:
    """M_V signed by the vehicle: binds the request to its TID, UAV, serving RTA and time."""
    return b"HF-SELAP/V" + tid + n_a1 + id_u + ta_id + t1


def uav_proof_input(id_u: bytes, n_a1: bytes, n_a2: bytes, n_a3: bytes, skv: bytes,
                    ta_id: bytes, t3: bytes) -> bytes:
    """M_U signed by the UAV: binds its answer to this session and to the key verifier."""
    return b"HF-SELAP/U" + id_u + n_a1 + n_a2 + n_a3 + skv + ta_id + t3


# --------------------------------------------------------- inter-TA messages
# Header: sender id (2 B) | receiver id (2 B) | type (1 B) | sequence (4 B) | T (4 B)
INTER_HEADER = struct.Struct(">HHBI4s")

FETCH_VEHICLE, FETCH_UAV, RECORD_VEHICLE, RECORD_UAV, TID_SYNC, REVOKE, HEARTBEAT, \
    DEPOSIT_VEHICLE, DEPOSIT_UAV, NACK, PARTIAL_KEY_REQUEST, PARTIAL_KEY = range(1, 13)

# Fixed-size record encodings shared by root and regional TAs.  Q is the
# entity's certificateless verification key (33-byte compressed point).
VEHICLE_RECORD = struct.Struct(">16s16s16s16s32s33sHI")   # handle, tid_o, tid_c, n_vr2, pid, Q, home, ver
UAV_RECORD = struct.Struct(">16s16s32s16s33sH")            # handle, id_u, pid, c_u, Q, home
TID_SYNC_BODY = struct.Struct(">16s16s16sI")               # handle, tid_o, tid_c, version
