"""Wire formats of the four SELAP messages and of HF-SELAP inter-TA messages.

Protocol messages carry exactly the fields of the base protocol, so their
sizes are measured from real serialised bytes:

    Msg1 = {TID_V, C_A1, Tag_A1, T1}   16 + 32 + 16 + 4 = 68 B  (544 bits)
    Msg2 = {C_A3, Tag_A3, T2}          64 + 16 + 4      = 84 B  (672 bits)
    Msg3 = {C_A5, Tag_A5, T3}          32 + 16 + 4      = 52 B  (416 bits)
    Msg4 = {C_A7, Tag_A7, T4}          80 + 16 + 4      = 100 B (800 bits)

Routing information (source, destination, a random per-session handle
``sid``) belongs to the transport layer, as in the base paper, and is kept
in :class:`Envelope` outside the counted protocol payload.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .primitives import NONCE, TAG, TS

CT_LEN = {1: 32, 2: 64, 3: 32, 4: 80}       # ciphertext length per message


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


# --------------------------------------------------------- inter-TA messages
# Header: sender id (2 B) | receiver id (2 B) | type (1 B) | sequence (4 B) | T (4 B)
INTER_HEADER = struct.Struct(">HHBI4s")

FETCH_VEHICLE, FETCH_UAV, RECORD_VEHICLE, RECORD_UAV, TID_SYNC, REVOKE, HEARTBEAT, \
    DEPOSIT_VEHICLE, DEPOSIT_UAV, NACK = range(1, 11)

# Fixed-size record encodings shared by root and regional TAs
VEHICLE_RECORD = struct.Struct(">16s16s16s16s32sHI")   # handle, tid_o, tid_c, n_vr2, pid, home, ver
UAV_RECORD = struct.Struct(">16s16s32s16sH")            # handle, id_u, pid, c_u, home
TID_SYNC_BODY = struct.Struct(">16s16s16sI")            # handle, tid_o, tid_c, version
