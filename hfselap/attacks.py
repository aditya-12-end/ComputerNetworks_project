"""Executable attack scenarios against HF-SELAP (Dolev-Yao + capture adversary).

Each scenario builds a fresh federation, mounts one attack through the
message tap / direct handler calls, and reports what the protocol did.
Both ``tests/test_security.py`` and ``experiments/exp_security.py`` use these
functions, so the security table in the report is produced by the same code
that the unit tests check.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .config import Config
from .entities import AuthError, LoginError, UAV
from .federation import LinkError
from .messages import INTER_HEADER, REVOKE, ProtocolMessage
from .primitives import rand
from .puf import ArbiterPUF
from .system import HFSELAP


@dataclass
class AttackOutcome:
    attack: str
    target: str
    defence: str
    blocked: bool
    observed: str


def world(seed: int = 7, **protocol_overrides) -> HFSELAP:
    cfg = Config()
    for k, v in protocol_overrides.items():
        setattr(cfg.protocol, k, v)
    s = HFSELAP(cfg, seed=seed)
    s.add_ta("RTA-1", "Region-A")
    s.add_ta("RTA-2", "Region-B")
    s.trust("RTA-1", "RTA-2", 0.9)
    s.register_vehicle("V1", "Region-A", password=b"vehicle-pass")
    s.register_vehicle("V2", "Region-A", password=b"second-pass")
    s.register_uav("U1", "Region-A", password=b"uav-pass")
    s.register_uav("U2", "Region-B", password=b"uav2-pass")
    for e in list(s.vehicles.values()) + list(s.uavs.values()):
        e.login()
    return s


def _flip(raw: bytes, index: int) -> bytes:
    b = bytearray(raw)
    b[index] ^= 0x01
    return bytes(b)


def _record(store: dict):
    def tap(stage, raw):
        store[stage] = raw
        return raw
    return tap


# ---------------------------------------------------------------- scenarios
def eavesdropping() -> AttackOutcome:
    s = world()
    v, u = s.vehicles["V1"], s.uavs["U1"]
    r1, r2 = s.authenticate(v, u), s.authenticate(v, u)
    wire = b"".join(r1.transcript.values()) + b"".join(r2.transcript.values())
    leaked = r1.sk_vehicle in wire or r2.sk_vehicle in wire or v.id_v in wire or u.id_u in wire
    linkable = r1.transcript["msg1"][:16] == r2.transcript["msg1"][:16]
    ok = r1.ok and r2.ok and not leaked and not linkable and r1.sk_vehicle != r2.sk_vehicle
    return AttackOutcome("Passive eavesdropping / traceability", "all messages",
                         "ASCON confidentiality, TID rotation, fresh nonces", ok,
                         "no key or real ID on the wire; TID differs per session" if ok
                         else "information leaked or sessions linkable")


def replay_msg1_within_window() -> AttackOutcome:
    s = world()
    cap = {}
    s.authenticate(s.vehicles["V1"], s.uavs["U1"], tap=_record(cap))
    ta = s.root.tas["RTA-1"]
    try:
        ta.handle_msg1(ProtocolMessage.from_bytes(1, cap["msg1"]), 99)
        return AttackOutcome("Replay of Msg1 inside Delta T", "TA", "replay cache", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Replay of Msg1 inside Delta T", "TA", "replay cache (tag seen)", True, str(e))


def replay_msg1_after_window() -> AttackOutcome:
    s = world(replay_cache=False)
    cap = {}
    s.authenticate(s.vehicles["V1"], s.uavs["U1"], tap=_record(cap))
    s.clock.advance(2 * s.cfg.protocol.delta_t_ms)
    try:
        s.root.tas["RTA-1"].handle_msg1(ProtocolMessage.from_bytes(1, cap["msg1"]), 98)
        return AttackOutcome("Replay of Msg1 after Delta T", "TA", "timestamp check", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Replay of Msg1 after Delta T", "TA", "timestamp freshness |T_R - T1| <= Delta T",
                             True, str(e))


def tamper(stage: str) -> AttackOutcome:
    s = world()
    offset = 16 if stage == "msg1" else 0            # flip a ciphertext byte
    r = s.authenticate(s.vehicles["V1"], s.uavs["U1"],
                       tap=lambda st, raw: _flip(raw, offset) if st == stage else raw)
    target = {"msg1": "TA", "msg2": "UAV", "msg3": "TA", "msg4": "vehicle"}[stage]
    return AttackOutcome(f"Modification of {stage.capitalize()}", target, "ASCON tag verification",
                         not r.ok, r.reason or "accepted")


def timestamp_forgery() -> AttackOutcome:
    s = world(replay_cache=False)
    cap = {}
    s.authenticate(s.vehicles["V1"], s.uavs["U1"], tap=_record(cap))
    s.clock.advance(5 * s.cfg.protocol.delta_t_ms)
    old = ProtocolMessage.from_bytes(1, cap["msg1"])
    from .primitives import encode_ts
    forged = ProtocolMessage(1, old.c, old.tag, encode_ts(s.clock.now_ms()), old.tid)
    try:
        s.root.tas["RTA-1"].handle_msg1(forged, 97)
        return AttackOutcome("Timestamp forgery on a replayed Msg1", "TA", "T1 bound into key", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Timestamp forgery on a replayed Msg1", "TA",
                             "T1 is an input of the ASCON key (M_A2)", True, str(e))


def vehicle_impersonation() -> AttackOutcome:
    s = world()
    cap = {}
    s.authenticate(s.vehicles["V1"], s.uavs["U1"], tap=_record(cap))
    from .primitives import encode_ts
    real_tid = s.vehicles["V1"].card.tid                   # observed in a previous Msg1
    forged = ProtocolMessage(1, rand(32), rand(16), encode_ts(s.clock.now_ms()), real_tid)
    try:
        s.root.tas["RTA-1"].handle_msg1(forged, 96)
        return AttackOutcome("Vehicle impersonation", "TA", "PID_V/N_VR2-bound key", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Vehicle impersonation (valid TID, forged ciphertext)", "TA",
                             "key needs PID_V and N_VR2", True, str(e))


def ta_impersonation() -> AttackOutcome:
    s = world()
    u = s.uavs["U1"]
    from .primitives import encode_ts
    forged = ProtocolMessage(2, rand(64), rand(16), encode_ts(s.clock.now_ms()))
    try:
        u.respond(forged, 95)
        return AttackOutcome("TA impersonation towards the UAV", "UAV", "PID_U/C_U-bound key", False, "accepted")
    except AuthError as e:
        return AttackOutcome("TA impersonation towards the UAV", "UAV",
                             "key needs PID_U (PUF-derived) and C_U", True, str(e))


def stolen_smart_card() -> AttackOutcome:
    s = world()
    v = s.vehicles["V1"]
    card = v.card
    guesses = [b"123456", b"password", b"qwerty", b"letmein", b"admin"]
    failures = 0
    for g in guesses:
        try:
            card.login(v.id_v, g)
        except LoginError:
            failures += 1
    try:
        card.login(v.id_v, v.pw)                            # correct password after lockout
        locked = False
    except LoginError:
        locked = True
    ok = failures == len(guesses) and locked
    return AttackOutcome("Stolen smart card + password guessing", "smart card",
                         "password-bound ASCON credential + lockout", ok,
                         f"{failures}/{len(guesses)} guesses rejected; card locked" if ok else "bypassed")


def uav_clone() -> AttackOutcome:
    s = world()
    u = s.uavs["U1"]
    clone = UAV(u.id_u, u.pw, u.card, ArbiterPUF(u.puf.n_bits, s.cfg.protocol.puf_noise_rate,
                                                 np.random.default_rng(123)),
                u.fe, s.clock, s.cfg.protocol, "U1-clone", u.region)
    clone.home_ta, clone.handle = u.home_ta, u.handle
    r = s.authenticate(s.vehicles["V1"], clone)
    return AttackOutcome("UAV cloning (card + password copied, different chip)", "UAV",
                         "PUF-derived PID_U cannot be reproduced", not r.ok, r.reason or "accepted")


def uav_physical_tamper() -> AttackOutcome:
    s = world()
    u = s.uavs["U1"]
    u.puf.tamper()
    r = s.authenticate(s.vehicles["V1"], u)
    return AttackOutcome("Physical capture / invasive tampering of a UAV", "UAV",
                         "tamper-evident PUF", not r.ok, r.reason or "accepted")


def msg3_substitution() -> AttackOutcome:
    s = world()
    old = {}
    s.authenticate(s.vehicles["V1"], s.uavs["U1"], tap=_record(old))
    r = s.authenticate(s.vehicles["V1"], s.uavs["U1"],
                       tap=lambda st, raw: old["msg3"] if st == "msg3" else raw)
    return AttackOutcome("Man-in-the-middle: splice Msg3 from another session", "TA",
                         "session-bound keys (N_A2, T3)", not r.ok, r.reason or "accepted")


def msg2_replay_to_uav() -> AttackOutcome:
    s = world()
    cap = {}
    s.authenticate(s.vehicles["V1"], s.uavs["U1"], tap=_record(cap))
    try:
        s.uavs["U1"].respond(ProtocolMessage.from_bytes(2, cap["msg2"]), 94)
        return AttackOutcome("Replay of Msg2 to the UAV", "UAV", "replay cache", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Replay of Msg2 to the UAV", "UAV", "UAV replay cache", True, str(e))


def desynchronisation(dual_record: bool = True) -> AttackOutcome:
    s = world(dual_record=dual_record)
    v, u = s.vehicles["V1"], s.uavs["U1"]
    blocked = s.authenticate(v, u, tap=lambda st, raw: None if st == "msg4" else raw)
    nxt = s.authenticate(v, u)
    label = "with dual TID records" if dual_record else "WITHOUT dual TID records (ablation)"
    return AttackOutcome(f"Desynchronisation: Msg4 blocked, {label}", "TA/vehicle state",
                         "<TID_o, TID_c> dual record" if dual_record else "none",
                         (not blocked.ok) and nxt.ok,
                         "next session succeeded" if nxt.ok else f"vehicle locked out: {nxt.reason}")


def revoked_vehicle() -> AttackOutcome:
    s = world()
    v, u = s.vehicles["V1"], s.uavs["U1"]
    s.authenticate(v, u, ta="RTA-2")                       # RTA-2 now caches V1's record
    s.revoke(v, "reported stolen")
    r1 = s.authenticate(v, u, ta="RTA-1")
    r2 = s.authenticate(v, u, ta="RTA-2")
    return AttackOutcome("Revoked vehicle tries to authenticate (home and foreign RTA)",
                         "all RTAs", "federated revocation registry", not r1.ok and not r2.ok,
                         f"RTA-1: {r1.reason}; RTA-2: {r2.reason}")


def revoked_uav() -> AttackOutcome:
    s = world()
    s.revoke(s.uavs["U2"], "captured")
    r = s.authenticate(s.vehicles["V1"], s.uavs["U2"])
    return AttackOutcome("Revoked UAV is requested by a vehicle", "RTA", "revocation registry",
                         not r.ok, r.reason or "accepted")


def untrusted_delegation() -> AttackOutcome:
    s = world()
    s.trust("RTA-1", "RTA-2", 0.3)                         # below the 0.6 threshold
    r = s.authenticate(s.vehicles["V1"], s.uavs["U2"], ta="RTA-1")
    return AttackOutcome("Cross-region request through an untrusted RTA", "Root TA",
                         "trust threshold on delegation", not r.ok, r.reason or "accepted")


def forged_inter_ta() -> AttackOutcome:
    s = world()
    ta = s.root.tas["RTA-1"]
    header = INTER_HEADER.pack(0, s.root.ta_ids["RTA-1"], REVOKE, 10**6, b"\x00" * 4)
    forged = header + rand(16) + rand(20) + rand(16)
    try:
        ta.link.open(forged, s.root.ta_ids["RTA-1"])
        forged_ok = False
    except LinkError:
        forged_ok = True
    with_key = ta.link.seal(0, REVOKE, b"x" * 20)
    ta.link.open(with_key, s.root.ta_ids["RTA-1"])
    try:
        ta.link.open(with_key, s.root.ta_ids["RTA-1"])     # replay of a genuine message
        replay_ok = False
    except LinkError:
        replay_ok = True
    return AttackOutcome("Forged / replayed inter-TA control message", "RTA",
                         "ASCON link key + sequence numbers", forged_ok and replay_ok,
                         "forgery and replay rejected" if forged_ok and replay_ok else "accepted")


def unknown_tid() -> AttackOutcome:
    s = world()
    from .primitives import encode_ts
    msg = ProtocolMessage(1, rand(32), rand(16), encode_ts(s.clock.now_ms()), rand(16))
    r = s.run_ta_step
    try:
        r(s.root.tas["RTA-1"], s.root.tas["RTA-1"].handle_msg1, msg, 93)
        return AttackOutcome("Random / guessed TID", "TA", "TID directory", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Random / guessed TID", "TA + Root", "TID directory lookup", True, str(e))


def old_card_after_reenrolment() -> AttackOutcome:
    s = world()
    v, u = s.vehicles["V1"], s.uavs["U1"]
    old_card_tid = v.card.tid
    new_v = s.reenrol_vehicle(v)
    new_v.login()
    v.card.tid = old_card_tid
    old = s.authenticate(v, u)
    new = s.authenticate(new_v, u)
    return AttackOutcome("Old credentials used after recovery / re-enrolment", "RTA",
                         "revocation + fresh credentials", (not old.ok) and new.ok,
                         "old card rejected, re-enrolled vehicle accepted" if (not old.ok and new.ok)
                         else f"old={old.ok} new={new.ok}")


def all_scenarios() -> list[AttackOutcome]:
    out = [eavesdropping(), replay_msg1_within_window(), replay_msg1_after_window(),
           timestamp_forgery()]
    out += [tamper(st) for st in ("msg1", "msg2", "msg3", "msg4")]
    out += [vehicle_impersonation(), ta_impersonation(), unknown_tid(), stolen_smart_card(),
            uav_clone(), uav_physical_tamper(), msg3_substitution(), msg2_replay_to_uav(),
            desynchronisation(True), revoked_vehicle(), revoked_uav(), untrusted_delegation(),
            forged_inter_ta(), old_card_after_reenrolment()]
    return out
