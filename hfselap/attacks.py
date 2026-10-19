"""Executable attack scenarios against HF-SELAP (Dolev-Yao + capture adversary).

Each scenario builds a fresh federation, mounts one attack through the
message tap / direct handler calls, and reports what the protocol did.
Both ``tests/test_security.py`` and ``experiments/exp_security.py`` use these
functions, so the security table in the report is produced by the same code
that the unit tests check.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass

from . import certificateless as cl
from .config import Config
from .entities import AuthError, LoginError
from .federation import LinkError
from .messages import CT_LEN, INTER_HEADER, REVOKE, ProtocolMessage, vehicle_proof_input
from .primitives import AeadParams, encode_ts, h, rand, seal
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
    real_tid = s.vehicles["V1"].card.tid                   # observed in a previous Msg1
    forged = ProtocolMessage(1, rand(CT_LEN[1]), rand(16), encode_ts(s.clock.now_ms()), real_tid)
    try:
        s.root.tas["RTA-1"].handle_msg1(forged, 96)
        return AttackOutcome("Vehicle impersonation", "TA", "PID_V/N_VR2-bound key", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Vehicle impersonation (valid TID, forged ciphertext)", "TA",
                             "key needs PID_V and N_VR2", True, str(e))


def ta_impersonation() -> AttackOutcome:
    s = world()
    u = s.uavs["U1"]
    forged = ProtocolMessage(2, rand(CT_LEN[2]), rand(16), encode_ts(s.clock.now_ms()))
    try:
        u.respond(forged, 95)
        return AttackOutcome("TA impersonation towards the UAV", "UAV", "PID_U/C_U-bound key", False, "accepted")
    except AuthError as e:
        return AttackOutcome("TA impersonation towards the UAV", "UAV",
                             "key needs PID_U and C_U", True, str(e))


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


def vehicle_signature_forgery() -> AttackOutcome:
    """The adversary holds the vehicle's symmetric credentials (PID_V, N_VR2, TID_V),
    e.g. leaked from a compromised TA database, but not its private key SK_V."""
    s = world()
    v, u, ta = s.vehicles["V1"], s.uavs["U1"], s.root.tas["RTA-1"]
    n_vr1, n_vr2 = v._creds
    pid = h(v.id_v, n_vr1)
    t1 = encode_ts(s.clock.now_ms())
    n_a1 = rand()
    fake_key = cl.signer(cl.random_scalar().to_bytes(32, "big"))
    sigma = cl.sign(fake_key, vehicle_proof_input(v.card.tid, n_a1, u.id_u, ta.ident, t1))
    c, tag = seal(AeadParams(h(pid, n_vr2, t1)), n_a1 + u.id_u + sigma)
    try:
        ta.handle_msg1(ProtocolMessage(1, c, tag, t1, v.card.tid), 92)
        return AttackOutcome("Vehicle impersonation with leaked symmetric credentials",
                             "TA", "certificateless signature", False, "accepted")
    except AuthError as e:
        return AttackOutcome("Vehicle impersonation with leaked symmetric credentials "
                             "(no SK_V)", "TA", "certificateless signature sigma_V", True, str(e))


def uav_signature_forgery() -> AttackOutcome:
    """A rogue UAV copies the genuine UAV's symmetric credentials (N_UR1, C_U) but signs
    with a key of its own, because SK_U never leaves the genuine UAV's smart card."""
    s = world()
    u = s.uavs["U1"]
    rogue = copy.copy(u)
    rogue.session_keys, rogue.seen_tags = {}, {}
    rogue._signer = cl.signer(cl.random_scalar().to_bytes(32, "big"))
    r = s.authenticate(s.vehicles["V1"], rogue)
    return AttackOutcome("UAV impersonation with copied symmetric credentials (no SK_U)",
                         "TA", "certificateless signature sigma_U", not r.ok,
                         r.reason or "accepted")


def public_key_replacement() -> AttackOutcome:
    """Type-I adversary: replaces the UAV's public key PK_U = (X_U, R_U) with values it
    chose, trying to cancel the h*P_pub term so that it knows the matching key."""
    s = world()
    u, ta = s.uavs["U1"], s.root.tas["RTA-1"]
    kgc = s.root.kgc.public
    rec = ta.uavs[u.id_u]
    x_new, x_pub = cl.new_secret_value()
    r_guess = cl.random_scalar()
    h_guess = cl.h1(u.id_u, x_pub, cl.encode_point(cl.base_mult(r_guess)), kgc)
    # R' = r'G - h_guess*P_pub, hoping that Q' = X' + R' + h*P_pub = (x' + r')G
    r_pub = cl.encode_point(cl.point_add(cl.base_mult(r_guess),
                                         cl.point_neg(kgc.mult(h_guess))))
    rec.pk = cl.verification_key(u.id_u, x_pub, r_pub, kgc)        # registry now holds PK'
    rec.verifier = None
    rogue = copy.copy(u)
    rogue.session_keys, rogue.seen_tags = {}, {}
    rogue._signer = cl.signer(((x_new + r_guess) % cl.N).to_bytes(32, "big"))
    r = s.authenticate(s.vehicles["V1"], rogue, ta="RTA-1")
    return AttackOutcome("Public-key replacement (Type-I certificateless adversary)", "TA",
                         "X_U and R_U bound into h_U = H1(ID_U || X_U || R_U || P_pub)",
                         not r.ok, r.reason or "accepted")


def malicious_kgc() -> AttackOutcome:
    """Type-II adversary: the KGC knows the partial private key D_U it issued (and the
    master secret) but not the UAV's secret value x_U."""
    s = world()
    captured = {}
    issue = s.root.issue_partial_key

    def logging_kgc(ta, ident, x_pub):
        r_pub, d = issue(ta, ident, x_pub)
        captured[ident] = d
        return r_pub, d

    s.root.issue_partial_key = logging_kgc
    u = s.register_uav("U-target", "Region-A", password=b"target-pass")
    u.login()
    rogue = copy.copy(u)
    rogue.session_keys, rogue.seen_tags = {}, {}
    rogue._signer = cl.signer(captured[u.id_u].to_bytes(32, "big"))
    r = s.authenticate(s.vehicles["V1"], rogue)
    return AttackOutcome("Malicious KGC signs with the partial key D_U (Type-II adversary)",
                         "TA", "full key SK_U = x_U + D_U needs the UAV's secret value",
                         not r.ok, r.reason or "accepted")


def forged_partial_key() -> AttackOutcome:
    """A forged or corrupted partial private key is delivered during enrolment."""
    s = world()
    issue = s.root.issue_partial_key
    s.root.issue_partial_key = lambda ta, ident, x_pub: (lambda r, d: (r, (d + 1) % cl.N))(
        *issue(ta, ident, x_pub))
    try:
        s.register_vehicle("V-forged", "Region-A")
        return AttackOutcome("Forged partial private key at enrolment", "vehicle",
                             "partial-key validation", False, "accepted")
    except cl.EnrolmentError as e:
        return AttackOutcome("Forged partial private key at enrolment", "vehicle",
                             "check D*G = R + h*P_pub before use", True, str(e))


def msg1_redirect_to_other_rta() -> AttackOutcome:
    """A Msg1 captured on its way to RTA-1 is replayed to RTA-2 within Delta T."""
    s = world()
    cap = {}
    s.authenticate(s.vehicles["V1"], s.uavs["U1"], ta="RTA-1", tap=_record(cap))
    ta2 = s.root.tas["RTA-2"]
    try:
        s.run_ta_step(ta2, ta2.handle_msg1, ProtocolMessage.from_bytes(1, cap["msg1"]), 91)
        return AttackOutcome("Msg1 replayed to a different RTA", "RTA-2", "ID_TA binding",
                             False, "accepted")
    except AuthError as e:
        return AttackOutcome("Msg1 replayed to a different RTA inside Delta T", "RTA-2",
                             "ID_TA signed into sigma_V", True, str(e))


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
    msg = ProtocolMessage(1, rand(CT_LEN[1]), rand(16), encode_ts(s.clock.now_ms()), rand(16))
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
            vehicle_signature_forgery(), uav_signature_forgery(), public_key_replacement(),
            malicious_kgc(), forged_partial_key(), msg1_redirect_to_other_rta(),
            msg3_substitution(), msg2_replay_to_uav(), desynchronisation(True),
            revoked_vehicle(), revoked_uav(), untrusted_delegation(), forged_inter_ta(),
            old_card_after_reenrolment()]
    return out
