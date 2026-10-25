"""Endpoint traces for presence keys: keys in the grants a device issues, rotation, re-granting, rotation chains and the
grantee's held keys (P§12.3–P§12.5; spec-gaps 157, 159, 161; impl/vectors/README.md "Endpoint presence keys").

Expectations are authored from those rules, not recorded from an engine.
"""
from __future__ import annotations

from .. import fixtures as F
from .common import NOW, uid
from .presence_sealed import did_key_secret, tag
from .state import ALICE, ALICE_SELF, APH, BLA, BOB, BOBPH_SELF, IDENTITIES, S, UI, msg, trace

CAR, CAROL = F.did("carol-phone"), F.did("carol")
DPH, DAVE = F.did("dave-phone"), F.did("dave")
FAMILY = tag(did_key_secret("bob"), BOB, "family")
YEAR = NOW + 31_536_000
REFS = ["P§12.3", "P§12.5", "§19.4"]


def intro(label: str, frm: str, at: int = NOW) -> dict:
    return {"type": "introduction", "id": uid(label, at), "from": frm, "to": BOB, "purpose": "Met at the meetup."}


def keys(epochs=None, due=None, chains=None, held=None) -> dict:
    return {"epochs": epochs or {}, "due": due or {}, "chains": chains or {}, "held": held or {}}


def st(event, emit, presence_keys=None, grants_issued=None) -> dict:
    s = {"event": event, "expect": {"emit": emit, "sessions": {}}}
    if presence_keys is not None:
        s["expect"]["presence_keys"] = presence_keys
    if grants_issued is not None:
        s["expect"]["contacts"] = {"allow": [], "grants_issued": sorted(grants_issued), "grants_held": [], "requests": [],
                                   "pending_sent": []}
    return s


def ktrace(vid: str, desc: str, steps: list, presence_keys: dict | None, self_=BOBPH_SELF) -> dict:
    v = trace(vid, desc, REFS, self_, steps)
    v["context"]["identities"] = IDENTITIES | {DPH: DAVE}
    if presence_keys is not None:
        v["context"]["presence_keys"] = presence_keys
    return v


def grant_sent(to, session, gid, scope, valid_until=YEAR, audience=None, kids=None):
    return S(type="grant", to=to, session=session, id=gid, scope=scope, valid_until=valid_until,
             presence_audience=audience, presence_keys=kids)


def granting(label, frm, identity, gid, scope, at=NOW, valid_until=YEAR, audience=None, kids=None) -> list:
    """An introduction arrives and is granted."""
    i = intro(label, frm, at)
    ev = {"local": "grant", "introduction": i["id"], "id": gid, "scope": scope, "valid_until": valid_until}
    if audience is not None:
        ev["presence_audience"] = audience
    return [st({"recv": i}, [UI("introduction_received", **{"from": identity})]),
            st(ev, [grant_sent(identity, i["id"], gid, scope, valid_until, audience, kids)])]


def rotated(scope, epoch):
    return {"keys": "rotated", "scope": scope, "epoch": epoch}


def seen(scope, epoch):
    return {"keys": "seen", "scope": scope, "epoch": epoch}


def record(frm, subject, kid=None, at=NOW):
    m = msg("presence", f"rec-{frm[-6:]}-{kid}", frm, None, at, subject=subject, device=frm)
    if kid is not None:
        m["kid"] = kid
    return m


def vectors() -> list[dict]:
    out = []
    SUB, INV_SUB, INV = ["dsip.subscribe"], ["dsip.invite", "dsip.subscribe"], ["dsip.invite"]
    F0 = f"{FAMILY}.0"

    # ---------------------------------------------------------------- P§12.3
    G1, G2, G3 = uid("pk-g1", NOW + 1), uid("pk-g2", NOW + 2), uid("pk-g3", NOW + 3)
    out.append(ktrace("presence-keys-in-grants",
                      "P§12.3: a grant that admits presence carries the keys of main and its audience at the current epochs, "
                      "when either is sealed; a grant for calls only carries none.", [
        *granting("pk-i1", CAR, CAROL, G1, INV_SUB, kids=["main.0"]),
        *granting("pk-i2", APH, ALICE, G2, SUB, audience=FAMILY, kids=["main.0", F0]),
        *granting("pk-i3", DPH, DAVE, G3, INV),
        st({"advance": 1}, [], keys({"main": 0, FAMILY: 0}), [G1, G2, G3]),
    ], {"sealed": ["main", FAMILY]}))

    out.append(ktrace("presence-keys-only-for-sealed-scopes",
                      "P§12.3, P§12.6: sealing is chosen per audience. With only the family audience sealed, a grant with no "
                      "audience, or another audience, carries no keys; a family grant carries main's key too.", [
        *granting("pk-i1", CAR, CAROL, G1, SUB),
        *granting("pk-i2", DPH, DAVE, G2, SUB, audience="work"),
        *granting("pk-i3", APH, ALICE, G3, SUB, audience=FAMILY, kids=["main.0", F0]),
        st({"local": "revoke", "grant": G1}, [{"revoke": [G1]}], keys({"main": 0, FAMILY: 0})),
        st({"local": "revoke", "grant": G2}, [{"revoke": [G2]}], keys({"main": 0, FAMILY: 0})),
    ], {"sealed": [FAMILY]}))

    # ---------------------------------------------------------------- P§12.5 rotation on revocation, chains
    R1, R2, R3 = uid("pk-r1", NOW + 50), uid("pk-r2", NOW + 51), uid("pk-r3", NOW + 52)
    G4 = uid("pk-g4", NOW + 15)
    out.append(ktrace("presence-keys-revocation-rotates",
                      "P§12.5: revoking a grant that carried keys rotates its scopes, the first time at once, then at most "
                      "once per T-Presence-Rotate (60 s); every live grant carrying a rotated key is re-granted, once, and the "
                      "grant it follows heads its chain without being revoked (spec-gap 159). Ending a share revokes the "
                      "grant and its whole chain, newest first.", [
        *granting("pk-i1", CAR, CAROL, G1, SUB, kids=["main.0"]),
        *granting("pk-i2", APH, ALICE, G2, SUB, audience=FAMILY, kids=["main.0", F0]),
        *granting("pk-i3", DPH, DAVE, G3, SUB, kids=["main.0"]),
        st({"local": "revoke", "grant": G1},
           [{"revoke": [G1]}, rotated("main", 1),
            grant_sent(ALICE, G2, R1, SUB, audience=FAMILY, kids=["main.1", F0]),
            grant_sent(DAVE, G3, R2, SUB, kids=["main.1"])],
           keys({"main": 1, FAMILY: 0}, chains={R1: [G2], R2: [G3]}), [R1, R2]),
        st({"advance": 10}, []),
        st({"local": "revoke", "grant": R1}, [{"revoke": [R1, G2]}, rotated(FAMILY, 1)],
           keys({"main": 1, FAMILY: 1}, {"main": NOW + 60}, {R2: [G3]}), [R2]),
        *[s for s in granting("pk-i4", CAR, CAROL, G4, SUB, at=NOW + 15, kids=["main.1"])],
        st({"advance": 10}, []),
        st({"local": "revoke", "grant": G4}, [{"revoke": [G4]}],
           keys({"main": 1, FAMILY: 1}, {"main": NOW + 60}, {R2: [G3]}), [R2]),
        st({"advance": 39}, [], keys({"main": 1, FAMILY: 1}, {"main": NOW + 60}, {R2: [G3]})),
        st({"advance": 1}, [rotated("main", 2), grant_sent(DAVE, R2, R3, SUB, kids=["main.2"])],
           keys({"main": 2, FAMILY: 1}, chains={R3: [R2, G3]}), [R3]),
        st({"local": "revoke", "grant": R3}, [{"revoke": [R3, R2, G3]}],
           keys({"main": 2, FAMILY: 1}, {"main": NOW + 120}), []),
        st({"advance": 60}, [rotated("main", 3)], keys({"main": 3, FAMILY: 1}), []),
    ], {"sealed": ["main", FAMILY], "grant_ids": [R1, R2, R3]}))

    # ---------------------------------------------------------------- P§12.5 rotation at valid_until
    out.append(ktrace("presence-keys-valid-until-rotates",
                      "P§12.5: a share that reaches its valid_until ends, and its scopes rotate then (spec-gap 141: at that "
                      "instant, not a second later); revoking it afterwards revokes it again at the authority but rotates "
                      "nothing more. With T-Presence-Rotate 0 every ending rotates at once.", [
        *granting("pk-i1", CAR, CAROL, G1, SUB, valid_until=NOW + 100, kids=["main.0"]),
        *granting("pk-i2", APH, ALICE, G2, SUB, kids=["main.0"]),
        st({"advance": 99}, [], keys({"main": 0})),
        st({"advance": 1}, [rotated("main", 1), grant_sent(ALICE, G2, R1, SUB, kids=["main.1"])],
           keys({"main": 1}, chains={R1: [G2]}), [G1, R1]),
        st({"local": "revoke", "grant": G1}, [{"revoke": [G1]}], keys({"main": 1}, chains={R1: [G2]}), [R1]),
        st({"local": "revoke", "grant": R1}, [{"revoke": [R1, G2]}, rotated("main", 2)], keys({"main": 2}), []),
    ], {"sealed": ["main"], "t_rotate": 0, "grant_ids": [R1]}))

    out.append(ktrace("presence-keys-rotate-interval-clamped",
                      "P§8: T-Presence-Rotate is bounded 0–3,600 s; 9,999 is taken as 3,600.", [
        *granting("pk-i1", CAR, CAROL, G1, SUB, kids=["main.0"]),
        *granting("pk-i2", APH, ALICE, G2, SUB, kids=["main.0"]),
        st({"local": "revoke", "grant": G1}, [{"revoke": [G1]}, rotated("main", 1),
                                              grant_sent(ALICE, G2, R1, SUB, kids=["main.1"])]),
        st({"advance": 1}, []),
        st({"local": "revoke", "grant": R1}, [{"revoke": [R1, G2]}], keys({"main": 1}, {"main": NOW + 3600})),
        st({"advance": 3598}, []),
        st({"advance": 1}, [rotated("main", 2)], keys({"main": 2})),
    ], {"sealed": ["main"], "t_rotate": 9999, "grant_ids": [R1]}))

    # ---------------------------------------------------------------- spec-gap 161: changing a share
    G5, G6, G7 = uid("pk-g5", NOW + 5), uid("pk-g6", NOW + 6), uid("pk-g7", NOW + 7)
    out.append(ktrace("presence-keys-changed-share-rotates-what-is-lost",
                      "P§12.5 (spec-gap 161): a share changed by a following grant revokes the old grant and its chain "
                      "(spec-gap 159), and rotates only the scopes the new grant does not carry: leaving the family audience "
                      "rotates family, calls only rotates main, a new length rotates nothing.", [
        *granting("pk-i1", APH, ALICE, G1, INV_SUB, audience=FAMILY, kids=["main.0", F0]),
        *granting("pk-i2", CAR, CAROL, G2, SUB, kids=["main.0"]),
        st({"local": "regrant", "grant": G1, "id": G5, "scope": INV_SUB, "valid_until": YEAR},
           [{"revoke": [G1]}, grant_sent(ALICE, G1, G5, INV_SUB, kids=["main.0"]), rotated(FAMILY, 1)],
           keys({"main": 0, FAMILY: 1}), [G2, G5]),
        st({"local": "regrant", "grant": G5, "id": G6, "scope": INV, "valid_until": YEAR},
           [{"revoke": [G5]}, grant_sent(ALICE, G5, G6, INV), rotated("main", 1),
            grant_sent(CAROL, G2, R1, SUB, kids=["main.1"])],
           keys({"main": 1, FAMILY: 1}, chains={R1: [G2]}), [G6, R1]),
        st({"local": "regrant", "grant": R1, "id": G7, "scope": SUB, "valid_until": NOW + 3600},
           [{"revoke": [R1, G2]}, grant_sent(CAROL, R1, G7, SUB, NOW + 3600, kids=["main.1"])],
           keys({"main": 1, FAMILY: 1}), [G6, G7]),
    ], {"sealed": ["main", FAMILY], "grant_ids": [R1]}))

    # ---------------------------------------------------------------- P§12.5: a sibling's epoch
    OTHER = tag(did_key_secret("bob"), BOB, "work")
    out.append(ktrace("presence-keys-sibling-epoch",
                      "P§12.5: a record of our own identity from a sibling device, seen through our own watch, with an epoch "
                      "above ours: the epoch is adopted and our live grants carrying that scope are re-granted. Seeing is not "
                      "rotating: a scope waiting for T-Presence-Rotate still rotates then, above the epoch seen.", [
        *granting("pk-i1", APH, ALICE, G1, SUB, audience=FAMILY, kids=["main.0", F0]),
        *granting("pk-i2", CAR, CAROL, G2, SUB, kids=["main.0"]),
        st({"recv": record(BLA, BOB, "main.0")}, [], keys({"main": 0, FAMILY: 0})),
        st({"recv": record(BLA, BOB, f"{FAMILY}.2")},
           [seen(FAMILY, 2), grant_sent(ALICE, G1, R1, SUB, audience=FAMILY, kids=["main.0", f"{FAMILY}.2"])],
           keys({"main": 0, FAMILY: 2}, chains={R1: [G1]}), [G2, R1]),
        st({"recv": record(APH, ALICE, "main.5")}, [], keys({"main": 0, FAMILY: 2}, chains={R1: [G1]})),
        st({"recv": record(BLA, BOB)}, []),
        st({"recv": record(BLA, BOB, f"{OTHER}.0")}, [seen(OTHER, 0)],
           keys({"main": 0, FAMILY: 2, OTHER: 0}, chains={R1: [G1]})),
        st({"local": "revoke", "grant": G2},
           [{"revoke": [G2]}, rotated("main", 1), grant_sent(ALICE, R1, R2, SUB, audience=FAMILY, kids=["main.1", f"{FAMILY}.2"])],
           keys({"main": 1, FAMILY: 2, OTHER: 0}, chains={R2: [R1, G1]}), [R2]),
        st({"advance": 1}, []),
        st({"recv": record(BLA, BOB, "main.4", NOW + 1)},
           [seen("main", 4), grant_sent(ALICE, R2, R3, SUB, audience=FAMILY, kids=["main.4", f"{FAMILY}.2"])],
           keys({"main": 4, FAMILY: 2, OTHER: 0}, chains={R3: [R2, R1, G1]}), [R3]),
        st({"advance": 1}, []),
        st({"local": "revoke", "grant": R3}, [{"revoke": [R3, R2, R1, G1]}, rotated(FAMILY, 3)],
           keys({"main": 4, FAMILY: 3, OTHER: 0}, {"main": NOW + 60}), []),
        st({"advance": 58}, [rotated("main", 5)], keys({"main": 5, FAMILY: 3, OTHER: 0})),
    ], {"sealed": ["main", FAMILY], "grant_ids": [R1, R2, R3]}))

    # ---------------------------------------------------------------- P§12.4: the grantee's side
    I = uid("pk-intro-a", NOW)
    H1, H2, H3, H4 = (uid(f"pk-h{n}", NOW + n) for n in (1, 2, 3, 4))
    BOBPH = F.did("bob-phone")

    def grant_in(gid, session, kids, at):
        return {"recv": msg("grant", "unused", BOBPH, session, at, id=gid, scope=SUB, valid_until=YEAR, presence_keys=kids)
                | {"id": gid}}

    out.append(ktrace("presence-keys-held-two-epochs",
                      "P§12.4: a grantee keeps, per scope, the keys of the two highest epochs its grants from that identity "
                      "carried; a grant it cannot place (an unknown introduction) adds none. It needs no presence key "
                      "context of its own.", [
        st({"local": "introduce", "id": I, "to": BOB, "purpose": "Met at the meetup."},
           [S(type="introduction", to=BOB, id=I, purpose="Met at the meetup.")]),
        st(grant_in(H1, I, ["main.0", F0], NOW + 1), [UI("granted", by=BOB)], keys(held={BOB: [F0, "main.0"]})),
        st(grant_in(H2, H1, ["main.1", F0], NOW + 2), [UI("granted", by=BOB)],
           keys(held={BOB: [F0, "main.0", "main.1"]})),
        st(grant_in(H3, H2, ["main.2", f"{FAMILY}.1"], NOW + 3), [UI("granted", by=BOB)],
           keys(held={BOB: [F0, f"{FAMILY}.1", "main.1", "main.2"]})),
        st(grant_in(H4, uid("pk-nowhere", NOW), ["main.9"], NOW + 4), [{"drop": "unknown-introduction"}],
           keys(held={BOB: [F0, f"{FAMILY}.1", "main.1", "main.2"]})),
    ], None, self_=ALICE_SELF))

    # ---------------------------------------------------------------- off
    out.append(ktrace("presence-keys-off",
                      "Without presence keys the endpoint seals nothing: a presence grant carries no keys, a revocation "
                      "rotates nothing, and a record of our own identity is ignored.", [
        *granting("pk-i1", CAR, CAROL, G1, SUB),
        st({"recv": record(BLA, BOB, "main.3")}, [], keys()),
        st({"local": "revoke", "grant": G1}, [{"revoke": [G1]}], keys(), []),
    ], None))
    return out
