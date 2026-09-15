"""`messaging/` vectors — DSIP Messaging Profile 1.0 (v0.8 draft, cited M§n), tranche 1: message and
object shapes and stateless rules, hub traces and mailbox traces. Expectations are authored by hand
from the profile text; `dsipvec.messaging` and `dsip-messaging` must both reproduce them."""
from __future__ import annotations

import copy

from .. import fixtures as F
from ..crypto import b64url_encode
from .common import NOW, uid, vector, accept, reject

VERSION = {"core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": []}
ALICE, BOB, CAROL, MALLORY = "did:web:alice.example", F.BOB_WEB, "did:web:carol.example", "did:web:mallory.example"
APH, ALA, BPH, BLA = F.did("alice-phone"), F.did("alice-laptop"), F.did("bob-phone"), F.did("bob-laptop")
BTAB, CPH, MPH = "did:key:z6MkBobTablet", F.did("carol-phone"), F.did("mallory")
HUB_A, MBX_B = "did:web:mbx.alice.example", "did:web:mbx.bob.example"
GROUP = b64url_encode(uid("group-1").encode())
GROUP2 = b64url_encode(uid("group-2").encode())
CONV = uid("conversation-1")
SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
KEY32 = b64url_encode(bytes(range(32)))
MLS = b64url_encode(b"\x00\x01mls-message")


def mv(vid, desc, refs, inp, expect, ctx=None):
    return vector(f"messaging/{vid}", "messaging", desc, refs, ctx or {}, inp, expect)


def trace(vid, desc, refs, check, ctx, steps):
    """steps: (event, emit, state) triples, all authored by hand."""
    return mv(vid, desc, refs, {"check": check, "steps": [{"event": e} for e, _, _ in steps]},
              {"steps": [{"emit": em, "state": st} for _, em, st in steps]}, ctx=ctx)


def c(n: int) -> str:
    return f"c:{n:016x}"


# ---------------------------------------------------------------- payload builders

def msg(t, label, frm, to, ttl=30, at=NOW, **fields):
    p = {"dsip": copy.deepcopy(VERSION), "type": t, "id": uid(label, at), "from": frm, "to": to}
    p.update(fields)
    p["issued_at"], p["expires_at"] = at, at + ttl
    return p


def deposit(label="dep", cls="application", ttl=30, **fields):
    base = {"group": GROUP, "class": cls}
    if cls in ("handshake", "application", "welcome", "group-info"):
        base["mls"] = MLS
    base.update(fields)
    return msg("deposit", label, APH, HUB_A, ttl=ttl, **base)


def content(label="m1", kind="text", purpose="message", at=NOW, sender=ALICE, **fields):
    o = {"object": "content", "id": uid(label, at), "conversation": CONV, "sender": sender, "sent_at": at,
         "kind": kind, "purpose": purpose}
    if kind == "text" and "text" not in fields:
        o["content_type"], o["text"] = "text/plain", "Dinner at 7?"
    o.update(fields)
    return o


def blob(**over):
    b = {"uri": f"https://mbx.alice.example/blobs/{SHA}", "sha256": SHA, "size": 482220, "key": KEY32,
         "alg": "A256GCM", "content_type": "audio/ogg; codecs=opus"}
    b.update(over)
    return b


OBJ_CTX = {"conversation": CONV, "conversation_kind": "direct", "leaf_identity": ALICE}


def vectors() -> list[dict]:
    out = []
    out += message_vectors()
    out += object_vectors()
    out += hub_vectors()
    out += mailbox_vectors()
    out += voicemail_offer_vectors()
    out += conversation_vectors()
    out += client_vectors()
    out += gap_vectors()
    return out


# ---------------------------------------------------------------- messages (M§5)

def message_vectors():
    out = []

    def m(vid, desc, refs, payload, expect):
        out.append(mv(vid, desc, refs, {"check": "message", "payload": payload}, expect))

    m("deposit-application-valid", "Application deposit with an MLS message and a blob manifest.", ["M§5.2"],
      deposit(blobs=[{"uri": f"https://mbx.alice.example/blobs/{SHA}", "sha256": SHA, "size": 482220}]), accept())
    m("deposit-unknown-class-refused", "Deposit class is structural: an unregistered class is refused, not ignored.",
      ["M§5.2", "M§16"], deposit(cls="telemetry", sealed="AAAA"), reject("deposit-class-unsupported", "mailbox.unsupported-class"))
    m("deposit-lifetime-over-60s", "Profile messages are delivery envelopes: validity over 60 s is refused.", ["M§5.1"],
      deposit(ttl=61), reject("lifetime-exceeded"))
    m("deposit-ephemeral-valid", "Ephemeral deposit with sealed activity and a 10 s lifetime.", ["M§5.2", "M§11.2"],
      deposit(cls="ephemeral", ttl=10, sealed="c2VhbGVkLWFjdGl2aXR5"), accept())
    m("deposit-ephemeral-lifetime-over-10s", "Ephemeral activity may not outlive 10 s on the wire.", ["M§11.2"],
      deposit(cls="ephemeral", ttl=11, sealed="c2VhbGVkLWFjdGl2aXR5"), reject("lifetime-exceeded"))
    m("deposit-ephemeral-with-mls-refused", "Ephemeral activity never travels in the MLS secret tree.", ["M§5.2", "M§11.1"],
      deposit(cls="ephemeral", ttl=10, sealed="c2VhbGVk", mls=MLS), reject("deposit-fields"))
    m("deposit-application-with-archive-refused", "An application deposit may not carry archive fields.", ["M§5.2"],
      deposit(archive="YXJjaGl2ZQ"), reject("deposit-fields"))
    m("deposit-welcome-missing-hub", "A welcome must name the group's hub so the mailbox can register it.", ["M§5.2", "M§6.6"],
      deposit(cls="welcome"), reject("deposit-fields"))
    m("deposit-welcome-valid", "Hub-forwarded welcome with hub, grant and origin.", ["M§5.2", "M§14.2"],
      deposit(cls="welcome", recipient=BOB, hub={"did": HUB_A, "uri": "wss://mbx.alice.example/dsip"},
              grants=["eyJ.grant.sig"], origin="eyJ.origin.sig"), accept())
    m("deposit-welcome-with-seq-refused", "Only handshake and application items carry a hub seq.", ["M§5.2"],
      deposit(cls="welcome", hub={"did": HUB_A}, seq=3), reject("deposit-fields"))
    m("deposit-archive-valid", "Archive deposit with akid and item reference.", ["M§5.2", "M§12.2"],
      msg("deposit", "arch", BPH, MBX_B, group=GROUP, **{"class": "archive"}, archive="YXJjaGl2ZQ",
          akid=uid("akid-1"), ref_group=GROUP, ref_seq=42), accept())
    m("deposit-archive-missing-akid", "An archive item without its archive key id cannot be decrypted later.", ["M§5.2", "M§12.2"],
      msg("deposit", "arch2", BPH, MBX_B, group=GROUP, **{"class": "archive"}, archive="YXJjaGl2ZQ",
          ref_group=GROUP, ref_seq=42), reject("deposit-fields"))
    m("deposit-mls-at-cap-accepted", "An MLS value of exactly 24,576 decoded bytes fits.", ["M§5.1"],
      deposit(mls=b64url_encode(b"\x00" * 24576)), accept())
    m("deposit-mls-over-cap-refused", "An MLS value one byte over 24,576 decoded bytes must go by blob.", ["M§5.1", "M§8.3"],
      deposit(mls=b64url_encode(b"\x00" * 24577)), reject("object-too-large", "mailbox.object-too-large"))
    m("sync-valid", "Sync from a cursor with an acknowledgement and live push.", ["M§5.4"],
      msg("sync", "sync", BPH, MBX_B, since=c(3), ack_through=c(3), limit=200, live=True), accept())
    m("sync-limit-over-1000", "sync.limit is capped at 1000.", ["M§5.4"],
      msg("sync", "sync2", BPH, MBX_B, since=None, limit=1001), reject("schema-invalid"))
    m("items-valid", "Items response with one application item.", ["M§5.4"],
      msg("items", "items", MBX_B, BPH, in_reply_to=uid("sync"), next=None,
          items=[{"cursor": c(4), "stored_at": NOW, "class": "application", "source": HUB_A, "group": GROUP, "seq": 42, "mls": MLS}]),
      accept())
    m("accepted-valid", "Hub acceptance with seq.", ["M§5.3"],
      msg("accepted", "acc", HUB_A, APH, in_reply_to=uid("dep"), group=GROUP, seq=42), accept())
    m("key-packages-upload-valid", "KeyPackage upload with a last resort.", ["M§5.5"],
      msg("key-packages", "kpu", BPH, MBX_B, subject=BOB, key_packages=[MLS, MLS], last_resort=MLS), accept())
    m("key-packages-empty-refused", "A key-packages message must carry at least one KeyPackage.", ["M§5.5"],
      msg("key-packages", "kpe", BPH, MBX_B, subject=BOB, key_packages=[]), reject("key-packages-empty"))
    m("key-package-fetch-valid", "Fetch with a grant.", ["M§5.5", "M§14.2"],
      msg("key-package-fetch", "kpf", CPH, MBX_B, target=BOB, grant="eyJ.grant.sig"), accept())
    m("blob-put-valid", "Blob upload authorization.", ["M§5.6"],
      msg("blob-put", "bp", APH, HUB_A, ttl=60, sha256=SHA, size=482220), accept())
    m("blob-put-uppercase-sha-refused", "sha256 is lowercase hex.", ["M§5.6"],
      msg("blob-put", "bp2", APH, HUB_A, sha256=SHA.upper(), size=482220), reject("schema-invalid"))
    m("mailbox-config-valid", "Mode, admit, group confirmation and a revoked grant.", ["M§5.7"],
      msg("mailbox-config", "cfg", BPH, MBX_B, subject=BOB, mode="sync", admit="grant",
          groups=[{"group": GROUP, "hub": HUB_A, "state": "joined"}], revoked_grants=[uid("grant-x")]), accept())
    m("mailbox-config-unknown-mode-refused", "An unregistered mailbox mode is refused.", ["M§4.4", "M§16"],
      msg("mailbox-config", "cfg2", BPH, MBX_B, subject=BOB, mode="archive-forever"),
      reject("mailbox-mode-unsupported", "mailbox.unsupported-mode"))
    m("mailbox-config-admit-invalid", "admit is grant or open.", ["M§5.7"],
      msg("mailbox-config", "cfg3", BPH, MBX_B, subject=BOB, admit="anyone"), reject("schema-invalid"))
    return out


# ---------------------------------------------------------------- objects (M§8, M§10–M§13)

def object_vectors():
    out = []

    def o(vid, desc, refs, obj, expect, ctx=None):
        out.append(mv(vid, desc, refs, {"check": "object", "object": obj}, expect, ctx=ctx or OBJ_CTX))

    o("content-text-valid", "Plain text message.", ["M§8.1", "M§8.2"], content(),
      accept(effective={"kind": "text", "purpose": "message"}))
    o("content-sender-not-leaf-identity", "content.sender must be the identity of the MLS sender leaf.", ["M§8.1", "M§6.2"],
      content(sender=BOB), reject("sender-mismatch"))
    o("content-wrong-conversation", "content.conversation must match the group's dsip_conversation.", ["M§8.1", "M§6.3"],
      content(conversation=uid("other-conv")), reject("conversation-mismatch"))
    o("content-ulid-sent-at-mismatch", "Content id timestamp more than 300 s from sent_at.", ["M§8.1", "§20.6"],
      {**content(), "id": uid("m-backdated", NOW - 3600)}, reject("ulid-sent-at-mismatch"))
    o("content-location-valid", "Location uses integer degrees × 10⁷.", ["M§8.2", "§10.3"],
      content("loc", kind="location", lat_e7=430481000, lon_e7=-761474000, accuracy_m=20),
      accept(effective={"kind": "location", "purpose": "message"}))
    o("content-location-float-refused", "A float coordinate violates §10.3 inside MLS plaintext too.", ["M§8.2", "§10.3"],
      content("locf", kind="location", lat_e7=43.0481, lon_e7=-76.1474), reject("payload-float"))
    o("content-unknown-kind-with-blob-is-file", "Unknown kind carrying a blob is offered as a file.", ["M§8.2"],
      content("hol", kind="hologram", blob=blob(content_type="model/gltf-binary")),
      accept(effective={"kind": "file", "purpose": "message"}))
    o("content-unknown-kind-without-blob-is-unsupported", "Unknown kind with no blob renders as an unsupported-message placeholder.",
      ["M§8.2"], content("poll", kind="poll", question="Pizza?"), accept(effective={"kind": "unsupported", "purpose": "message"}))
    o("content-unknown-purpose-is-message", "Unknown purpose is handled as message.", ["M§8.2"],
      content("pp", purpose="sticker"), accept(effective={"kind": "text", "purpose": "message"}))
    o("content-audio-missing-blob", "Audio content must carry its blob and duration.", ["M§8.2"],
      content("au", kind="audio", purpose="voice-message", duration_ms=5000), reject("content-body"))
    o("content-blob-key-wrong-length", "A blob key is exactly 32 bytes (43 base64url characters).", ["M§8.4"],
      content("au2", kind="audio", purpose="voice-message", duration_ms=5000, blob=blob(key=KEY32[:40])), reject("schema-invalid"))
    o("content-reaction-valid", "Reaction: one emoji replying to a target.", ["M§8.2"],
      content("r1", purpose="reaction", text="👍", reply_to=uid("m1")), accept(effective={"kind": "text", "purpose": "reaction"}))
    o("content-reaction-too-long", "A reaction text over 32 bytes is not a reaction.", ["M§8.2"],
      content("r2", purpose="reaction", text="👍" * 9, reply_to=uid("m1")), reject("reaction-invalid"))
    o("content-reaction-without-target", "A reaction must reply to a target.", ["M§8.2"],
      content("r3", purpose="reaction", text="👍", reply_to=None), reject("reaction-invalid"))
    o("content-voicemail-valid", "Voicemail: audio with blob, duration and the invite id.", ["M§13.1", "M§13.2"],
      content("vm", kind="audio", purpose="voicemail", duration_ms=28400, blob=blob(), session=uid("invite-1")),
      accept(effective={"kind": "audio", "purpose": "voicemail"}))
    o("content-voicemail-missing-session", "A voicemail names the unanswered session.", ["M§13.2"],
      content("vm2", kind="audio", purpose="voicemail", duration_ms=28400, blob=blob()), reject("content-body"))
    rc = {"object": "receipt", "id": uid("rc"), "conversation": CONV, "sender": ALICE, "sent_at": NOW}
    o("receipt-read-watermark-valid", "Read receipt is a per-conversation watermark.", ["M§10.3"],
      {**rc, "kind": "read", "through": uid("m1")}, accept(effective={"receipt": "read"}))
    o("receipt-read-with-targets-refused", "A read watermark carries through, not targets.", ["M§10.3"],
      {**rc, "kind": "read", "through": uid("m1"), "targets": [uid("m1")]}, reject("receipt-shape"))
    o("receipt-delivered-without-targets-refused", "delivered names its targets.", ["M§10.2"],
      {**rc, "kind": "delivered"}, reject("receipt-shape"))
    o("receipt-unknown-kind-ignored", "Unknown receipt kinds are ignored, never errors.", ["M§10", "M§17"],
      {**rc, "kind": "seen-by-ai", "targets": [uid("m1")]}, accept(effective={"render": "ignore"}))
    act = {"object": "activity", "conversation": CONV, "sender": ALICE, "state": "active"}
    o("activity-typing-valid", "Typing indicator.", ["M§11.1"], {**act, "activity": "typing"}, accept(effective={"activity": "typing"}))
    o("activity-unknown-is-generic", "Unknown activity renders as a generic active indicator.", ["M§11.1"],
      {**act, "activity": "drawing"}, accept(effective={"activity": "active"}))
    ak = {"object": "archive-key", "akid": uid("akid-1"), "key": KEY32, "created_at": NOW}
    o("archive-key-in-personal-group", "Archive keys travel in the personal group.", ["M§12.1"], ak, accept(),
      ctx={**OBJ_CTX, "conversation_kind": "personal"})
    o("archive-key-outside-personal-group-refused", "An archive key in a direct conversation would disclose it to the peer.",
      ["M§12.1"], ak, reject("personal-group-only"))
    o("unknown-object-ignored", "Unknown object types are ignored.", ["M§8.1"],
      {"object": "poll-vote", "choice": 2}, accept(effective={"render": "ignore"}))
    out.append(mv("conversation-ext-unknown-kind-is-group", "Unknown conversation kind is handled as group.", ["M§6.3"],
                  {"check": "conversation-ext", "extension": {"conversation": CONV, "kind": "channel", "hub": {"did": HUB_A},
                                                              "successor_of": None}},
                  accept(effective={"kind": "group"})))
    return out


# ---------------------------------------------------------------- hub traces (M§6.5–M§6.8, M§7.3, M§9.3, M§11.2)

def hub_ctx(epoch=1, roster=None, kind="direct", owner=None):
    ctx = {"component": "hub", "hub": HUB_A, "group": GROUP, "kind": kind, "now": NOW, "epoch": epoch,
           "roster": roster if roster is not None else {ALICE: [ALA, APH], BOB: [BPH]}}
    if owner:
        ctx["owner"] = owner
    return ctx


def hs(epoch, next_seq, roster, pending=None):
    return {"epoch": epoch, "next_seq": next_seq, "roster": roster, "pending": pending or {}}


def dep(label, device, identity, cls, epoch=None, digest=None, **kw):
    d = {"id": uid(label), "device": device, "identity": identity, "class": cls}
    if epoch is not None:
        d["epoch"] = epoch
    d["digest"] = digest or label
    d.update(kw)
    return {"deposit": d}


def acc(device, label, seq, dup=False):
    a = {"to": device, "in_reply_to": uid(label), "seq": seq}
    if dup:
        a["duplicate"] = True
    return {"accepted": a}


def err(device, label, reason):
    return {"error": {"to": device, "in_reply_to": uid(label), "reason": reason}}


def fan(to, seq, cls="application"):
    return {"fanout": {"to": to, "seq": seq, "class": cls}}


def hub_vectors():
    out = []
    R = {ALICE: [ALA, APH], BOB: [BPH]}
    refs = ["M§6.5"]

    out.append(trace("hub-application-sequenced-and-fanned-out",
                     "An application message is sequenced and fanned out to every member identity, the sender's own included.",
                     refs + ["M§9.1"], "hub-trace", hub_ctx(), [
                         (dep("a1", APH, ALICE, "application", 1), [acc(APH, "a1", 1), fan(ALICE, 1), fan(BOB, 1)],
                          hs(1, 2, R, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-commit-conflict",
                     "The first valid commit for an epoch wins; a second commit for the same epoch is refused.",
                     refs, "hub-trace", hub_ctx(), [
                         (dep("k1", APH, ALICE, "handshake", 1, commit={"adds": [], "removes": []}),
                          [acc(APH, "k1", 1), fan(ALICE, 1, "handshake"), fan(BOB, 1, "handshake")],
                          hs(2, 2, R, {ALICE: [1], BOB: [1]})),
                         (dep("k2", BPH, BOB, "handshake", 1, commit={"adds": [], "removes": []}),
                          [err(BPH, "k2", "mailbox.commit-conflict")], hs(2, 2, R, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-stale-epoch",
                     "Application messages for the current or previous epoch are accepted; older ones are stale.",
                     refs, "hub-trace", hub_ctx(epoch=3), [
                         (dep("a2", APH, ALICE, "application", 2), [acc(APH, "a2", 1), fan(ALICE, 1), fan(BOB, 1)],
                          hs(3, 2, R, {ALICE: [1], BOB: [1]})),
                         (dep("a3", BPH, BOB, "application", 1), [err(BPH, "a3", "mailbox.stale-epoch")],
                          hs(3, 2, R, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-idempotent-redeposit",
                     "Re-depositing the same MLS bytes returns the original seq with duplicate and fans out nothing.",
                     ["M§9.3"], "hub-trace", hub_ctx(), [
                         (dep("a4", APH, ALICE, "application", 1, digest="d-a4"), [acc(APH, "a4", 1), fan(ALICE, 1), fan(BOB, 1)],
                          hs(1, 2, R, {ALICE: [1], BOB: [1]})),
                         (dep("a4-retry", APH, ALICE, "application", 1, digest="d-a4"), [acc(APH, "a4-retry", 1, dup=True)],
                          hs(1, 2, R, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-non-member-refused", "A device of a non-member identity cannot deposit into the group.",
                     refs, "hub-trace", hub_ctx(), [
                         (dep("m1", MPH, MALLORY, "application", 1), [err(MPH, "m1", "policy.blocked")], hs(1, 1, R)),
                     ]))
    out.append(trace("hub-fanout-waits-for-ack",
                     "Fan-out to each mailbox is in seq order: a later item waits until the earlier one is acknowledged.",
                     refs, "hub-trace", hub_ctx(), [
                         (dep("f1", APH, ALICE, "application", 1), [acc(APH, "f1", 1), fan(ALICE, 1), fan(BOB, 1)],
                          hs(1, 2, R, {ALICE: [1], BOB: [1]})),
                         ({"ack": {"identity": ALICE, "seq": 1}}, [], hs(1, 2, R, {BOB: [1]})),
                         (dep("f2", APH, ALICE, "application", 1), [acc(APH, "f2", 2), fan(ALICE, 2)],
                          hs(1, 3, R, {ALICE: [2], BOB: [1, 2]})),
                         ({"ack": {"identity": BOB, "seq": 2}}, [], hs(1, 3, R, {ALICE: [2], BOB: [1, 2]})),
                         ({"ack": {"identity": BOB, "seq": 1}}, [fan(BOB, 2)], hs(1, 3, R, {ALICE: [2], BOB: [2]})),
                     ]))
    out.append(trace("hub-commit-adds-identity-sends-welcome",
                     "A commit adding a new identity fans out to existing members and sends a welcome to the new one.",
                     refs + ["M§7.3"], "hub-trace", hub_ctx(kind="group"), [
                         (dep("add-carol", APH, ALICE, "handshake", 1, commit={"adds": [{"identity": CAROL, "device": CPH}], "removes": []}),
                          [acc(APH, "add-carol", 1), fan(ALICE, 1, "handshake"), fan(BOB, 1, "handshake"),
                           {"fanout": {"to": CAROL, "class": "welcome"}}],
                          hs(2, 2, {ALICE: [ALA, APH], BOB: [BPH], CAROL: [CPH]}, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-add-other-identitys-device-refused",
                     "Adding a device to another member identity is reserved to that identity's own devices.",
                     ["M§7.3"], "hub-trace", hub_ctx(kind="group"), [
                         (dep("add-bla", APH, ALICE, "handshake", 1, commit={"adds": [{"identity": BOB, "device": BLA}], "removes": []}),
                          [err(APH, "add-bla", "policy.blocked")], hs(1, 1, R)),
                     ]))
    RB2 = {ALICE: [ALA, APH], BOB: [BLA, BPH]}
    out.append(trace("hub-remove-whole-identity-allowed",
                     "Any member may remove another identity entirely; the removed identity still receives the commit.",
                     ["M§7.3", "M§6.5"], "hub-trace", hub_ctx(kind="group", roster=RB2), [
                         (dep("rm-bob", APH, ALICE, "handshake", 1,
                              commit={"adds": [], "removes": [{"identity": BOB, "device": BPH}, {"identity": BOB, "device": BLA}]}),
                          [acc(APH, "rm-bob", 1), fan(ALICE, 1, "handshake"), fan(BOB, 1, "handshake")],
                          hs(2, 2, {ALICE: [ALA, APH]}, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-remove-partial-other-identity-refused",
                     "Removing only some devices of another identity is refused while their delegations are valid.",
                     ["M§7.3"], "hub-trace", hub_ctx(kind="group", roster=RB2), [
                         (dep("rm-bla", APH, ALICE, "handshake", 1, commit={"adds": [], "removes": [{"identity": BOB, "device": BLA}]}),
                          [err(APH, "rm-bla", "policy.blocked")], hs(1, 1, RB2)),
                     ]))
    out.append(trace("hub-remove-lapsed-delegation-leaf-allowed",
                     "Any member may remove a leaf whose delegation no longer verifies.",
                     ["M§7.3", "M§6.2"], "hub-trace", hub_ctx(kind="group", roster=RB2), [
                         (dep("rm-lapsed", APH, ALICE, "handshake", 1,
                              commit={"adds": [], "removes": [{"identity": BOB, "device": BLA, "delegation_valid": False}]}),
                          [acc(APH, "rm-lapsed", 1), fan(ALICE, 1, "handshake"), fan(BOB, 1, "handshake")],
                          hs(2, 2, {ALICE: [ALA, APH], BOB: [BPH]}, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-external-commit-own-identity",
                     "A new device of a member identity may join by external commit, replacing that identity's stale leaf.",
                     ["M§6.8"], "hub-trace", hub_ctx(), [
                         (dep("ext-tab", BTAB, BOB, "handshake", 1,
                              commit={"external": True, "adds": [{"identity": BOB, "device": BTAB}],
                                      "removes": [{"identity": BOB, "device": BPH}]}),
                          [acc(BTAB, "ext-tab", 1), fan(ALICE, 1, "handshake"), fan(BOB, 1, "handshake")],
                          hs(2, 2, {ALICE: [ALA, APH], BOB: [BTAB]}, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-external-commit-stranger-refused",
                     "An identity with no leaf in the group may not join by external commit.",
                     ["M§6.8"], "hub-trace", hub_ctx(), [
                         (dep("ext-carol", CPH, CAROL, "handshake", 1,
                              commit={"external": True, "adds": [{"identity": CAROL, "device": CPH}], "removes": []}),
                          [err(CPH, "ext-carol", "policy.blocked")], hs(1, 1, R)),
                     ]))
    out.append(trace("hub-external-commit-personal-group-owner",
                     "The owner may re-join its own personal group by external commit even with no surviving leaf.",
                     ["M§6.8", "M§7.1"], "hub-trace", hub_ctx(kind="personal", owner=BOB, roster={}), [
                         (dep("ext-own", BTAB, BOB, "handshake", 1,
                              commit={"external": True, "adds": [{"identity": BOB, "device": BTAB}], "removes": []}),
                          [acc(BTAB, "ext-own", 1)], hs(2, 2, {BOB: [BTAB]})),
                     ]))
    out.append(trace("hub-invalid-commit-refused", "A commit that fails validation is refused and does not advance the epoch.",
                     refs, "hub-trace", hub_ctx(), [
                         (dep("bad", APH, ALICE, "handshake", 1, commit={"valid": False, "adds": [], "removes": []}),
                          [err(APH, "bad", "policy.blocked")], hs(1, 1, R)),
                     ]))
    out.append(trace("hub-proposal-sequenced-no-epoch-change",
                     "A standalone proposal is sequenced and fanned out but does not advance the epoch.",
                     refs, "hub-trace", hub_ctx(), [
                         (dep("prop", BPH, BOB, "handshake", 1), [acc(BPH, "prop", 1), fan(ALICE, 1, "handshake"), fan(BOB, 1, "handshake")],
                          hs(1, 2, R, {ALICE: [1], BOB: [1]})),
                     ]))
    out.append(trace("hub-ephemeral-forwarded-not-sequenced",
                     "Activity is forwarded to the other member identities: no seq, no acceptance, nothing queued.",
                     ["M§11.2"], "hub-trace", hub_ctx(), [
                         (dep("typ", APH, ALICE, "ephemeral", expires_at=NOW + 10), [{"forward": {"to": BOB, "class": "ephemeral"}}],
                          hs(1, 1, R)),
                     ]))
    out.append(trace("hub-ephemeral-expired-dropped", "Expired activity is dropped silently.",
                     ["M§11.2"], "hub-trace", hub_ctx(), [
                         (dep("typ-old", APH, ALICE, "ephemeral", expires_at=NOW - 1), [], hs(1, 1, R)),
                     ]))
    out.append(trace("hub-unsupported-class-refused", "A hub orders only handshake, application and ephemeral traffic.",
                     ["M§6.5", "M§5.2"], "hub-trace", hub_ctx(), [
                         (dep("arch", APH, ALICE, "archive"), [err(APH, "arch", "mailbox.unsupported-class")], hs(1, 1, R)),
                     ]))
    return out


# ---------------------------------------------------------------- mailbox traces (M§4.4, M§5.4–M§5.7, M§6.6, M§12.2, M§14.2)

def mbx_ctx(**over):
    ctx = {"component": "mailbox", "mailbox": MBX_B, "owner": BOB, "serves": [BOB], "devices": [BLA, BPH], "now": NOW,
           "mode": "sync", "admit": "grant", "pending_group_ttl": 604800, "pending_group_max_items": 2,
           "groups": {}, "key_packages": {}}
    ctx.update(over)
    return ctx


def ms(items=(), groups=None, kps=None):
    return {"items": list(items), "groups": groups or {}, "key_packages": kps or {}}


def grant(label="g1", scope=("dsip.message",), valid_until=NOW + 86400, frm=BOB, to=CAROL):
    return {"id": uid(label), "from": frm, "to": to, "scope": list(scope), "valid_until": valid_until}


def welcome(label="w1", adder=CAROL, device=CPH, grant_=None, group=GROUP, hub=HUB_A, recipient=BOB, successor_of=None):
    e = {"id": uid(label), "from": device, "adder_identity": adder, "recipient": recipient, "group": group, "hub": hub,
         "grant": grant_}
    if successor_of is not None:
        e["successor_of"] = successor_of
    return {"welcome": e}


def macc(to, label, cur=None, dup=False):
    a = {"to": to, "in_reply_to": uid(label)}
    if cur is not None:
        a["cursor"] = cur
    if dup:
        a["duplicate"] = True
    return {"accepted": a}


def hubdep(label, seq, cls="application", group=GROUP, frm=HUB_A, recipient=BOB):
    return {"hub_deposit": {"id": uid(label), "from": frm, "recipient": recipient, "group": group, "seq": seq, "class": cls}}


def mailbox_vectors():
    out = []
    P = {GROUP: "pending"}
    J = {GROUP: "joined"}
    T = "mailbox-trace"

    out.append(trace("mailbox-welcome-with-grant-registers-pending",
                     "A welcome from an identity holding a dsip.message grant is stored and registers the group as pending.",
                     ["M§14.2", "M§6.6"], T, mbx_ctx(), [
                         (welcome(grant_=grant()), [macc(CPH, "w1", c(1))], ms([c(1)], P)),
                     ]))
    out.append(trace("mailbox-welcome-without-grant-refused",
                     "Without a grant (and admit grant) the welcome is refused with first-contact-required.",
                     ["M§14.2", "§19.4"], T, mbx_ctx(), [
                         (welcome(), [err(CPH, "w1", "policy.first-contact-required")], ms()),
                     ]))
    out.append(trace("mailbox-welcome-revoked-grant-refused",
                     "A grant listed in revoked_grants no longer authorizes.", ["M§14.2", "M§5.7"], T, mbx_ctx(), [
                         ({"config": {"id": uid("cfg"), "device": BPH, "revoked_grants": [uid("g1")]}}, [macc(BPH, "cfg")], ms()),
                         (welcome(grant_=grant()), [err(CPH, "w1", "policy.first-contact-required")], ms()),
                     ]))
    out.append(trace("mailbox-welcome-expired-grant-refused", "A grant past valid_until no longer authorizes.",
                     ["M§14.2"], T, mbx_ctx(), [
                         (welcome(grant_=grant(valid_until=NOW)), [err(CPH, "w1", "policy.first-contact-required")], ms()),
                     ]))
    out.append(trace("mailbox-welcome-invite-grant-accepted",
                     "A dsip.invite grantee may create a conversation (to leave voicemail).", ["M§14.2", "M§13.2"], T, mbx_ctx(), [
                         (welcome(grant_=grant(scope=("dsip.invite",))), [macc(CPH, "w1", c(1))], ms([c(1)], P)),
                     ]))
    out.append(trace("mailbox-welcome-subscribe-grant-refused", "A dsip.subscribe-only grant does not authorize messaging.",
                     ["M§14.2", "§19.4"], T, mbx_ctx(), [
                         (welcome(grant_=grant(scope=("dsip.subscribe",))), [err(CPH, "w1", "policy.first-contact-required")], ms()),
                     ]))
    out.append(trace("mailbox-welcome-grant-for-other-grantee-refused", "A grant names its grantee; another identity cannot use it.",
                     ["M§14.2"], T, mbx_ctx(), [
                         (welcome(grant_=grant(to=MALLORY)), [err(CPH, "w1", "policy.first-contact-required")], ms()),
                     ]))
    out.append(trace("mailbox-welcome-admit-open", "An owner with admit open accepts welcomes without a grant.",
                     ["M§14.2", "M§5.7"], T, mbx_ctx(admit="open"), [
                         (welcome(), [macc(CPH, "w1", c(1))], ms([c(1)], P)),
                     ]))
    out.append(trace("mailbox-welcome-from-own-device", "A device of the owner identity needs no grant.",
                     ["M§14.2", "M§6.7"], T, mbx_ctx(), [
                         (welcome(adder=BOB, device=BPH), [macc(BPH, "w1", c(1))], ms([c(1)], P)),
                     ]))
    out.append(trace("mailbox-welcome-successor-group-no-grant",
                     "A successor group of a registered group is admitted without a grant.", ["M§7.5", "M§14.2"], T,
                     mbx_ctx(groups={GROUP: {"hub": "did:web:dead-hub.example", "state": "joined"}}), [
                         (welcome(group=GROUP2, successor_of=GROUP), [macc(CPH, "w1", c(1))], ms([c(1)], {GROUP: "joined", GROUP2: "pending"})),
                     ]))
    out.append(trace("mailbox-welcome-unknown-recipient", "A mailbox refuses deposits for identities it does not serve.",
                     ["M§15.5", "§13.2"], T, mbx_ctx(), [
                         (welcome(recipient=ALICE, grant_=grant()), [err(CPH, "w1", "transport.unknown-recipient")], ms()),
                     ]))
    out.append(trace("mailbox-hub-deposit-unregistered-group", "Hub fan-out for a group not registered for the owner is refused.",
                     ["M§6.6"], T, mbx_ctx(), [
                         (hubdep("h1", 1), [err(HUB_A, "h1", "mailbox.unknown-group")], ms()),
                     ]))
    out.append(trace("mailbox-hub-deposit-wrong-hub", "Only the registered hub of a group may fan out into it.",
                     ["M§6.6"], T, mbx_ctx(groups={GROUP: {"hub": HUB_A, "state": "joined"}}), [
                         (hubdep("h1", 1, frm="did:web:rogue-hub.example"), [err("did:web:rogue-hub.example", "h1", "mailbox.unknown-group")], ms(groups=J)),
                     ]))
    out.append(trace("mailbox-pending-group-bounded",
                     "A pending group admits a bounded number of items before its owner confirms it.", ["M§6.6"], T, mbx_ctx(), [
                         (welcome(grant_=grant()), [macc(CPH, "w1", c(1))], ms([c(1)], P)),
                         (hubdep("h1", 1), [macc(HUB_A, "h1", c(2))], ms([c(1), c(2)], P)),
                         (hubdep("h2", 2), [macc(HUB_A, "h2", c(3))], ms([c(1), c(2), c(3)], P)),
                         (hubdep("h3", 3), [err(HUB_A, "h3", "mailbox.quota-exceeded")], ms([c(1), c(2), c(3)], P)),
                     ]))
    out.append(trace("mailbox-pending-group-confirmed",
                     "After the owner confirms the group, the pending bound no longer applies.", ["M§6.6", "M§5.7"], T, mbx_ctx(), [
                         (welcome(grant_=grant()), [macc(CPH, "w1", c(1))], ms([c(1)], P)),
                         (hubdep("h1", 1), [macc(HUB_A, "h1", c(2))], ms([c(1), c(2)], P)),
                         (hubdep("h2", 2), [macc(HUB_A, "h2", c(3))], ms([c(1), c(2), c(3)], P)),
                         ({"config": {"id": uid("cfg"), "device": BPH, "groups": [{"group": GROUP, "state": "joined"}]}},
                          [macc(BPH, "cfg")], ms([c(1), c(2), c(3)], J)),
                         (hubdep("h3", 3), [macc(HUB_A, "h3", c(4))], ms([c(1), c(2), c(3), c(4)], J)),
                     ]))
    out.append(trace("mailbox-pending-group-expires",
                     "An unconfirmed pending group is dropped with its items after pending_group_ttl.", ["M§6.6"], T, mbx_ctx(), [
                         (welcome(grant_=grant()), [macc(CPH, "w1", c(1))], ms([c(1)], P)),
                         (hubdep("h1", 1), [macc(HUB_A, "h1", c(2))], ms([c(1), c(2)], P)),
                         ({"advance": 604800}, [], ms([c(1), c(2)], P)),
                         ({"advance": 1}, [], ms()),
                     ]))
    out.append(trace("mailbox-sync-and-live-push",
                     "sync returns stored items; with live, new items are pushed to the bound device until it unbinds.",
                     ["M§5.4", "M§9.1"], T, mbx_ctx(groups={GROUP: {"hub": HUB_A, "state": "joined"}}), [
                         (hubdep("h1", 1), [macc(HUB_A, "h1", c(1))], ms([c(1)], J)),
                         ({"sync": {"id": uid("s1"), "device": BPH, "since": None, "live": True}},
                          [{"items": {"to": BPH, "in_reply_to": uid("s1"), "cursors": [c(1)], "next": None}}], ms([c(1)], J)),
                         (hubdep("h2", 2), [macc(HUB_A, "h2", c(2)), {"push": {"to": BPH, "cursor": c(2)}}], ms([c(1), c(2)], J)),
                         ({"unbind": {"device": BPH}}, [], ms([c(1), c(2)], J)),
                         (hubdep("h3", 3), [macc(HUB_A, "h3", c(3))], ms([c(1), c(2), c(3)], J)),
                     ]))
    out.append(trace("mailbox-sync-cursor-invalid", "A cursor the mailbox never issued is refused; the device re-syncs from null.",
                     ["M§5.4"], T, mbx_ctx(), [
                         ({"sync": {"id": uid("s1"), "device": BPH, "since": c(9)}}, [err(BPH, "s1", "mailbox.cursor-invalid")], ms()),
                     ]))
    out.append(trace("mailbox-sync-pagination", "sync honours limit and returns next when more items remain.",
                     ["M§5.4"], T, mbx_ctx(groups={GROUP: {"hub": HUB_A, "state": "joined"}}), [
                         (hubdep("h1", 1), [macc(HUB_A, "h1", c(1))], ms([c(1)], J)),
                         (hubdep("h2", 2), [macc(HUB_A, "h2", c(2))], ms([c(1), c(2)], J)),
                         (hubdep("h3", 3), [macc(HUB_A, "h3", c(3))], ms([c(1), c(2), c(3)], J)),
                         ({"sync": {"id": uid("s1"), "device": BPH, "since": None, "limit": 2}},
                          [{"items": {"to": BPH, "in_reply_to": uid("s1"), "cursors": [c(1), c(2)], "next": c(2)}}], ms([c(1), c(2), c(3)], J)),
                         ({"sync": {"id": uid("s2"), "device": BPH, "since": c(2), "limit": 2}},
                          [{"items": {"to": BPH, "in_reply_to": uid("s2"), "cursors": [c(3)], "next": None}}], ms([c(1), c(2), c(3)], J)),
                     ]))
    QJ = {GROUP: {"hub": HUB_A, "state": "joined"}}
    out.append(trace("mailbox-queue-mode-deletes-after-every-device-acks",
                     "In queue mode an item is deleted only once every registered device has acknowledged it.",
                     ["M§4.4"], T, mbx_ctx(mode="queue", groups=QJ), [
                         (hubdep("h1", 1), [macc(HUB_A, "h1", c(1))], ms([c(1)], J)),
                         (hubdep("h2", 2), [macc(HUB_A, "h2", c(2))], ms([c(1), c(2)], J)),
                         ({"sync": {"id": uid("s1"), "device": BPH, "since": c(2), "ack_through": c(2)}},
                          [{"items": {"to": BPH, "in_reply_to": uid("s1"), "cursors": [], "next": None}}], ms([c(1), c(2)], J)),
                         ({"sync": {"id": uid("s2"), "device": BLA, "since": c(1), "ack_through": c(1)}},
                          [{"items": {"to": BLA, "in_reply_to": uid("s2"), "cursors": [c(2)], "next": None}}], ms([c(2)], J)),
                         ({"sync": {"id": uid("s3"), "device": BLA, "since": c(2), "ack_through": c(2)}},
                          [{"items": {"to": BLA, "in_reply_to": uid("s3"), "cursors": [], "next": None}}], ms([], J)),
                     ]))
    out.append(trace("mailbox-sync-mode-retains-after-ack",
                     "In sync mode acknowledged items are retained so later devices can reconstruct history.",
                     ["M§4.4", "M§12"], T, mbx_ctx(groups=QJ), [
                         (hubdep("h1", 1), [macc(HUB_A, "h1", c(1))], ms([c(1)], J)),
                         ({"sync": {"id": uid("s1"), "device": BPH, "since": c(1), "ack_through": c(1)}},
                          [{"items": {"to": BPH, "in_reply_to": uid("s1"), "cursors": [], "next": None}}], ms([c(1)], J)),
                         ({"sync": {"id": uid("s2"), "device": BLA, "since": c(1), "ack_through": c(1)}},
                          [{"items": {"to": BLA, "in_reply_to": uid("s2"), "cursors": [], "next": None}}], ms([c(1)], J)),
                     ]))
    out.append(trace("mailbox-ephemeral-pushed-never-stored",
                     "Ephemeral fan-out reaches only currently bound devices and is never stored or acknowledged.",
                     ["M§11.2"], T, mbx_ctx(groups=QJ), [
                         ({"sync": {"id": uid("s1"), "device": BLA, "since": None, "live": True}},
                          [{"items": {"to": BLA, "in_reply_to": uid("s1"), "cursors": [], "next": None}}], ms([], J)),
                         (hubdep("typ", None, cls="ephemeral"), [{"push": {"to": BLA, "class": "ephemeral"}}], ms([], J)),
                     ]))
    out.append(trace("mailbox-archive-first-wins",
                     "The first archive item per (group, seq) is kept; later ones are acknowledged as duplicates.",
                     ["M§12.2"], T, mbx_ctx(groups=QJ), [
                         ({"archive": {"id": uid("ar1"), "device": BPH, "ref_group": GROUP, "ref_seq": 42}}, [macc(BPH, "ar1", c(1))], ms([c(1)], J)),
                         ({"archive": {"id": uid("ar2"), "device": BLA, "ref_group": GROUP, "ref_seq": 42}},
                          [macc(BLA, "ar2", c(1), dup=True)], ms([c(1)], J)),
                     ]))
    out.append(trace("mailbox-archive-pushed-to-other-bound-devices",
                     "A new archive item is pushed to bound devices other than the one that deposited it.",
                     ["M§12.2", "M§5.4"], T, mbx_ctx(groups=QJ), [
                         ({"sync": {"id": uid("s1"), "device": BLA, "since": None, "live": True}},
                          [{"items": {"to": BLA, "in_reply_to": uid("s1"), "cursors": [], "next": None}}], ms([], J)),
                         ({"sync": {"id": uid("s2"), "device": BPH, "since": None, "live": True}},
                          [{"items": {"to": BPH, "in_reply_to": uid("s2"), "cursors": [], "next": None}}], ms([], J)),
                         ({"archive": {"id": uid("ar1"), "device": BPH, "ref_group": GROUP, "ref_seq": 7}},
                          [macc(BPH, "ar1", c(1)), {"push": {"to": BLA, "cursor": c(1)}}], ms([c(1)], J)),
                     ]))
    out.append(trace("mailbox-archive-refused-in-queue-mode", "Queue-mode mailboxes keep no history and refuse archive items.",
                     ["M§12.2", "M§4.4"], T, mbx_ctx(mode="queue"), [
                         ({"archive": {"id": uid("ar1"), "device": BPH, "ref_group": GROUP, "ref_seq": 42}},
                          [err(BPH, "ar1", "mailbox.unsupported-class")], ms()),
                     ]))
    out.append(trace("mailbox-trace-config-unknown-mode-refused", "An unregistered mode is refused and nothing changes.",
                     ["M§4.4", "M§16"], T, mbx_ctx(), [
                         ({"config": {"id": uid("cfg"), "device": BPH, "mode": "forever"}}, [err(BPH, "cfg", "mailbox.unsupported-mode")], ms()),
                         ({"archive": {"id": uid("ar1"), "device": BPH, "ref_group": GROUP, "ref_seq": 1}}, [macc(BPH, "ar1", c(1))], ms([c(1)])),
                     ]))
    KP = {BLA: {"one_time": 1, "last_resort": True}, BPH: {"one_time": 0, "last_resort": False}}
    out.append(trace("mailbox-key-packages-single-use-then-last-resort",
                     "Each fetch consumes one KeyPackage per device; an exhausted device falls back to its last resort, "
                     "and a device with neither is omitted.",
                     ["M§5.5"], T, mbx_ctx(key_packages=KP), [
                         ({"kp_fetch": {"id": uid("f1"), "from": CPH, "from_identity": CAROL, "target": BOB, "grant": grant()}},
                          [{"key_packages": {"to": CPH, "in_reply_to": uid("f1"), "devices": {BLA: "one-time"}}}],
                          ms(kps={BLA: {"one_time": 0, "last_resort": True}, BPH: {"one_time": 0, "last_resort": False}})),
                         ({"kp_fetch": {"id": uid("f2"), "from": CPH, "from_identity": CAROL, "target": BOB, "grant": grant()}},
                          [{"key_packages": {"to": CPH, "in_reply_to": uid("f2"), "devices": {BLA: "last-resort"}}}],
                          ms(kps={BLA: {"one_time": 0, "last_resort": True}, BPH: {"one_time": 0, "last_resort": False}})),
                         ({"kp_upload": {"id": uid("u1"), "device": BPH, "count": 2, "last_resort": True}}, [macc(BPH, "u1")],
                          ms(kps={BLA: {"one_time": 0, "last_resort": True}, BPH: {"one_time": 2, "last_resort": True}})),
                         ({"kp_fetch": {"id": uid("f3"), "from": CPH, "from_identity": CAROL, "target": BOB, "grant": grant()}},
                          [{"key_packages": {"to": CPH, "in_reply_to": uid("f3"), "devices": {BLA: "last-resort", BPH: "one-time"}}}],
                          ms(kps={BLA: {"one_time": 0, "last_resort": True}, BPH: {"one_time": 1, "last_resort": True}})),
                     ]))
    out.append(trace("mailbox-key-package-fetch-unauthorized", "A fetch without authorization is refused and consumes nothing.",
                     ["M§5.5", "M§14.2"], T, mbx_ctx(key_packages={BPH: {"one_time": 3, "last_resort": True}}), [
                         ({"kp_fetch": {"id": uid("f1"), "from": MPH, "from_identity": MALLORY, "target": BOB, "grant": None}},
                          [err(MPH, "f1", "policy.first-contact-required")], ms(kps={BPH: {"one_time": 3, "last_resort": True}})),
                     ]))
    out.append(trace("mailbox-key-package-fetch-none-available", "With no KeyPackage and no last resort for any device the fetch fails.",
                     ["M§5.5", "M§16"], T, mbx_ctx(), [
                         ({"kp_fetch": {"id": uid("f1"), "from": CPH, "from_identity": CAROL, "target": BOB, "grant": grant()}},
                          [err(CPH, "f1", "mailbox.no-key-packages")], ms()),
                     ]))
    out.append(trace("mailbox-key-package-upload-bounded", "A mailbox keeps at most 100 one-time KeyPackages per device.",
                     ["M§5.5"], T, mbx_ctx(key_packages={BPH: {"one_time": 90, "last_resort": False}}), [
                         ({"kp_upload": {"id": uid("u1"), "device": BPH, "count": 20}}, [macc(BPH, "u1")],
                          ms(kps={BPH: {"one_time": 100, "last_resort": False}})),
                     ]))
    return out


# ---------------------------------------------------------------- tranche 2: voicemail offer (M§13.2)

def voicemail_offer_vectors():
    out = []
    VM = {"max_duration_s": 180}

    def vo(vid, desc, outcome, expect, voicemail=VM, can_send=True):
        inp = {"check": "voicemail-offer", "voicemail": voicemail, "can_send": can_send, "outcome": outcome}
        out.append(mv(f"voicemail-offer-{vid}", desc, ["M§13.2"], inp, expect))

    yes = {"offer": True, "max_duration_s": 180}
    no = {"offer": False}
    vo("no-answer", "reject user.no-answer offers voicemail.", {"type": "reject", "reason": "user.no-answer"}, yes)
    vo("declined", "reject user.declined offers voicemail.", {"type": "reject", "reason": "user.declined"}, yes)
    vo("busy", "reject endpoint.busy offers voicemail.", {"type": "reject", "reason": "endpoint.busy"}, yes)
    vo("unavailable", "reject endpoint.unavailable offers voicemail.", {"type": "reject", "reason": "endpoint.unavailable"}, yes)
    vo("caller-timeout", "The caller's own cancel session.timeout (T-Establish/T-Ring) offers voicemail.",
       {"type": "cancel", "reason": "session.timeout"}, yes)
    vo("blocked", "user.blocked never offers voicemail.", {"type": "reject", "reason": "user.blocked"}, no)
    vo("policy", "policy.* never offers voicemail.", {"type": "reject", "reason": "policy.first-contact-required"}, no)
    vo("identity", "identity.* never offers voicemail.", {"type": "reject", "reason": "identity.not-in-service"}, no)
    vo("media", "media.* never offers voicemail.", {"type": "reject", "reason": "media.unsupported"}, no)
    vo("answered-elsewhere", "session.answered-elsewhere is not a missed call and never offers voicemail.",
       {"type": "cancel", "reason": "session.answered-elsewhere"}, no)
    vo("registered-endpoint-capability", "A registered endpoint token outside the list (endpoint.capability) does not offer.",
       {"type": "reject", "reason": "endpoint.capability"}, no)
    vo("unregistered-endpoint-condition", "An unregistered endpoint.* condition falls back to its category and offers "
       "(endpoint state prevented the call, like busy or unavailable).", {"type": "reject", "reason": "endpoint.do-not-disturb"}, yes)
    vo("unregistered-user-condition", "An unregistered user.* condition does not offer (conservative: it may be block-like).",
       {"type": "reject", "reason": "user.stepped-out"}, no)
    vo("not-advertised", "No voicemail advertisement in the callee's DSIPMailbox entry: no offer.",
       {"type": "reject", "reason": "user.no-answer"}, no, voicemail=None)
    vo("cannot-send", "No conversation and no authorization to create one: no offer.",
       {"type": "reject", "reason": "user.no-answer"}, no, can_send=False)
    vo("no-max-duration", "An advertisement without max_duration_s still offers, with no duration bound in the result.",
       {"type": "reject", "reason": "user.no-answer"}, {"offer": True}, voicemail={})
    return out


# ---------------------------------------------------------------- tranche 2: conversation convergence (M§7.2, M§7.5)

def conversation_vectors():
    out = []
    c_early, c_late = uid("dc-a", NOW - 2), uid("dc-b", NOW)
    out.append(mv("direct-select-lower-ulid-wins", "Two concurrent direct conversations converge on the lower ULID.", ["M§7.2"],
                  {"check": "direct-select", "candidates": [{"conversation": c_late, "issued_at": NOW},
                                                           {"conversation": c_early, "issued_at": NOW - 2}]},
                  {"winner": c_early, "discarded": []}))
    backdated = uid("dc-backdated", NOW - 3600)
    out.append(mv("direct-select-backdated-discarded",
                  "A conversation ULID backdated an hour against its creating deposit's issued_at cannot win (§20.6 guard).",
                  ["M§7.2", "§20.6"],
                  {"check": "direct-select", "candidates": [{"conversation": c_late, "issued_at": NOW},
                                                           {"conversation": backdated, "issued_at": NOW}]},
                  {"winner": c_late, "discarded": [backdated]}))
    out.append(mv("successor-check-valid", "A predecessor member re-creating the group with predecessor members is accepted.",
                  ["M§7.5"], {"check": "successor-check", "predecessor_roster": [ALICE, BOB, CAROL], "creator": BOB,
                              "roster": [ALICE, BOB, CAROL]}, accept()))
    out.append(mv("successor-check-roster-shrink-valid", "A successor may omit predecessor members.", ["M§7.5"],
                  {"check": "successor-check", "predecessor_roster": [ALICE, BOB, CAROL], "creator": BOB, "roster": [ALICE, BOB]},
                  accept()))
    out.append(mv("successor-check-creator-not-member", "A successor created by a non-member is a new conversation, not a successor.",
                  ["M§7.5"], {"check": "successor-check", "predecessor_roster": [ALICE, BOB], "creator": MALLORY,
                              "roster": [ALICE, BOB, MALLORY]}, reject("successor-invalid")))
    out.append(mv("successor-check-adds-outsider", "A successor that adds an identity outside the predecessor roster is rejected.",
                  ["M§7.5"], {"check": "successor-check", "predecessor_roster": [ALICE, BOB], "creator": BOB,
                              "roster": [ALICE, BOB, MALLORY]}, reject("successor-invalid")))
    # Pick two group ULIDs whose base64url text sorts opposite to the ULIDs themselves.
    ga, gb = None, None
    for i in range(200):
        u1, u2 = uid(f"succ-a-{i}", NOW), uid(f"succ-b-{i}", NOW)
        lo, hi = sorted([u1, u2])
        b_lo, b_hi = b64url_encode(lo.encode()), b64url_encode(hi.encode())
        if b_lo > b_hi:
            ga, gb = b_lo, b_hi
            break
    assert ga is not None
    out.append(mv("successor-select-compares-decoded-ulid",
                  "Concurrent successors converge on the lowest group_id compared as the decoded ULID; here the base64url "
                  "text sorts the other way.", ["M§7.5"],
                  {"check": "successor-select", "candidates": [gb, ga]}, {"winner": ga, "discarded": []}))
    junk = b64url_encode(b"not-a-ulid")
    out.append(mv("successor-select-invalid-group-id-discarded", "A group_id that is not a ULID cannot win.", ["M§7.5", "M§6.3"],
                  {"check": "successor-select", "candidates": [junk, ga]}, {"winner": ga, "discarded": [junk]}))
    return out


# ---------------------------------------------------------------- tranche 2: client receipts and activity (M§10, M§11.2)

def cl_ctx(me=BOB, delivered=True, read=False, played=False, activity=False, members=2):
    return {"component": "client", "me": me, "device": BPH, "now": NOW, "member_identities": members,
            "policy": {"delivered": delivered, "read": read, "played": played, "activity": activity}}


def cs(timeline=(), delivered=None, played=None, read_through=None):
    return {"timeline": list(timeline), "delivered": delivered or {}, "played": played or {}, "read_through": read_through or {}}


def item(seq, obj):
    return {"seq": seq, "object": obj}


def ct(label, sender=ALICE, kind="text"):
    return {"object": "content", "id": uid(label), "sender": sender, "kind": kind}


def rc(kind, sender, at=NOW, **kw):
    return {"object": "receipt", "kind": kind, "sender": sender, "sent_at": at, **kw}


def sync(*items):
    return {"sync": {"items": list(items)}}


def send(to, receipt, **kw):
    return {"send": {"to": to, "receipt": receipt, **kw}}


def client_vectors():
    out = []
    T = "client-trace"
    m1, m2, m3, vm = uid("m1"), uid("m2"), uid("m3"), uid("vm")

    out.append(trace("client-delivered-sent-once-per-batch",
                     "After a sync batch the device sends one delivered receipt covering every new item from other identities.",
                     ["M§10.2"], T, cl_ctx(), [
                         (sync(item(1, ct("m1")), item(2, ct("m2")), item(3, ct("m3", sender=BOB))),
                          [send("conversation", "delivered", targets=[m1, m2])], cs([m1, m2, m3])),
                         (sync(item(1, ct("m1"))), [], cs([m1, m2, m3])),
                     ]))
    out.append(trace("client-delivered-suppressed-by-sibling-in-batch",
                     "A sibling device's delivered receipt later in the same batch suppresses this device's receipt for that item.",
                     ["M§10.2"], T, cl_ctx(), [
                         (sync(item(1, ct("m1")), item(2, ct("m2")), item(3, rc("delivered", BOB, targets=[m1]))),
                          [send("conversation", "delivered", targets=[m2])], cs([m1, m2], delivered={m1: {BOB: NOW}})),
                     ]))
    out.append(trace("client-delivered-off-by-policy", "delivered receipts are not sent when the user has them off.",
                     ["M§10.2", "M§10.5"], T, cl_ctx(delivered=False), [
                         (sync(item(1, ct("m1"))), [], cs([m1])),
                     ]))
    out.append(trace("client-delivered-not-in-large-group", "No delivered receipts in groups over 32 member identities.",
                     ["M§10.2"], T, cl_ctx(members=33), [
                         (sync(item(1, ct("m1"))), [], cs([m1])),
                     ]))
    out.append(trace("client-receipts-collapse-first-by-seq",
                     "Duplicate delivered receipts from one identity collapse; the first by seq keeps its timestamp.",
                     ["M§10.2"], T, cl_ctx(me=ALICE, delivered=False), [
                         (sync(item(1, ct("m1")), item(2, rc("delivered", BOB, at=NOW + 1, targets=[m1])),
                               item(3, rc("delivered", BOB, at=NOW + 2, targets=[m1]))),
                          [], cs([m1], delivered={m1: {BOB: NOW + 1}})),
                     ]))
    out.append(trace("client-receipt-from-content-sender-ignored",
                     "An identity's receipt about its own content is not a sender-visible receipt.", ["M§10.2"], T,
                     cl_ctx(me=BOB, delivered=False), [
                         (sync(item(1, ct("m1")), item(2, rc("delivered", ALICE, targets=[m1]))), [], cs([m1])),
                     ]))
    out.append(trace("client-played-only-for-media", "played applies to audio and video content only.", ["M§10.4"], T,
                     cl_ctx(me=ALICE, delivered=False), [
                         (sync(item(1, ct("m1")), item(2, ct("vm", kind="audio")),
                               item(3, rc("played", BOB, targets=[m1, vm]))),
                          [], cs([m1, vm], played={vm: {BOB: NOW}})),
                     ]))
    out.append(trace("client-read-watermark-monotone",
                     "A read watermark only advances; a lower or unknown through is ignored.", ["M§10.3"], T,
                     cl_ctx(me=ALICE, delivered=False), [
                         (sync(item(1, ct("m1")), item(2, ct("m2")), item(3, rc("read", BOB, through=m2))),
                          [], cs([m1, m2], read_through={BOB: m2})),
                         (sync(item(4, rc("read", BOB, through=m1))), [], cs([m1, m2], read_through={BOB: m2})),
                         (sync(item(5, rc("read", BOB, through=uid("never-seen")))), [], cs([m1, m2], read_through={BOB: m2})),
                     ]))
    out.append(trace("client-read-private-goes-to-personal-group",
                     "With read receipts off, the device still syncs its watermark, to its personal group only.",
                     ["M§10.5"], T, cl_ctx(delivered=False, read=False), [
                         (sync(item(1, ct("m1"))), [], cs([m1])),
                         ({"read": {"through": m1}}, [send("personal", "read", through=m1)], cs([m1], read_through={BOB: m1})),
                     ]))
    out.append(trace("client-read-disclosed-goes-to-conversation",
                     "With read receipts opted in, the watermark goes to the conversation group.", ["M§10.5", "M§10.3"], T,
                     cl_ctx(delivered=False, read=True), [
                         (sync(item(1, ct("m1"))), [], cs([m1])),
                         ({"read": {"through": m1}}, [send("conversation", "read", through=m1)], cs([m1], read_through={BOB: m1})),
                     ]))
    out.append(trace("client-read-sibling-watermark-suppresses",
                     "A sibling device's watermark already covering the item means reading it here sends nothing.",
                     ["M§10.3"], T, cl_ctx(delivered=False, read=True), [
                         (sync(item(1, ct("m1")), item(2, ct("m2")), item(3, rc("read", BOB, through=m2))),
                          [], cs([m1, m2], read_through={BOB: m2})),
                         ({"read": {"through": m1}}, [], cs([m1, m2], read_through={BOB: m2})),
                     ]))
    out.append(trace("client-read-rate-limited",
                     "At most one watermark per conversation per 5 s: a later read is held and the latest watermark sent when the "
                     "interval passes.", ["M§10.3"], T, cl_ctx(delivered=False, read=True), [
                         (sync(item(1, ct("m1")), item(2, ct("m2")), item(3, ct("m3"))), [], cs([m1, m2, m3])),
                         ({"read": {"through": m1}}, [send("conversation", "read", through=m1)], cs([m1, m2, m3], read_through={BOB: m1})),
                         ({"advance": 1}, [], cs([m1, m2, m3], read_through={BOB: m1})),
                         ({"read": {"through": m2}}, [], cs([m1, m2, m3], read_through={BOB: m2})),
                         ({"read": {"through": m3}}, [], cs([m1, m2, m3], read_through={BOB: m3})),
                         ({"advance": 3}, [], cs([m1, m2, m3], read_through={BOB: m3})),
                         ({"advance": 1}, [send("conversation", "read", through=m3)], cs([m1, m2, m3], read_through={BOB: m3})),
                     ]))
    out.append(trace("client-played-sent-once-when-opted-in", "A played receipt is sent once, for media, when opted in.",
                     ["M§10.4", "M§10.5"], T, cl_ctx(delivered=False, played=True), [
                         (sync(item(1, ct("vm", kind="audio")), item(2, ct("m1"))), [], cs([vm, m1])),
                         ({"play": {"id": m1}}, [], cs([vm, m1])),
                         ({"play": {"id": vm}}, [send("conversation", "played", targets=[vm])], cs([vm, m1])),
                         ({"play": {"id": vm}}, [], cs([vm, m1])),
                     ]))
    out.append(trace("client-played-off-by-default", "played receipts are not sent without opt-in.", ["M§10.5"], T,
                     cl_ctx(delivered=False), [
                         (sync(item(1, ct("vm", kind="audio"))), [], cs([vm])),
                         ({"play": {"id": vm}}, [], cs([vm])),
                     ]))
    out.append(trace("client-duplicate-content-collapses",
                     "The same content id arriving again (another mailbox, a successor group) is collapsed and keeps its first place.",
                     ["M§8.5"], T, cl_ctx(delivered=False), [
                         (sync(item(1, ct("m1")), item(2, ct("m2"))), [], cs([m1, m2])),
                         (sync(item(7, ct("m1"))), [], cs([m1, m2])),
                     ]))
    act = lambda a, st: {"activity": {"activity": a, "state": st}}
    typing = lambda st: {"send": {"to": "conversation", "activity": "typing", "state": st}}
    out.append(trace("client-activity-refresh-bounded",
                     "Typing refreshes are sent at most every 5 s; stopped is always sent.", ["M§11.2"], T,
                     cl_ctx(delivered=False, activity=True), [
                         (act("typing", "active"), [typing("active")], cs()),
                         ({"advance": 2}, [], cs()),
                         (act("typing", "active"), [], cs()),
                         ({"advance": 3}, [], cs()),
                         (act("typing", "active"), [typing("active")], cs()),
                         (act("typing", "stopped"), [typing("stopped")], cs()),
                         (act("typing", "active"), [typing("active")], cs()),
                     ]))
    out.append(trace("client-activity-off-by-default", "Activity is not sent without opt-in.", ["M§11.2", "M§10.5"], T,
                     cl_ctx(delivered=False), [
                         (act("typing", "active"), [], cs()),
                     ]))
    return out


# ---------------------------------------------------------------- tranche 2: seq gaps (M§6.5)

def gap_vectors():
    out = []
    T = "gap-trace"
    ctx = {"component": "gap", "now": NOW, "contiguous": 0}
    it = lambda seq, cls="application": {"item": {"seq": seq, "class": cls}}
    g = lambda contiguous, held=(): {"contiguous": contiguous, "held": list(held)}
    out.append(trace("gap-in-order", "Items in seq order are processed as they arrive.", ["M§6.5"], T, ctx, [
        (it(1, "handshake"), [{"process": 1}], g(1)),
        (it(2), [{"process": 2}], g(2)),
    ]))
    out.append(trace("gap-application-across-gap-processed",
                     "An application item beyond a gap is processed; nothing is held.", ["M§6.5"], T, ctx, [
                         (it(1), [{"process": 1}], g(1)),
                         (it(3), [{"process": 3}], g(1)),
                         (it(2), [{"process": 2}], g(3)),
                     ]))
    out.append(trace("gap-handshake-held-until-filled",
                     "A handshake item beyond a gap is held, and so is everything after it, until the gap fills.", ["M§6.5"], T, ctx, [
                         (it(1), [{"process": 1}], g(1)),
                         (it(3, "handshake"), [{"hold": 3}], g(1, [3])),
                         (it(4), [{"hold": 4}], g(1, [3, 4])),
                         (it(2), [{"process": 2}, {"process": 3}, {"process": 4}], g(4)),
                     ]))
    out.append(trace("gap-timeout-rejoins",
                     "A gap not filled within 300 s of the first held item makes the device re-join by external commit.",
                     ["M§6.5", "M§6.8"], T, ctx, [
                         (it(1), [{"process": 1}], g(1)),
                         (it(3, "handshake"), [{"hold": 3}], g(1, [3])),
                         ({"advance": 299}, [], g(1, [3])),
                         ({"advance": 1}, [{"rejoin": {"held": [3]}}], g(3)),
                         (it(2), [{"duplicate": 2}], g(3)),
                     ]))
    out.append(trace("gap-duplicate-seq", "A seq already processed is reported as a duplicate and not processed again.",
                     ["M§6.5", "M§8.5"], T, ctx, [
                         (it(1), [{"process": 1}], g(1)),
                         (it(1), [{"duplicate": 1}], g(1)),
                     ]))
    return out
