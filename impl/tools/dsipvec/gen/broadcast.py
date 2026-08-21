"""Broadcast vectors (kind `broadcast`) — receiver-side verification of publication records and provenance (§22)."""
from __future__ import annotations

import copy

from .. import fixtures as F
from .common import NOW, signed, default_context, vector, accept, reject, uid

BOB, BPH, CAROL, CPH, ALICE = F.did("bob"), F.did("bob-phone"), F.did("carol"), F.did("carol-phone"), F.did("alice")
STREAM = BOB + ":radio:main"
BCAST = {"core": "1.0", "min_core": "1.0", "profiles": ["verified-broadcast/1.0"], "extensions": [], "critical": []}
VARIANTS = [
    {"id": "main-opus", "media": ["audio"], "codec": "codec:audio/opus", "transport": "transport:webrtc",
     "uri": "wss://live.bob.example/dsip/webrtc/main"},
    {"id": "main-aac-hls", "media": ["audio"], "codec": "codec:audio/aac", "transport": "transport:hls",
     "uri": "https://live.bob.example/main.m3u8"},
]
CAPS_WEBRTC = {"codecs": ["codec:audio/opus"], "transports": ["transport:webrtc"]}
CAPS_BOTH = {"codecs": ["codec:audio/opus", "codec:audio/aac"], "transports": ["transport:webrtc", "transport:hls"]}
CAPS_HLS = {"codecs": ["codec:audio/aac"], "transports": ["transport:hls"]}


def publication(label="pub", publisher=BOB, frm=BOB, stream=STREAM, at=NOW, ttl=300, state="live", policy=None, variants=None,
                integrity="metadata-only"):
    return {"dsip": copy.deepcopy(BCAST), "type": "publish", "id": uid(label, at), "from": frm, "publisher": publisher,
            "stream_id": stream, "title": "Bob Live Radio", "state": state, "integrity": integrity,
            "variants": copy.deepcopy(variants or VARIANTS),
            "policy": policy if policy is not None else {"redistribution": "allowed-with-attribution", "transcoding": "allowed"},
            "issued_at": at, "expires_at": at + ttl}


def provenance(pub_id, label="prov", processor=CAROL, frm=CAROL, stream=STREAM, operation="transcode",
               input_variant="main-opus", output_variant="main-aac-hls", at=NOW + 5):
    return {"dsip": copy.deepcopy(BCAST), "type": "provenance", "id": uid(label, at), "from": frm,
            "original_stream": stream, "original_publication": pub_id, "processor": processor, "operation": operation,
            "input_variant": input_variant, "output_variant": output_variant,
            "output_uri": "https://cdn.carol.example/bob/main.m3u8", "issued_at": at, "expires_at": at + 3600}


def bv(vid, desc, refs, pub_env, expect, prov_envs=(), caps=None, ctx=None):
    inp = {"publication": pub_env, "provenance": list(prov_envs), "capabilities": caps or CAPS_BOTH}
    return vector(f"broadcast/{vid}", "broadcast", desc, refs, ctx or default_context(), inp, expect)


def pub_accept(selected, provenance=(), transcoded=(), delivered=(), integrity="metadata-only", signer=BOB, identity=BOB):
    return accept(type="publish", signer=signer, identity=identity, selected_variant=selected,
                  provenance=list(provenance),
                  display={"original_publisher": BOB, "delivered_by": list(delivered), "transcoded_by": list(transcoded),
                           "integrity_mode": integrity})


def vectors() -> list[dict]:
    out = []
    pub = publication()
    pub_env = signed(pub, "bob")
    out.append(bv("publication-valid-metadata-only", "Publisher-signed record; receiver selects the first variant it supports (publisher order = preference).",
                  ["§22.1", "§22.2"], pub_env, pub_accept("main-opus"), caps=CAPS_BOTH))
    out.append(bv("publication-variant-selection-hls", "A receiver with only HLS/AAC selects the second variant.", ["§22.1"],
                  pub_env, pub_accept("main-aac-hls"), caps=CAPS_HLS))
    out.append(bv("publication-no-compatible-variant", "No advertised variant matches the receiver; the record is still verified.", ["§22.1"],
                  pub_env, pub_accept(None), caps={"codecs": ["codec:video/av1"], "transports": ["transport:webrtc"]}))
    out.append(bv("publication-delegated-device", "Record for bob's identity signed by bob-phone under a live delegation.", ["§22.1", "§7.4"],
                  signed(publication(frm=BOB), "bob-phone"), pub_accept("main-opus", signer=BPH), caps=CAPS_WEBRTC))
    out.append(bv("publication-publisher-mismatch", "Record names alice as publisher but is signed by bob (Impl, spec-gap 18).", ["§22.1", "§8.1"],
                  signed(publication(publisher=ALICE, stream=ALICE + ":radio"), "bob"), reject("publisher-mismatch")))
    out.append(bv("publication-stream-outside-namespace", "stream_id is not under the publisher DID (Impl, spec-gap 18).", ["§22.1"],
                  signed(publication(stream="did:web:wxyz.com:radio:main"), "bob"), reject("stream-id-namespace")))
    out.append(bv("publication-expired", "Publication past expires_at is rejected before anything else.", ["§12.9", "§22.1"],
                  signed(publication(at=NOW - 200, ttl=100), "bob"), reject("expired")))
    out.append(bv("publication-schema-bad-variant", "Variant without a uri fails the publish schema.", ["§22.1"],
                  signed(publication(variants=[{"id": "x", "media": ["audio"], "codec": "codec:audio/opus", "transport": "transport:webrtc"}]), "bob"),
                  reject("schema-invalid")))

    # §22.2 (v0.7, spec-gap 20): record-level integrity with variant override and registry fallback
    out.append(bv("publication-integrity-derivative-bound-declared", "The record itself declares derivative-bound; with no statements the receiver shows the declared mode.",
                  ["§22.2"], signed(publication("pub-db", integrity="derivative-bound"), "bob"), pub_accept("main-opus", integrity="derivative-bound")))
    out.append(bv("publication-integrity-unknown-mode", "A reserved/unknown integrity token (frame-bound) falls back to metadata-only (registry membership, not a closed enum).",
                  ["§22.2", "§15.6"], signed(publication("pub-fb", integrity="frame-bound"), "bob"), pub_accept("main-opus", integrity="metadata-only")))
    vo = copy.deepcopy(VARIANTS); vo[0]["integrity"] = "derivative-bound"
    out.append(bv("publication-variant-integrity-override", "The selected variant overrides the record-level mode.", ["§22.2"],
                  signed(publication("pub-vo", variants=vo), "bob"), pub_accept("main-opus", integrity="derivative-bound"), caps=CAPS_WEBRTC))

    prov_ok = signed(provenance(pub["id"]), "carol")
    out.append(bv("provenance-derivative-bound", "A transcoder's signed statement references the original record; receiver displays publisher + processor, integrity derivative-bound.",
                  ["§22.2", "§22.3"], pub_env,
                  pub_accept("main-opus", provenance=[{"verdict": "accept", "processor": CAROL, "operation": "transcode", "integrity_mode": "derivative-bound"}],
                             transcoded=[CAROL], integrity="derivative-bound"), prov_envs=[prov_ok]))
    out.append(bv("provenance-relay-operation", "A relay statement (operation relay) shows as delivered-by; integrity stays metadata-only.", ["§22.3"],
                  pub_env, pub_accept("main-opus", provenance=[{"verdict": "accept", "processor": CAROL, "operation": "relay", "integrity_mode": "derivative-bound"}],
                                      delivered=[CAROL], integrity="metadata-only"),
                  prov_envs=[signed(provenance(pub["id"], operation="relay", output_variant="main-opus"), "carol")]))
    out.append(bv("provenance-wrong-publication", "Statement references a publication id that is not this record.", ["§22.3"], pub_env,
                  pub_accept("main-opus", provenance=[{"verdict": "reject", "code": "provenance-unknown-publication"}]),
                  prov_envs=[signed(provenance(uid("other-pub")), "carol")]))
    out.append(bv("provenance-processor-mismatch", "Statement claims processor alice but is signed by carol.", ["§22.3"], pub_env,
                  pub_accept("main-opus", provenance=[{"verdict": "reject", "code": "provenance-processor-mismatch"}]),
                  prov_envs=[signed(provenance(pub["id"], processor=ALICE), "carol")]))
    out.append(bv("provenance-unknown-input-variant", "Statement transcodes a variant the record does not advertise.", ["§22.3"], pub_env,
                  pub_accept("main-opus", provenance=[{"verdict": "reject", "code": "provenance-variant-unknown"}]),
                  prov_envs=[signed(provenance(pub["id"], input_variant="nope"), "carol")]))
    out.append(bv("provenance-unsigned-by-processor", "Statement signed by mallory (no delegation from carol).", ["§22.3", "§7.4"], pub_env,
                  pub_accept("main-opus", provenance=[{"verdict": "reject", "code": "signer-mismatch"}]),
                  prov_envs=[signed(provenance(pub["id"]), "mallory")]))
    out.append(bv("provenance-schema-invalid", "Statement missing output_variant fails the provenance schema.", ["§22.3"], pub_env,
                  pub_accept("main-opus", provenance=[{"verdict": "reject", "code": "schema-invalid"}]),
                  prov_envs=[signed({k: v for k, v in provenance(pub["id"]).items() if k != "output_variant"}, "carol")]))
    forb = publication("pub-forbid", policy={"redistribution": "allowed-with-attribution", "transcoding": "forbidden"})
    out.append(bv("provenance-policy-transcoding-forbidden", "Publisher policy forbids transcoding; the statement verifies but the receiver flags the violation (§16.4: policy is displayed, not magic).",
                  ["§22.3", "§16.4"], signed(forb, "bob"),
                  pub_accept("main-opus", provenance=[{"verdict": "accept", "processor": CAROL, "operation": "transcode", "integrity_mode": "derivative-bound",
                                                       "policy_violation": "transcoding"}], transcoded=[CAROL], integrity="derivative-bound"),
                  prov_envs=[signed(provenance(forb["id"]), "carol")]))
    out.append(bv("provenance-chain-two-processors", "Relay then transcoder: both processors displayed in their roles.", ["§22.3"], pub_env,
                  pub_accept("main-opus", provenance=[{"verdict": "accept", "processor": CAROL, "operation": "relay", "integrity_mode": "derivative-bound"},
                                                      {"verdict": "accept", "processor": ALICE, "operation": "transcode", "integrity_mode": "derivative-bound"}],
                             delivered=[CAROL], transcoded=[ALICE], integrity="derivative-bound"),
                  prov_envs=[signed(provenance(pub["id"], operation="relay", output_variant="main-opus"), "carol"),
                             signed(provenance(pub["id"], label="prov2", processor=ALICE, frm=ALICE), "alice")]))
    return out
