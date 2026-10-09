"""`alias-transparency/` vectors — the Alias Transparency Profile's stage-1 building blocks (T§2, T§3, T§5).

Expected values come from outside references where they exist (RFC 9381 Appendix B.3; katie's commitment test; the
KEYTRANS draft's worked search-tree and ladder examples), by hand where they are simple encodings, and otherwise
are computed here and confirmed by the KEYTRANS editor's implementation (katie) — see spec-gap 104.
"""
from __future__ import annotations

from ..crypto import keypair_from_seed_name
from .. import kt
from .. import kt_vrf as vrf
from .common import vector

REFS = ["T§5"]
# RFC 9381 Appendix B.3, Examples 16–18: (SK, PK, alpha, pi, beta)
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
     "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
     "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
     "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"),
]
VRF_SK = bytes.fromhex(RFC[0][0])
VRF_PK = RFC[0][1]


def kv(vid, desc, inp, expect, refs=None):
    return vector(f"alias-transparency/{vid}", "alias-transparency", desc, refs or REFS, {}, inp, expect)


def vectors() -> list[dict]:
    out = []
    # --- T§3 alias normalization (by hand) -----------------------------------------------------------
    for vid, alias, want in [
        ("alias-tel-plain", "tel:+15551234567", "tel:+15551234567"),
        ("alias-tel-separators-removed", "tel:+1-555-123-4567", "tel:+15551234567"),
        ("alias-tel-dots-parens", "TEL:+1.(555).123.4567", "tel:+15551234567"),
        ("alias-tel-scheme-case", "Tel:+447700900123", "tel:+447700900123"),
        ("alias-tel-local-number", "tel:5551234567", None),
        ("alias-tel-parameter", "tel:+15551234567;ext=12", None),
        ("alias-tel-space", "tel:+1 555 123 4567", None),
        ("alias-tel-leading-zero", "tel:+05551234567", None),
        ("alias-tel-too-long", "tel:+1555123456789012", None),
        ("alias-tel-one-digit", "tel:+1", None),
        ("alias-tel-empty", "tel:", None),
        ("alias-tel-with-at", "tel:+15551234567@example.com", None),
        ("alias-domain-lowercased", "Alice@Example.COM", "Alice@example.com"),
        ("alias-local-case-kept", "BOB.Smith+x@example.org", "BOB.Smith+x@example.org"),
        ("alias-a-label-domain", "carol@xn--bcher-kva.example", "carol@xn--bcher-kva.example"),
        ("alias-split-at-last-at", "\"a@b\"@example.com", None),
        ("alias-no-at", "alice.example.com", None),
        ("alias-empty-local", "@example.com", None),
        ("alias-single-label-domain", "alice@localhost", None),
        ("alias-label-leading-hyphen", "alice@-x.example.com", None),
        ("alias-label-trailing-hyphen", "alice@x-.example.com", None),
        ("alias-label-inner-hyphen", "alice@x-y.example.com", "alice@x-y.example.com"),
        ("alias-u-label-domain", "dave@bücher.example", None),
        ("alias-non-ascii-local", "élise@example.com", None),
        ("alias-space-in-local", "al ice@example.com", None),
        ("alias-too-long", "a" * 244 + "@example.com", None),
        ("alias-at-limit", "a" * 243 + "@example.com", "a" * 243 + "@example.com"),
    ]:
        out.append(kv(vid, f"T§3: {alias[:40]!r} → {want[:40] if want else 'not an alias'}.", {"check": "alias", "alias": alias},
                      {"label": want} if want else {"error": "not-an-alias"}, ["T§3"]))

    # --- VrfInput (by hand: u8 length ‖ label ‖ u32 version, big-endian) -------------------------------
    out.append(kv("vrf-input-alice-v0", "The draft's example: alice@example.com, version 0.",
                  {"check": "vrf-input", "label": "alice@example.com", "version": 0},
                  {"bytes": "11" + b"alice@example.com".hex() + "00000000"}))
    out.append(kv("vrf-input-version-max", "Version 2^32−1.", {"check": "vrf-input", "label": "a@b.c", "version": 4294967295},
                  {"bytes": "05" + b"a@b.c".hex() + "ffffffff"}))
    out.append(kv("vrf-input-label-too-long", "A label of 256 bytes does not fit the <0..2^8-1> vector.",
                  {"check": "vrf-input", "label": "x" * 256, "version": 0}, {"error": "vrf-input"}))

    # --- ECVRF (RFC 9381 Appendix B.3) ---------------------------------------------------------------
    for n, (sk, pk, alpha, pi, beta) in enumerate(RFC, 16):
        out.append(kv(f"vrf-rfc9381-example-{n}", f"RFC 9381 Appendix B.3 Example {n}: the proof verifies and gives beta.",
                      {"check": "vrf-verify", "public_key": pk, "alpha": alpha, "proof": pi}, {"valid": True, "beta": beta},
                      ["T§2", "T§5"]))
    sk, pk, alpha, pi, beta = RFC[0]
    bad_c = pi[:64] + ("%02x" % (int(pi[64:66], 16) ^ 1)) + pi[66:]
    out.append(kv("vrf-tampered-challenge", "Example 16's proof with one bit of c flipped.",
                  {"check": "vrf-verify", "public_key": pk, "alpha": alpha, "proof": bad_c}, {"valid": False, "beta": None}))
    out.append(kv("vrf-wrong-alpha", "Example 16's proof checked against another input.",
                  {"check": "vrf-verify", "public_key": pk, "alpha": "00", "proof": pi}, {"valid": False, "beta": None}))
    out.append(kv("vrf-low-order-key", "validate_key: a public key of low order (the identity point) is refused.",
                  {"check": "vrf-verify", "public_key": "01" + "00" * 31, "alpha": alpha, "proof": pi}, {"valid": False, "beta": None},
                  ["T§2"]))
    out.append(kv("vrf-low-order-key-sign-bit", "A low-order key (y = 0, an order-4 point) with its sign bit set is refused.",
                  {"check": "vrf-verify", "public_key": "00" * 31 + "80", "alpha": alpha, "proof": pi}, {"valid": False, "beta": None},
                  ["T§2"]))
    out.append(kv("vrf-gamma-not-canonical", "A proof whose Gamma encodes x = 0 with the sign bit set (not canonical, RFC 8032 §5.1.3).",
                  {"check": "vrf-verify", "public_key": pk, "alpha": alpha, "proof": "01" + "00" * 30 + "80" + pi[64:]},
                  {"valid": False, "beta": None}))
    out.append(kv("vrf-key-y-not-reduced", "A public key encoding y ≥ p (2^255 − 19 + 1) is not canonical.",
                  {"check": "vrf-verify", "public_key": "ee" + "ff" * 30 + "7f", "alpha": alpha, "proof": pi},
                  {"valid": False, "beta": None}))
    out.append(kv("vrf-s-not-reduced", "A proof whose scalar s is not below the group order is refused (RFC 9381 §5.4.4).",
                  {"check": "vrf-verify", "public_key": pk, "alpha": alpha, "proof": pi[:96] + "ff" * 32}, {"valid": False, "beta": None}))
    out.append(kv("vrf-short-proof", "A proof of 79 bytes.", {"check": "vrf-verify", "public_key": pk, "alpha": alpha, "proof": pi[:-2]},
                  {"valid": False, "beta": None}))

    # --- the index of a label (computed; confirmed by katie) ------------------------------------------
    for label, ver in [("alice@example.com", 0), ("alice@example.com", 1), ("bob@example.com", 0)]:
        proof = vrf.prove(VRF_SK, kt.vrf_input(label.encode(), ver))
        idx = vrf.proof_to_hash(proof)[:32]
        out.append(kv(f"index-{label.split('@')[0]}-v{ver}", f"The index of ({label}, {ver}): the first 32 bytes of beta.",
                      {"check": "index", "public_key": VRF_PK, "label": label, "version": ver, "proof": proof.hex()},
                      {"index": idx.hex()}))
    proof = vrf.prove(VRF_SK, kt.vrf_input(b"alice@example.com", 0))
    out.append(kv("index-proof-for-another-version", "A proof for version 0 presented for version 1 gives no index.",
                  {"check": "index", "public_key": VRF_PK, "label": "alice@example.com", "version": 1, "proof": proof.hex()},
                  {"error": "vrf-invalid"}))

    # --- commitments ---------------------------------------------------------------------------------
    out.append(kv("commitment-katie-vector-1", "katie's commitment test: HMAC-SHA256(Kc, opening ‖ empty body) — Kc is the 16 raw bytes.",
                  {"check": "commitment-raw", "opening": "000102030405060708090a0b0c0d0e0f", "body": ""},
                  {"commitment": "51dde6316662100215a7cc1878113d416ec25d9443310989e0672bac6e8ea9da"}))
    opening = bytes(range(16))
    for label, ver, value in [("alice@example.com", 0, "did:web:alice.example"), ("alice@example.com", 1, "did:webvh:QmXpnm4R7BPTnL6iWNL5HJhq1sSUjkc3dudv2BRuSJWBbC:alice.example")]:
        c = kt.commitment(opening, label.encode(), ver, value.encode())
        out.append(kv(f"commitment-alice-v{ver}", f"The commitment to ({label}, {ver}) → {value[:24]}….",
                      {"check": "commitment", "opening": opening.hex(), "label": label, "version": ver, "value": value},
                      {"commitment": c.hex()}))
    out.append(kv("commitment-label-too-long", "A label of 256 bytes.", {"check": "commitment", "opening": "00" * 16,
                  "label": "x" * 256, "version": 0, "value": "did:key:z6Mk"}, {"error": "label"}))
    out.append(kv("commitment-opening-not-16", "An opening of 15 bytes.", {"check": "commitment", "opening": "00" * 15,
                  "label": "a@b.c", "version": 0, "value": "did:key:z6Mk"}, {"error": "opening"}))

    # --- trees (computed; confirmed by katie) ---------------------------------------------------------
    idx = [vrf.proof_to_hash(vrf.prove(VRF_SK, kt.vrf_input(lb.encode(), 0)))[:32] for lb in ("alice@example.com", "bob@example.com", "carol@example.com")]
    com = [kt.commitment(opening, lb.encode(), 0, b"did:key:z6Mk" + lb.encode()) for lb in ("alice@example.com", "bob@example.com", "carol@example.com")]
    leaves = [{"index": i.hex(), "commitment": c.hex()} for i, c in zip(idx, com)]
    for n in (1, 2, 3):
        root = kt.prefix_root({i: c for i, c in zip(idx[:n], com[:n])})
        out.append(kv(f"prefix-root-{n}-leaves", f"The prefix tree of {n} leaves: each leaf only as deep as it must be.",
                      {"check": "prefix-root", "leaves": leaves[:n]}, {"root": root.hex()}))
    out.append(kv("prefix-root-short-index", "A leaf whose index is not 32 bytes.",
                  {"check": "prefix-root", "leaves": [{"index": "00" * 31, "commitment": "00" * 32}]}, {"error": "malformed"}))
    out.append(kv("prefix-root-duplicate-index", "Two leaves with the same index.",
                  {"check": "prefix-root", "leaves": [leaves[0], leaves[0]]}, {"error": "malformed"}))
    out.append(kv("log-root-empty", "A log of no entries has no root.", {"check": "log-root", "entries": []}, {"error": "malformed"}))
    out.append(kv("prefix-parent-missing-child", "A parent with no right child hashes 32 zero bytes in its place.",
                  {"check": "prefix-parent", "left": "11" * 32, "right": None}, {"hash": kt.prefix_parent(b"\x11" * 32, None).hex()}))
    pr = [kt.sha(bytes([n]) * 3) for n in range(7)]
    for n in (1, 2, 3, 5, 7):
        entries = [{"timestamp": 1790000000000 + 1000 * j, "prefix_root": pr[j].hex()} for j in range(n)]
        root = kt.log_root([kt.log_leaf(e["timestamp"], bytes.fromhex(e["prefix_root"])) for e in entries])
        out.append(kv(f"log-root-{n}", f"A log of {n} entries: left-balanced, hashContent tags 0x00/0x01.",
                      {"check": "log-root", "entries": entries}, {"root": root.hex()}))

    # --- Configuration and tree heads -----------------------------------------------------------------
    sig = keypair_from_seed_name("kt-provider")
    cfg = {"ciphersuite": 2, "mode": 1, "signature_public_key": sig.public.hex(), "vrf_public_key": VRF_PK,
           "max_ahead": 60000, "max_behind": 86400000, "reasonable_monitoring_window": 3600000, "maximum_lifetime": None}
    cb = kt.configuration({**cfg, **{k: bytes.fromhex(cfg[k]) for k in ("signature_public_key", "vrf_public_key")}})
    # the KEYTRANS editors' copy (and katie): mode 1 carries no leaf_public_key (spec-gap 104)
    hand = ("0002" + "01" + "0020" + cfg["signature_public_key"] + "0020" + VRF_PK
            + "%016x" % 60000 + "%016x" % 86400000 + "%016x" % 3600000 + "00")
    assert cb.hex() == hand
    out.append(kv("configuration-mode1", "A mode-1 Configuration, encoded by hand from [KT] §11.2 (editors' copy: no leaf key).", {"check": "configuration", "config": cfg},
                  {"bytes": hand}))
    life = hand[:-2] + "01" + "%016x" % 604800000
    accepted = {"signature_public_key": cfg["signature_public_key"], "vrf_public_key": VRF_PK,
                "max_ahead": 60000, "max_behind": 86400000, "reasonable_monitoring_window": 3600000}
    out.append(kv("configuration-accept", "A suite-2, mode-1 Configuration is accepted.", {"check": "configuration-accept", "bytes": hand},
                  {"config": {**accepted, "maximum_lifetime": None}}, ["T§2"]))
    out.append(kv("configuration-accept-lifetime", "optional<uint64> maximum_lifetime present.",
                  {"check": "configuration-accept", "bytes": life}, {"config": {**accepted, "maximum_lifetime": 604800000}}, ["T§2"]))
    out.append(kv("configuration-p256-refused", "Suite 0x0001 (P-256) is not this profile's.", {"check": "configuration-accept",
                  "bytes": "0001" + hand[4:]}, {"error": "unsupported-suite"}, ["T§2"]))
    out.append(kv("configuration-mode3-refused", "Mode 3 (third-party auditing) is not this profile's.",
                  {"check": "configuration-accept", "bytes": hand[:4] + "03" + hand[6:]}, {"error": "unsupported-mode"}, ["T§2"]))
    out.append(kv("configuration-optional-flag-2", "An optional<> presence byte of 2 is malformed ([KT] §2.1).",
                  {"check": "configuration-accept", "bytes": hand[:-2] + "02"}, {"error": "malformed"}, ["T§2"]))
    out.append(kv("configuration-duration-beyond-2p53", "A reasonable_monitoring_window above 2^53−1 ms is refused.",
                  {"check": "configuration-accept", "bytes": hand[:-18] + "%016x" % (2**53) + "00"}, {"error": "malformed"}, ["T§2"]))
    out.append(kv("configuration-05-leaf-key-is-trailing", "The -05 layout (with a leaf key) leaves bytes over in the editors' layout.",
                  {"check": "configuration-accept", "bytes": hand[:4 + 2 + 68 + 68] + "0020" + "77" * 32 + hand[4 + 2 + 68 + 68:]},
                  {"error": "malformed"}, ["T§2"]))
    out.append(kv("configuration-trailing-byte", "A Configuration with a byte after its end.",
                  {"check": "configuration-accept", "bytes": hand + "00"}, {"error": "malformed"}, ["T§2"]))
    root = kt.log_root([kt.log_leaf(1790000000000, pr[0])])
    tbs = cb + kt.u64(1) + root
    s = sig.sign(tbs).hex()
    out.append(kv("tree-head-valid", "A tree head signed over TreeHeadTBS(Configuration, tree_size, root).",
                  {"check": "tree-head", "configuration": hand, "tree_size": 1, "root": root.hex(), "signature": s}, {"valid": True}))
    out.append(kv("tree-head-wrong-size", "The same signature with tree_size 2.",
                  {"check": "tree-head", "configuration": hand, "tree_size": 2, "root": root.hex(), "signature": s}, {"valid": False}))
    out.append(kv("tree-head-other-configuration", "The signature binds the Configuration: a different RMW does not verify.",
                  {"check": "tree-head", "configuration": hand[:-18] + "%016x" % 1800000 + "00", "tree_size": 1, "root": root.hex(),
                   "signature": s}, {"valid": False}))

    # --- the implicit search tree and the binary ladder (the draft's own examples) --------------------
    for n, root_, front in [(50, 31, [31, 47, 49]), (13, 7, [7, 11, 12]), (1, 0, [0]), (8, 7, [7])]:
        out.append(kv(f"search-tree-{n}", f"[KT] §4.1 / Appendix A: n={n}.", {"check": "search-tree", "n": n},
                      {"root": root_, "frontier": front}))
    for t, lad in [(6, [0, 1, 3, 7, 5, 6]), (2, [0, 1, 3, 2]), (0, [0, 1]), (7, [0, 1, 3, 7, 15, 11, 9, 8])]:
        out.append(kv(f"ladder-{t}", f"[KT] §5: the base binary ladder for version {t}.", {"check": "ladder", "version": t}, {"ladder": lad}))
    return out
