"""Number bindings (Number Attestation Profile draft, N§3; spec-gap 110): a STIR-signed `tn → DID` statement.

A test STIR PKI is built here with a small DER writer, so certificates that break one rule each can be made on
purpose. Keys are P-256 scalars from sha256("dsip-vector-tn:" + name), and every signature uses RFC 6979's
deterministic nonce, so the vectors regenerate byte for byte. Expectations are hand-written from the profile and
the README's check order, never read back from a verifier.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .common import vector, NOW

REFS = ["N§3"]
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# --- DER --------------------------------------------------------------------------------------------------------


def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(b)]) + b + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(items))


def explicit(n: int, content: bytes) -> bytes:
    return tlv(0xA0 + n, content)


def oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def integer(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, b)


def boolean(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def ia5(s: str) -> bytes:
    return tlv(0x16, s.encode("ascii"))


def bitstring(b: bytes, unused: int = 0) -> bytes:
    return tlv(0x03, bytes([unused]) + b)


def octet(b: bytes) -> bytes:
    return tlv(0x04, b)


def gtime(t: int) -> bytes:
    import datetime
    d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    if 1950 <= d.year < 2050:
        return tlv(0x17, d.strftime("%y%m%d%H%M%SZ").encode())
    return tlv(0x18, d.strftime("%Y%m%d%H%M%SZ").encode())


O, CN, C = "2.5.4.10", "2.5.4.3", "2.5.4.6"


def name(*attrs: tuple[str, str]) -> bytes:
    """attrs: (oid, value); C is PrintableString, everything else UTF8String."""
    rdns = []
    for a, v in attrs:
        val = tlv(0x13 if a == C else 0x0C, v.encode())
        rdns.append(set_(seq(oid(a), val)))
    return seq(*rdns)


# --- keys -------------------------------------------------------------------------------------------------------

def key(label: str, curve=None) -> ec.EllipticCurvePrivateKey:
    curve = curve or ec.SECP256R1()
    d = int.from_bytes(hashlib.sha256(b"dsip-vector-tn:" + label.encode()).digest(), "big")
    order = N_P256 if isinstance(curve, ec.SECP256R1) else 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    return ec.derive_private_key(d % (order - 1) + 1, curve)


def spki(k: ec.EllipticCurvePrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


ECDSA_SHA256, ECDSA_SHA384 = "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3"
BC, KU, TNAUTH, SKI = "2.5.29.19", "2.5.29.15", "1.3.6.1.5.5.7.1.26", "2.5.29.14"


def ext(o: str, value: bytes, critical: bool = False) -> bytes:
    return seq(oid(o), *( [boolean(True)] if critical else []), octet(value))


def bc(ca: bool, pathlen: int | None = None) -> bytes:
    items = [boolean(True)] if ca else []
    if pathlen is not None:
        items.append(integer(pathlen))
    return ext(BC, seq(*items), critical=True)


def ku(*bits: int) -> bytes:
    """keyUsage named bits (0 digitalSignature, 5 keyCertSign, 6 cRLSign), DER-minimal."""
    v = 0
    for b in bits:
        v |= 1 << (15 - b)
    raw = v.to_bytes(2, "big").rstrip(b"\x00") or b"\x00"
    last = raw[-1]
    unused = (last & -last).bit_length() - 1 if last else 0
    return ext(KU, bitstring(raw, unused), critical=True)


def tn_one(d: str) -> bytes:
    return explicit(2, ia5(d))


def tn_range(start: str, count: int) -> bytes:
    return explicit(1, seq(ia5(start), integer(count)))


def tn_spc(s: str) -> bytes:
    return explicit(0, ia5(s))


def tnauth(*entries: bytes, raw: bytes | None = None) -> bytes:
    return ext(TNAUTH, raw if raw is not None else seq(*entries))


def sign(k: ec.EllipticCurvePrivateKey, data: bytes, h=None) -> bytes:
    return k.sign(data, ec.ECDSA(h or hashes.SHA256(), deterministic_signing=True))


class Cert:
    def __init__(self, der: bytes, k: ec.EllipticCurvePrivateKey, subject: bytes):
        self.der, self.key, self.subject = der, k, subject

    def b64(self) -> str:
        return base64.b64encode(self.der).decode()


def cert(subject: bytes, k, issuer: Cert | None, exts: list[bytes], serial: int, nb=NOW - 86400 * 30,
         na=NOW + 86400 * 365, alg=ECDSA_SHA256, issuer_name: bytes | None = None, signer=None,
         inner_alg: str | None = None) -> Cert:
    """issuer None = self-signed. `issuer_name` / `signer` override the link for refusal cases."""
    iname = issuer_name if issuer_name is not None else (issuer.subject if issuer else subject)
    algid = seq(oid(alg))
    tbs = seq(explicit(0, integer(2)), integer(serial), seq(oid(inner_alg)) if inner_alg else algid, iname, seq(gtime(nb), gtime(na)), subject, spki(k),
              *([explicit(3, seq(*exts))] if exts else []))  # no extensions: [3] left out, never empty
    sk = signer or (issuer.key if issuer else k)
    sig = sign(sk, tbs, hashes.SHA384() if alg == ECDSA_SHA384 else None)
    return Cert(seq(tbs, algid, bitstring(sig)), k, subject)


def pem(*certs: Cert) -> str:
    out = []
    for c in certs:
        b = c.b64()
        out.append("-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
                   + "\n-----END CERTIFICATE-----\n")
    return "".join(out)


# --- the PKI ----------------------------------------------------------------------------------------------------

CA_KU = ku(5, 6)
LEAF_KU = ku(0)
TN = "+15551234567"
D = TN[1:]
SPC = "709J"
SPC_NUMBER = "15553330000"
ROOT = cert(name((C, "US"), (O, "Example STI-CA"), (CN, "Example STI-CA Root")), key("root"), None,
            [bc(True), CA_KU], 1, nb=NOW - 86400 * 3650, na=NOW + 86400 * 3650)
INTER = cert(name((C, "US"), (O, "Example STI-CA"), (CN, "Example STI-CA Issuing 1")), key("inter"), ROOT,
             [bc(True, 1), CA_KU], 2, nb=NOW - 86400 * 1000, na=NOW + 86400 * 1000)
LEAF_TNAUTH = tnauth(tn_one(D), tn_range("15552000000", 1000), tn_spc(SPC))
LEAF_NAME = name((C, "US"), (O, "Carrier Example"), (CN, "SHAKEN 709J"))
LEAF = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 3)
X5U = "https://cr.carrier.example/sti.pem"
DID = "did:web:alice.example"
IAT = NOW - 3600
EXP = IAT + 86400
JTI = "01K6Z8R8QAEXAMP1EB1NDNG001"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def header(**over) -> dict:
    h = {"alg": "ES256", "typ": "dsip-tn-binding+jwt", "x5u": X5U}
    h.update(over)
    return {k: v for k, v in h.items() if v is not DROP}


def claims(**over) -> dict:
    p = {"tn": TN, "did": DID, "iat": IAT, "exp": EXP, "jti": JTI}
    p.update(over)
    return {k: v for k, v in p.items() if v is not DROP}


DROP = object()


def raw_sig(k, signing_input: bytes) -> bytes:
    r, s = decode_dss_signature(sign(k, signing_input))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def jws(h: dict | bytes | str = None, p: dict | bytes | str = None, k=None, sig=None) -> str:
    """h/p: dict (JSON-encoded), bytes (raw), or str (already a segment)."""
    def seg(x, dflt):
        x = dflt() if x is None else x
        if isinstance(x, str):
            return x
        if isinstance(x, dict):
            x = json.dumps(x, separators=(",", ":")).encode()
        return b64u(x)
    hs, ps = seg(h, header), seg(p, claims)
    si = f"{hs}.{ps}".encode()
    if sig is None:
        sig = b64u(raw_sig(k or LEAF.key, si))
    elif callable(sig):
        sig = sig(si)
    return f"{hs}.{ps}.{sig}"


def doc(*aka: str, id_: str = DID) -> dict:
    return {"@context": ["https://www.w3.org/ns/did/v1"], "id": id_, "alsoKnownAs": list(aka) or [f"tel:{TN}"]}


def ctx(chain: str | None = None, anchors=None, spc=None, require_status=False, status=None, certificates=None) -> dict:
    return {"trust_anchors": [c.b64() for c in (anchors if anchors is not None else [ROOT])],
            "certificates": certificates if certificates is not None else {X5U: chain if chain is not None else pem(LEAF, INTER)},
            "spc_numbers": spc if spc is not None else {SPC: [SPC_NUMBER, "15553330002"]},
            "require_status": require_status, "status": status or {}}


def inp(binding=None, did=DID, document=None, now=NOW) -> dict:
    return {"binding": binding or jws(), "did": did, "did_document": doc() if document is None else document, "now": now}


def ok(tn=TN, did=DID, expires=EXP, by="Carrier Example") -> dict:
    return {"outcome": "verified", "tn": tn, "did": did, "expires": expires, "attested_by": by}


def rej(r: str) -> dict:
    return {"outcome": "rejected", "reason": r}


def tv(vid, desc, context, input_, expect, refs=None):
    return vector(f"tn-binding/{vid}", "tn-binding", desc, refs or REFS, context, input_, expect)


NULLDOC = "null"  # sentinel: did_document null


def vectors() -> list[dict]:
    out = []

    def add(vid, desc, expect, binding=None, context=None, did=DID, document=None, now=NOW, refs=None):
        i = inp(binding, did, document, now)
        if document is NULLDOC:
            i["did_document"] = None
        out.append(tv(vid, desc, context or ctx(), i, expect, refs))

    # --- verified ---------------------------------------------------------------------------------------------
    add("verified-one", "A binding under an SP certificate whose TNAuthList names the number (`one`), chained "
        "leaf → intermediate → anchor; the DID claims it back.", ok())
    t = "+15552000999"
    add("verified-range-last", "The last number of a `range` entry (start 15552000000, count 1000) is covered.",
        ok(t), jws(p=claims(tn=t)), document=doc(f"tel:{t}"))
    t = "+15552000000"
    add("verified-range-start", "The first number of a `range` entry is covered.",
        ok(t), jws(p=claims(tn=t)), document=doc(f"tel:{t}"))
    t = "+" + SPC_NUMBER
    add("verified-spc", "An `spc` entry covers a number the relying party's SPC lookup assigns to that code.",
        ok(t), jws(p=claims(tn=t)), document=doc(f"tel:{t}"))
    add("verified-root-in-chain", "The chain at x5u includes the anchor itself: the path ends at it.",
        ok(), context=ctx(pem(LEAF, INTER, ROOT)))
    junk = cert(name((CN, "unrelated")), key("junk"), None, [bc(True)], 77)
    add("verified-after-anchor-ignored", "Certificates after the anchor in the chain are ignored, even unrelated ones.",
        ok(), context=ctx(pem(LEAF, INTER, ROOT, junk)))
    direct = cert(LEAF_NAME, key("sp-direct"), ROOT, [LEAF_KU, LEAF_TNAUTH], 4)
    add("verified-leaf-under-anchor", "A leaf issued directly by the anchor: the chain is the leaf alone.",
        ok(), jws(k=direct.key), context=ctx(pem(direct)))
    add("verified-other-alsoKnownAs-entries", "The DID document lists other aliases too; one is the number.",
        ok(), document=doc("https://alice.example", f"tel:{TN}", "tel:+15550000000"))
    add("verified-extra-members-ignored", "Unknown header and payload members are ignored (N§3.1).",
        ok(), jws(h=header(kid="sti-1"), p=claims(orig_carrier="x")))
    st = "https://status.carrier.example/tn/" + JTI
    add("verified-status-good-required", "The policy requires a status check and the status URL answers `good`.",
        ok(), jws(p=claims(status=st)), context=ctx(require_status=True, status={st: "good"}))
    add("verified-status-not-required-revoked-ignored", "Without a status policy, the status URL is never consulted, "
        "even when it would say `revoked`.", ok(), jws(p=claims(status=st)), context=ctx(status={st: "revoked"}))
    add("verified-iat-at-tolerance", "`iat` exactly 300 s ahead of the clock is within the tolerance.",
        ok(expires=NOW + 300 + 86400), jws(p=claims(iat=NOW + 300, exp=NOW + 300 + 86400)))
    add("verified-lifetime-exactly-7-days", "`exp − iat` exactly 604800 s is allowed.",
        ok(expires=IAT + 604800), jws(p=claims(exp=IAT + 604800)))
    add("verified-last-second", "The clock one second before `exp`.", ok(), now=EXP - 1)

    def high_s(si):
        r, s = decode_dss_signature(sign(LEAF.key, si))
        s2 = N_P256 - s if s < N_P256 // 2 else s
        return b64u(r.to_bytes(32, "big") + s2.to_bytes(32, "big"))
    add("verified-high-s", "A high-s signature (n − s) verifies: ECDSA allows it, and the profile does not forbid it.",
        ok(), jws(sig=high_s))
    other_anchor = cert(ROOT.subject, key("root-impostor"), None, [bc(True), CA_KU], 1)
    add("verified-second-anchor-same-name", "Two anchors share the intermediate's issuer name; the first one's key does "
        "not verify it, the second's does. Any qualifying anchor will do.", ok(),
        context=ctx(anchors=[other_anchor, ROOT]))
    ski = ext(SKI, octet(b"\x01" * 20))
    leaf_ski = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH, ski, ext("1.3.6.1.4.1.99999.1", b"\x05\x00")], 5)
    add("verified-noncritical-unknown-extension", "A non-critical extension the verifier does not know is ignored.",
        ok(), context=ctx(pem(leaf_ski, INTER)))
    noku = cert(LEAF_NAME, key("sp"), INTER, [LEAF_TNAUTH], 6)
    add("verified-leaf-without-keyusage", "keyUsage is optional on the leaf.", ok(), context=ctx(pem(noku, INTER)))
    cn_only = cert(name((CN, "SP Seven")), key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 7)
    add("attested-by-common-name", "With no organizationName in the leaf subject, `attested_by` is its commonName.",
        ok(by="SP Seven"), context=ctx(pem(cn_only, INTER)))
    c_only = cert(name((C, "US")), key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 8)
    add("attested-by-null", "A leaf subject with neither organizationName nor commonName: `attested_by` is null.",
        ok(by=None), context=ctx(pem(c_only, INTER)))
    two_o = cert(name((O, "First Carrier"), (CN, "x"), (O, "Second Carrier")), key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 9)
    add("attested-by-first-organization", "Of two organizationNames, the first in encoded order.",
        ok(by="First Carrier"), context=ctx(pem(two_o, INTER)))
    ia5_o = seq(set_(seq(oid(O), tlv(0x16, b"IA5 Carrier"))), set_(seq(oid(CN), tlv(0x0C, b"CN Carrier"))))
    ia5_leaf = cert(ia5_o, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 10)
    add("attested-by-skips-other-string-types", "An organizationName that is an IA5String is passed over; the "
        "commonName is used.", ok(by="CN Carrier"), context=ctx(pem(ia5_leaf, INTER)))

    # delegate certificates (RFC 9060): an SP CA with a range issues an enterprise's leaf for one number
    SPCA = cert(name((O, "Carrier Example"), (CN, "Carrier Example Delegation CA")), key("sp-ca"), INTER,
                [bc(True, 0), CA_KU, tnauth(tn_range("15551234500", 100))], 11)
    DEL = cert(name((O, "Enterprise Example"), (CN, "Delegate")), key("delegate"), SPCA, [LEAF_KU, tnauth(tn_one(D))], 12)
    add("verified-delegate", "An RFC 9060 delegate certificate: the enterprise's leaf names the number, and its "
        "issuer's TNAuthList (a range) covers it too.", ok(by="Enterprise Example"), jws(k=DEL.key),
        context=ctx(pem(DEL, SPCA, INTER)))
    t2 = "+15559990000"
    DEL2 = cert(name((O, "Enterprise Example"), (CN, "Delegate")), key("delegate"), SPCA, [LEAF_KU, tnauth(tn_one(t2[1:]))], 13)
    add("delegate-beyond-issuer-range", "A delegate leaf names a number its issuer's TNAuthList does not cover: every "
        "TNAuthList on the path must cover it.", rej("not-authorized-for-tn"), jws(p=claims(tn=t2), k=DEL2.key),
        context=ctx(pem(DEL2, SPCA, INTER)), document=doc(f"tel:{t2}"))
    INTER0 = cert(INTER.subject, key("inter"), ROOT, [bc(True, 0), CA_KU], 14, nb=NOW - 86400 * 1000, na=NOW + 86400 * 1000)
    add("pathlen-exceeded", "The intermediate's pathLenConstraint 0 allows no CA below it, but the delegation CA is "
        "one.", rej("untrusted-certificate"), jws(k=DEL.key), context=ctx(pem(DEL, SPCA, INTER0)))
    add("pathlen-zero-leaf-only", "pathLenConstraint 0 with only the leaf below it is allowed.", ok(),
        context=ctx(pem(LEAF, INTER0)))

    # --- 1. malformed ----------------------------------------------------------------------------------------
    good = jws()
    hs, ps, ss = good.split(".")
    M = rej("malformed")
    add("malformed-two-segments", "Two segments are not a compact JWS.", M, f"{hs}.{ps}")
    add("malformed-four-segments", "Four segments are not a compact JWS.", M, f"{good}.{ss}")
    add("malformed-padding", "base64url carries no `=` padding.", M, f"{hs}.{ps}.{ss}=")
    add("malformed-base64-alphabet", "A `+` is not base64url.", M, f"{hs}.{ps[:-2]}+A.{ss}")
    add("malformed-length-mod-4", "A segment one character longer than a multiple of 4 cannot be base64.",
        M, f"{hs}.{ps}{'A' * ((1 - len(ps)) % 4 or 4)}.{ss}")
    add("malformed-empty-signature", "The signature segment is empty.", M, f"{hs}.{ps}.")
    add("malformed-header-not-json", "The header does not decode to JSON.", M, jws(h=b"ES256"))
    add("malformed-header-array", "The header is JSON but not an object.", M, jws(h=b'["ES256"]'))
    add("malformed-duplicate-member", "A payload member name appears twice (I-JSON).", M,
        jws(p=json.dumps(claims(), separators=(",", ":")).replace('{"tn"', '{"tn":"+15550000000","tn"', 1).encode()))
    add("malformed-fraction", "`iat` written with `.0` is not an integer (§10.3).", M,
        jws(p=json.dumps(claims(), separators=(",", ":")).replace(f'"iat":{IAT}', f'"iat":{IAT}.0').encode()))
    add("malformed-exponent", "`exp` written with an exponent.", M,
        jws(p=json.dumps(claims(exp=1_800_000_000), separators=(",", ":")).replace('1800000000', '18e8').encode()))
    add("malformed-integer-too-large", "An ignored member holds an integer beyond 2^53−1: still not I-JSON.", M,
        jws(p=json.dumps(claims(), separators=(",", ":")).replace('{"tn"', '{"x":9007199254740992,"tn"', 1).encode()))
    add("malformed-lone-surrogate", "An ignored member holds an escaped lone surrogate: not I-JSON.", M,
        jws(p=json.dumps(claims(), separators=(",", ":")).replace('{"tn"', '{"x":"\\ud800","tn"', 1).encode()))
    add("malformed-bom", "A UTF-8 byte-order mark before the payload JSON.", M,
        jws(p=b"\xef\xbb\xbf" + json.dumps(claims(), separators=(",", ":")).encode()))
    add("malformed-not-utf8", "The payload is not UTF-8.", M,
        jws(p=b'{"x":"\xff\xfe",' + json.dumps(claims(), separators=(",", ":")).encode()[1:]))
    add("malformed-alg", "`alg` other than ES256.", M, jws(h=header(alg="RS256")))
    add("malformed-alg-missing", "No `alg`.", M, jws(h=header(alg=DROP)))
    add("malformed-typ", "`typ` must be exactly `dsip-tn-binding+jwt`.", M, jws(h=header(typ="passport")))
    add("malformed-typ-case", "`typ` compares exactly, case included.", M, jws(h=header(typ="DSIP-TN-BINDING+JWT")))
    add("malformed-x5u-http", "`x5u` must be https.", M, jws(h=header(x5u="http://cr.carrier.example/sti.pem")))
    add("malformed-crit", "A `crit` header member: this profile defines no critical parameters.", M,
        jws(h=header(crit=["ppt"])))
    for vid, t, why in [("tn-no-plus", D, "without its `+`"), ("tn-leading-zero", "+0155512345", "starting with 0"),
                        ("tn-too-long", "+1555123456789012", "of 16 digits"), ("tn-too-short", "+1", "of 1 digit"),
                        ("tn-formatted", "+1 555 123 4567", "with spaces"), ("tn-number", 15551234567, "as a JSON number")]:
        add(f"malformed-{vid}", f"`tn` {why}.", M, jws(p=claims(tn=t)))
    add("malformed-did", "`did` must start `did:`.", M, jws(p=claims(did="alice.example")))
    add("malformed-iat-negative", "`iat` below 0.", M, jws(p=claims(iat=-1, exp=100)))
    add("malformed-iat-string", "`iat` as a string.", M, jws(p=claims(iat=str(IAT))))
    add("malformed-exp-equals-iat", "`exp` must be greater than `iat`.", M, jws(p=claims(exp=IAT)))
    add("malformed-exp-missing", "No `exp`.", M, jws(p=claims(exp=DROP)))
    add("malformed-jti-prose", "A prose id like `01HZBINDINGABC` is not a ULID.", M, jws(p=claims(jti="01HZBINDINGABC")))
    add("malformed-jti-lowercase", "ULIDs are upper-case Crockford base32 here.", M, jws(p=claims(jti=JTI.lower())))
    add("malformed-jti-overflow", "A ULID whose first character is above 7 overflows 48 bits of time.", M,
        jws(p=claims(jti="8" + JTI[1:])))
    add("malformed-status-null", "`status: null` is not absent.", M, jws(p=claims(status=None)))
    add("malformed-status-http", "`status` must be https.", M, jws(p=claims(status="http://status.example/x")))
    add("order-malformed-before-certificate", "A bad `typ` and an x5u nobody serves: malformed comes first.", M,
        jws(h=header(typ="JWT", x5u="https://nowhere.example/x.pem")))

    # --- 2. untrusted-certificate ----------------------------------------------------------------------------
    U = rej("untrusted-certificate")
    add("cert-x5u-not-served", "Nothing is served at `x5u`.", U, jws(h=header(x5u="https://other.example/sti.pem")))
    add("cert-no-pem-block", "The text at `x5u` holds no certificate block.", U, context=ctx("no certificates here\n"))
    add("cert-pem-bad-base64", "A block whose body is not base64.", U,
        context=ctx("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"))
    add("cert-pem-not-der", "A block whose body is base64 but not a certificate.", U,
        context=ctx("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" + pem(INTER)))
    add("cert-pem-unterminated", "A BEGIN line with no END line.", U,
        context=ctx("-----BEGIN CERTIFICATE-----\n" + LEAF.b64() + "\n"))
    add("cert-pem-surrounding-text-ignored", "Text outside the blocks is ignored.", ok(),
        context=ctx("# chain for 709J\n" + pem(LEAF) + "trailing note\n" + pem(INTER)))
    add("cert-missing-intermediate", "The leaf alone: its issuer is not an anchor.", U, context=ctx(pem(LEAF)))
    add("cert-wrong-order", "Intermediate first: the path does not link.", U, context=ctx(pem(INTER, LEAF)))
    rogue = cert(ROOT.subject, key("rogue"), None, [bc(True), CA_KU], 1)
    rogue_inter = cert(INTER.subject, key("inter"), rogue, [bc(True, 1), CA_KU], 2)
    add("cert-untrusted-root", "A chain to a root with the trusted root's name but another key.", U,
        context=ctx(pem(LEAF, rogue_inter, rogue)))
    add("cert-no-anchors", "An empty trust list trusts nothing.", U, context=ctx(anchors=[]))
    bad_link = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 20, signer=key("mallory"))
    add("cert-leaf-signed-by-wrong-key", "The leaf names the intermediate as issuer but another key signed it.", U,
        context=ctx(pem(bad_link, INTER)))
    name_link = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 21,
                     issuer_name=name((C, "US"), (O, "Example STI-CA"), (CN, "Example STI-CA Issuing 2")))
    add("cert-issuer-name-mismatch", "The intermediate's key signed the leaf, but the leaf's issuer is another name.",
        U, context=ctx(pem(name_link, INTER)))
    for vid, desc, kw in [("leaf-expired", "The leaf's notAfter is before now.", dict(nb=NOW - 400 * 86400, na=NOW - 1)),
                          ("leaf-not-yet-valid", "The leaf's notBefore is after now.", dict(nb=NOW + 1, na=NOW + 86400))]:
        c = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 22, **kw)
        add(f"cert-{vid}", desc, U, context=ctx(pem(c, INTER)))
    edge = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 23, nb=NOW - 86400, na=NOW)
    add("cert-leaf-notafter-now", "notAfter equal to now is still valid (inclusive).", ok(), context=ctx(pem(edge, INTER)))
    old_inter = cert(INTER.subject, key("inter"), ROOT, [bc(True, 1), CA_KU], 24, nb=NOW - 900 * 86400, na=NOW - 86400)
    add("cert-intermediate-expired", "The intermediate expired.", U, context=ctx(pem(LEAF, old_inter)))
    old_root = cert(ROOT.subject, key("root"), None, [bc(True), CA_KU], 25, nb=NOW - 9000 * 86400, na=NOW - 1)
    add("cert-anchor-expired", "The anchor itself expired: every certificate on the path is checked.", U,
        context=ctx(anchors=[old_root]))
    not_ca = cert(INTER.subject, key("inter"), ROOT, [bc(False), CA_KU], 26, nb=NOW - 86400 * 1000, na=NOW + 86400 * 1000)
    add("cert-intermediate-not-ca", "The intermediate's basicConstraints has cA false.", U, context=ctx(pem(LEAF, not_ca)))
    no_bc = cert(INTER.subject, key("inter"), ROOT, [CA_KU], 27, nb=NOW - 86400 * 1000, na=NOW + 86400 * 1000)
    add("cert-intermediate-no-basic-constraints", "The intermediate has no basicConstraints.", U,
        context=ctx(pem(LEAF, no_bc)))
    no_kcs = cert(INTER.subject, key("inter"), ROOT, [bc(True, 1), ku(0, 6)], 28, nb=NOW - 86400 * 1000, na=NOW + 86400 * 1000)
    add("cert-intermediate-no-keycertsign", "The intermediate's keyUsage lacks keyCertSign.", U,
        context=ctx(pem(LEAF, no_kcs)))
    leaf_no_ds = cert(LEAF_NAME, key("sp"), INTER, [ku(5), LEAF_TNAUTH], 29)
    add("cert-leaf-no-digitalsignature", "The leaf's keyUsage lacks digitalSignature.", U, context=ctx(pem(leaf_no_ds, INTER)))
    root_pl0 = cert(ROOT.subject, key("root"), None, [bc(True, 0), CA_KU], 30, nb=NOW - 86400 * 3650, na=NOW + 86400 * 3650)
    add("cert-anchor-pathlen-zero", "The anchor's pathLenConstraint 0 allows no intermediate.", U,
        context=ctx(anchors=[root_pl0]))
    crit = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH, ext("1.3.6.1.4.1.99999.1", b"\x05\x00", critical=True)], 31)
    add("cert-unknown-critical-extension", "A critical extension the verifier does not recognize.", U,
        context=ctx(pem(crit, INTER)))
    s384 = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 32, alg=ECDSA_SHA384)
    add("cert-sha384-signature", "The leaf is signed ecdsa-with-SHA384: the path is SHA-256 only.", U,
        context=ctx(pem(s384, INTER)))
    p384 = cert(LEAF_NAME, key("sp-384", ec.SECP384R1()), INTER, [LEAF_KU, LEAF_TNAUTH], 33)
    add("cert-p384-key", "The leaf holds a P-384 key: the path is P-256 only.", U,
        jws(sig=b64u(b"\x00" * 64)), context=ctx(pem(p384, INTER)))

    def tn_bad(vid, desc, raw, on_inter=False):
        if on_inter:
            bad = cert(INTER.subject, key("inter"), ROOT, [bc(True, 1), CA_KU, tnauth(raw=raw)], 40,
                       nb=NOW - 86400 * 1000, na=NOW + 86400 * 1000)
            add(f"tnauth-{vid}", desc, U, context=ctx(pem(LEAF, bad)))
        else:
            bad = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, tnauth(raw=raw)], 41)
            add(f"tnauth-{vid}", desc, U, context=ctx(pem(bad, INTER)))
    good_list = seq(tn_one(D))
    tn_bad("trailing-bytes", "Bytes after the TNAuthList SEQUENCE.", good_list + b"\x05\x00")
    tn_bad("empty", "An empty TNAuthList.", seq())
    tn_bad("implicit-tag", "`one` with an IMPLICIT tag (82, digits directly): RFC 8226 tags are EXPLICIT.",
           seq(tlv(0x82, D.encode())))
    tn_bad("unknown-tag", "An entry tagged [3].", seq(explicit(3, ia5(D))))
    tn_bad("count-one", "A range with count 1 (must be ≥ 2).", seq(tn_range("15551234567", 1)))
    tn_bad("count-redundant-zero", "A range count INTEGER with a redundant leading 00 byte.",
           seq(explicit(1, seq(ia5("15551234500"), tlv(0x02, b"\x00\x64")))))
    tn_bad("range-extra-element", "A range SEQUENCE with a third element.",
           seq(explicit(1, seq(ia5("15551234500"), integer(100), integer(1)))))
    tn_bad("number-too-long", "A TelephoneNumber of 16 characters.", seq(tn_one("1555123456789012")))
    tn_bad("number-bad-character", "A TelephoneNumber with a letter.", seq(tn_one("1555123456A")))
    tn_bad("number-utf8string", "A TelephoneNumber as UTF8String, not IA5String.", seq(explicit(2, tlv(0x0C, D.encode()))))
    tn_bad("spc-empty", "An empty SPC.", seq(tn_spc("")))
    tn_bad("non-minimal-length", "A length in long form below 128 (`81 0D`).",
           b"\x30\x81" + bytes([len(tn_one(D))]) + tn_one(D))
    tn_bad("explicit-wrapper-extra", "The [2] wrapper holds a second element after the number.",
           seq(explicit(2, ia5(D) + ia5(D))))
    tn_bad("on-intermediate", "The intermediate's TNAuthList is malformed: every certificate on the path is checked.",
           seq(tlv(0x82, D.encode())), on_inter=True)
    tn_hash = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, tnauth(tn_one(D), tn_range("1555*00", 10))], 42)
    add("tnauth-star-in-range-allowed", "`*` and `#` are TelephoneNumber characters; a range starting with one parses "
        "(it just covers nothing).", ok(), context=ctx(pem(tn_hash, INTER)))
    # parse rules pinned after the impl-ts probes (spec-gap 110)
    dup = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH, LEAF_KU], 43)
    add("cert-duplicate-extension", "keyUsage appears twice in the leaf (RFC 5280 §4.2): it does not parse.", U,
        context=ctx(pem(dup, INTER)))
    dup_tn = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH, LEAF_TNAUTH], 44)
    add("cert-duplicate-tnauthlist", "Two TNAuthList extensions in the leaf: it does not parse.", U,
        context=ctx(pem(dup_tn, INTER)))
    pl_noca = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH, bc(False, 0)], 45)
    add("cert-pathlen-without-ca", "A leaf basicConstraints with a pathLenConstraint but cA false "
        "(RFC 5280 §4.2.1.9): it does not parse.", U, context=ctx(pem(pl_noca, INTER)))
    mixed = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 46, inner_alg=ECDSA_SHA384)
    add("cert-tbs-algorithm-differs", "The tbsCertificate's `signature` says ecdsa-with-SHA384 while the outer "
        "signatureAlgorithm says SHA-256 (RFC 5280 §4.1.1.2): it does not parse.", U, context=ctx(pem(mixed, INTER)))
    bad_after = cert(name((CN, "after")), key("junk"), None, [bc(True), tnauth(raw=seq())], 47)
    add("cert-unparseable-after-anchor", "A block after the anchor has an empty TNAuthList: every block must parse, "
        "even one the path ignores.", U, context=ctx(pem(LEAF, INTER, ROOT, bad_after)))
    add("cert-pem-crlf", "PEM lines may end in CRLF.", ok(), context=ctx(pem(LEAF, INTER).replace("\n", "\r\n")))
    add("cert-pem-marker-not-whole-line", "A marker with text before it on the line is not a marker; the text holds "
        "no block.", U, context=ctx("chain: " + pem(LEAF, INTER).replace("\n-----BEGIN", "\nchain: -----BEGIN")))
    add("cert-pem-vertical-tab", "Only SP, HT, CR and LF are removed from a body; a vertical tab is not base64.", U,
        context=ctx(pem(LEAF, INTER).replace("\n", "\x0b\n", 2)))
    add("cert-pem-open-block-after-chain", "A complete chain followed by a BEGIN line with no END: a block is left "
        "open.", U, context=ctx(pem(LEAF, INTER) + "-----BEGIN CERTIFICATE-----\n"))

    def unused_bits(c: Cert) -> str:
        b = c.b64()
        assert b.endswith("=") and not b.endswith("=="), "this certificate's base64 has 2 unused bits"
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = alpha[alpha.index(b[-2]) | 1]
        return "-----BEGIN CERTIFICATE-----\n" + b[:-2] + last + "=\n-----END CERTIFICATE-----\n"
    pad_leaf = next(c for c in (cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], n) for n in range(100, 140))
                    if c.b64().endswith("=") and not c.b64().endswith("=="))
    add("cert-pem-nonzero-unused-bits", "A PEM body whose last character carries non-zero unused bits is accepted "
        "(RFC 4648 §3.5).", ok(), context=ctx(unused_bits(pad_leaf) + pem(INTER)))
    add("anchor-bad-entries-ignored", "Trust-list entries that are not base64, or not a certificate, are ignored.",
        ok(), context=ctx() | {"trust_anchors": ["!!!!", "AAAA", ROOT.b64()]})
    wrapped = ROOT.b64()[:64] + "\n" + ROOT.b64()[64:]
    add("anchor-with-whitespace-ignored", "An anchor written with a line break is not padded base64: ignored, so "
        "nothing is trusted.", U, context=ctx() | {"trust_anchors": [wrapped]})
    add("anchor-each-qualifying-tried", "Two anchors with the same name and key; the first expired. The path through "
        "the second passes, so step 2 passes.", ok(), context=ctx(anchors=[old_root, ROOT]))
    bad_utf8 = seq(set_(seq(oid(O), tlv(0x0C, b"\xff\xfeCarrier"))), set_(seq(oid(CN), tlv(0x0C, b"CN One"))))
    bu_leaf = cert(bad_utf8, key("sp"), INTER, [LEAF_KU, LEAF_TNAUTH], 48)
    add("attested-by-invalid-utf8-passed-over", "An organizationName UTF8String whose bytes are not UTF-8 is passed "
        "over, never shown lossily: the commonName is used.", ok(by="CN One"), context=ctx(pem(bu_leaf, INTER)))
    add("order-certificate-before-signature", "An untrusted chain and a bad signature: untrusted-certificate first.",
        U, jws(k=key("mallory")), context=ctx(pem(LEAF)))

    # --- 3. signature ----------------------------------------------------------------------------------------
    S = rej("signature")
    add("signature-other-key", "Signed by a key other than the leaf's.", S, jws(k=key("mallory")))
    other = jws(p=claims(did="did:web:mallory.example"))
    add("signature-payload-swapped", "The payload segment replaced after signing.", S,
        f"{hs}.{other.split('.')[1]}.{ss}", document=doc())
    add("signature-63-bytes", "A signature of 63 bytes.", S, jws(sig=lambda si: b64u(raw_sig(LEAF.key, si)[:63])))
    add("signature-65-bytes", "A signature of 65 bytes.", S, jws(sig=lambda si: b64u(raw_sig(LEAF.key, si) + b"\x00")))
    add("signature-der", "An ASN.1 DER signature, not the 64-byte r‖s form.", S, jws(sig=lambda si: b64u(sign(LEAF.key, si))))
    add("signature-r-zero", "r = 0.", S, jws(sig=lambda si: b64u(b"\x00" * 32 + raw_sig(LEAF.key, si)[32:])))
    add("signature-s-order", "s = n.", S, jws(sig=lambda si: b64u(raw_sig(LEAF.key, si)[:32] + N_P256.to_bytes(32, "big"))))
    reencoded = b64u(json.dumps(claims(), indent=1).encode())
    add("signature-reencoded-payload", "The same claims re-serialized (whitespace added) after signing: the signature "
        "is over the bytes received (§10.2).", S, f"{hs}.{reencoded}.{ss}")
    add("order-signature-before-tn", "A bad signature on a number the certificate does not cover: signature first.", S,
        jws(p=claims(tn="+15550000001"), k=key("mallory")), document=doc("tel:+15550000001"))

    # --- 4. not-authorized-for-tn ----------------------------------------------------------------------------
    A = rej("not-authorized-for-tn")
    for vid, t, why in [("not-listed", "+15550000001", "a number no entry covers"),
                        ("range-end-excluded", "+15552001000", "start + count, one past the range"),
                        ("range-below-start", "+15551999999", "one below the range"),
                        ("range-longer-number", "+155520000005", "a number longer than the range's start"),
                        ("spc-not-assigned", "+15553330001", "a number the SPC lookup does not assign to 709J")]:
        add(f"tn-{vid}", f"Not covered: {why}.", A, jws(p=claims(tn=t)), document=doc(f"tel:{t}"))
    add("tn-spc-unknown-code", "The SPC lookup has no entry for the certificate's code.", A,
        jws(p=claims(tn="+" + SPC_NUMBER)), context=ctx(spc={}), document=doc(f"tel:+{SPC_NUMBER}"))
    no_tn = cert(LEAF_NAME, key("sp"), INTER, [LEAF_KU], 50)
    add("tn-leaf-without-tnauthlist", "The leaf has no TNAuthList.", A, context=ctx(pem(no_tn, INTER)))
    inter_tn = cert(INTER.subject, key("inter"), ROOT, [bc(True, 1), CA_KU, tnauth(tn_spc("OTHR"))], 51,
                    nb=NOW - 86400 * 1000, na=NOW + 86400 * 1000)
    add("tn-intermediate-list-does-not-cover", "The intermediate carries a TNAuthList that does not cover the number.",
        A, context=ctx(pem(LEAF, inter_tn)))
    add("tn-range-star-start", "A range whose start holds `*` covers nothing.", A,
        jws(p=claims(tn="+1555100")), context=ctx(pem(tn_hash, INTER)), document=doc("tel:+1555100"))
    add("order-tn-before-time", "An expired binding for a number the certificate does not cover: "
        "not-authorized-for-tn first.", A, jws(p=claims(tn="+15550000001")), document=doc("tel:+15550000001"),
        now=EXP + 10)

    # --- 5. time ---------------------------------------------------------------------------------------------
    add("lifetime-too-long", "`exp − iat` one second over 7 days.", rej("lifetime-too-long"),
        jws(p=claims(exp=IAT + 604801)))
    add("not-yet-valid", "`iat` 301 s ahead of the clock.", rej("not-yet-valid"),
        jws(p=claims(iat=NOW + 301, exp=NOW + 301 + 86400)))
    add("expired-at-exp", "The clock has reached `exp`.", rej("expired"), now=EXP)
    add("order-lifetime-before-expired", "Too long and expired: lifetime-too-long first.", rej("lifetime-too-long"),
        jws(p=claims(exp=IAT + 700000)), now=IAT + 700001)
    add("order-expired-before-did", "Expired and naming another DID: expired first.", rej("expired"),
        jws(p=claims(did="did:web:bob.example")), now=EXP + 1)

    # --- 6. did-mismatch / 7. back-reference -----------------------------------------------------------------
    add("did-mismatch", "The binding names another DID than the one being checked.", rej("did-mismatch"),
        jws(p=claims(did="did:web:bob.example")))
    add("did-mismatch-case", "DIDs compare exactly.", rej("did-mismatch"), jws(p=claims(did="did:web:Alice.example")))
    add("order-did-before-claim", "Another DID, whose document is absent too: did-mismatch first.", rej("did-mismatch"),
        jws(p=claims(did="did:web:bob.example")), document=NULLDOC)
    NC = rej("not-claimed-by-did")
    add("backref-no-document", "The DID did not resolve.", NC, document=NULLDOC)
    add("backref-no-alsoKnownAs", "The document has no `alsoKnownAs`.", NC, document={"id": DID})
    add("backref-alsoKnownAs-string", "`alsoKnownAs` is a string, not an array.", NC,
        document={"id": DID, "alsoKnownAs": f"tel:{TN}"})
    add("backref-other-number", "The document claims another number.", NC, document=doc("tel:+15559999999"))
    add("backref-without-plus", "`tel:15551234567`: the claim is `tel:` + `tn` exactly.", NC, document=doc(f"tel:{D}"))
    add("backref-formatted", "`tel:+1-555-123-4567`: visual separators are not stripped.", NC,
        document=doc("tel:+1-555-123-4567"))
    add("backref-document-id-differs", "The document's `id` is not the DID being checked.", NC,
        document=doc(id_="did:web:bob.example"))
    add("backref-document-not-object", "The document is an array.", NC, document=[doc()])

    # --- 8. status -------------------------------------------------------------------------------------------
    add("status-required-no-url", "The policy requires a status check; the binding has no status URL.",
        rej("status-unavailable"), context=ctx(require_status=True))
    add("status-required-no-answer", "The status URL does not answer.", rej("status-unavailable"),
        jws(p=claims(status=st)), context=ctx(require_status=True))
    add("status-revoked", "The issuer reports the binding revoked.", rej("revoked"), jws(p=claims(status=st)),
        context=ctx(require_status=True, status={st: "revoked"}))
    add("status-unknown-answer", "The status URL answers neither `good` nor `revoked`: fail closed.",
        rej("status-unavailable"), jws(p=claims(status=st)), context=ctx(require_status=True, status={st: "unknown"}))
    # --- check: claim (N§4) ----------------------------------------------------------------------------------
    def addc(vid, desc, claim, expect, context=None, identity=DID, document=None, now=NOW):
        i = {"check": "claim", "claim": claim, "identity": identity,
             "did_document": doc() if document is None else document, "now": now}
        if document is NULLDOC:
            i["did_document"] = None
        out.append(tv(f"claim-{vid}", desc, context or ctx(), i, expect, ["N§4", "N§3.4"]))

    def tel(number=TN, binding=None, **kw):
        return {"type": "tel", "number": number, "binding": jws() if binding is None else binding, **kw}
    line = f"{TN} · number attested by Carrier Example for this identity"
    addc("attested", "The caller's binding verifies against the envelope's signing identity: rendered with the "
         "issuer's name (§18.1).", tel(), {"outcome": "attested", "line": line, "issued": IAT, "expires": EXP})
    addc("attested-unnamed-issuer", "A leaf with neither O nor CN: the line names no issuer.", tel(),
         {"outcome": "attested", "line": f"{TN} · number attested for this identity", "issued": IAT, "expires": EXP},
         context=ctx(pem(c_only, INTER)))
    addc("attested-extra-members", "Other claim members are carried and ignored.", tel(cnam="ALICE"),
         {"outcome": "attested", "line": line, "issued": IAT, "expires": EXP})
    addc("dropped-other-identity", "The envelope was signed by another identity than the binding names.",
         tel(), {"outcome": "dropped", "reason": "did-mismatch", "line": f"{TN} (unverified)"},
         identity="did:web:mallory.example", document=doc(id_="did:web:mallory.example"))
    addc("dropped-not-claimed", "The identity's document does not claim the number back.", tel(),
         {"outcome": "dropped", "reason": "not-claimed-by-did", "line": f"{TN} (unverified)"},
         document=doc("tel:+15550000000"))
    t2 = "+15559990000"
    addc("dropped-not-covered", "A binding for a number the certificate does not cover.",
         tel(t2, jws(p=claims(tn=t2))), {"outcome": "dropped", "reason": "not-authorized-for-tn",
                                          "line": f"{t2} (unverified)"}, document=doc(f"tel:{t2}"))
    addc("dropped-number-mismatch", "The claim shows another number than the binding binds.", tel("+15550000000"),
         {"outcome": "dropped", "reason": "number-mismatch", "line": "+15550000000 (unverified)"})
    addc("dropped-binding-not-string", "`binding` is not a string.", tel(binding=["x"]),
         {"outcome": "dropped", "reason": "malformed", "line": f"{TN} (unverified)"})
    addc("dropped-number-not-e164", "A failed claim whose number is not E.164 has no line.",
         tel("555-1234"), {"outcome": "dropped", "reason": "number-mismatch", "line": None})
    addc("dropped-expired", "An expired binding.", tel(), {"outcome": "dropped", "reason": "expired",
                                                          "line": f"{TN} (unverified)"}, now=EXP)
    addc("order-verify-before-number", "A binding whose payload names did:web:bob.example, signed into a claim from "
         "alice that shows another number: the "
         "verification failure comes first.", tel("+15550000000", jws(p=claims(did="did:web:bob.example"))),
         {"outcome": "dropped", "reason": "did-mismatch", "line": "+15550000000 (unverified)"})
    addc("ignored-gateway-claim", "A gateway's `tel` claim (G§5) has no binding: not this check's.",
         {"type": "tel", "number": TN, "attestation": "A", "verified": True, "verifier": "did:web:gw.example"},
         {"outcome": "ignored"})
    addc("ignored-verifier-and-binding", "A claim with a string `verifier` is a gateway's claim even when it carries a "
         "`binding`: not this check's.", tel(attestation="A", verified=True, verifier="did:web:gw.example"),
         {"outcome": "ignored"})
    addc("dropped-binding-null", "`binding: null` is present, and not a string.", tel(binding=None) | {"binding": None},
         {"outcome": "dropped", "reason": "malformed", "line": f"{TN} (unverified)"})
    addc("ignored-other-type", "A claim of another type.", {"type": "brand", "binding": jws()}, {"outcome": "ignored"})
    addc("ignored-not-object", "A claim that is not an object.", "tel", {"outcome": "ignored"})

    # --- check: contact (N§5) --------------------------------------------------------------------------------
    def addk(vid, desc, contacts, attested, expect):
        out.append(tv(f"contact-{vid}", desc, {}, {"check": "contact", "contacts": contacts, "attested": attested},
                      expect, ["N§5"]))
    alice_c = {"name": "Alice", "did": DID, "numbers": [TN]}
    att = {"tn": TN, "did": "did:web:mallory.example", "attested_by": "Carrier B", "issued": 1759449600}
    warn = (f'{TN} now belongs to a different identity (number attested by Carrier B since 2025-10-03). '
            f'Your contact "Alice" is {DID}.')
    addk("different-identity", "A stored contact's number is now attested for another DID: the client says so, "
         "naming the contact's own DID.", [alice_c], att, warn)
    addk("same-identity", "The number is attested for the stored contact's DID: nothing to say.", [alice_c],
         {**att, "did": DID}, None)
    addk("unknown-number", "No contact lists the number.", [{"name": "Bob", "did": "did:web:bob.example",
                                                             "numbers": ["+15550000000"]}], att, None)
    addk("one-of-two-matches", "Two contacts list the number and one of them is the attested DID: unchanged.",
         [alice_c, {"name": "Alice (old)", "did": "did:web:old.example", "numbers": [TN]}], {**att, "did": DID}, None)
    addk("first-listing-contact", "Two contacts list the number, neither is the attested DID: the first is named.",
         [{"name": "Bob", "did": "did:web:bob.example", "numbers": ["+15550000000"]}, alice_c,
          {"name": "Al", "did": "did:web:al.example", "numbers": [TN]}], att, warn)
    addk("unnamed-issuer", "The issuer has no name.", [alice_c], {**att, "attested_by": None},
         warn.replace("number attested by Carrier B since", "number attested since"))
    addk("date-is-utc", "The date is the UTC calendar date of `issued` (23:59:59 UTC).", [alice_c],
         {**att, "issued": 1759535999}, warn)
    addk("empty-book", "An empty address book.", [], att, None)
    add("malformed-tn-trailing-newline", "`tn` with a trailing LF: patterns match the whole string.", M,
        jws(p=claims(tn=TN + "\n")))
    add("malformed-jti-trailing-newline", "`jti` with a trailing LF.", M, jws(p=claims(jti=JTI + "\n")))
    addc("dropped-number-trailing-newline", "A claim number with a trailing LF is not E.164: no line.",
         tel(TN + "\n"), {"outcome": "dropped", "reason": "number-mismatch", "line": None})

    # --- check: store (a node's PUT, N§6 route 1) -------------------------------------------------------------
    def adds(vid, desc, binding, held, expect, tn=TN, context=None, now=NOW):
        out.append(tv(f"store-{vid}", desc, context or ctx(),
                      {"check": "store", "tn": tn, "binding": binding, "held": held, "now": now}, expect, ["N§6", "N§3.4"]))

    def order(bs):
        return sorted(bs, key=lambda b: (-json.loads(base64.urlsafe_b64decode(b.split(".")[1] + "==="))["iat"], b))

    def bnd(did=DID, iat=IAT, jti=JTI, tn=TN, exp=None):
        return jws(p=claims(did=did, iat=iat, exp=exp or iat + 86400, jti=jti, tn=tn))
    b0 = jws()
    STORED = lambda held: {"outcome": "stored", "held": order(held)}  # noqa: E731
    adds("first", "The first binding for a number is stored.", b0, [], STORED([b0]))
    adds("bad-number", "The path is not E.164.", b0, [], rej("bad-number"), tn=D)
    adds("bad-number-before-binding", "A bad path and a malformed binding: bad-number first.", "x.y", [],
         rej("bad-number"), tn="tel:" + TN)
    adds("malformed", "A binding that is not a compact JWS.", "x.y", [], rej("malformed"))
    adds("untrusted", "A binding whose x5u the node cannot fetch.", jws(h=header(x5u="https://other.example/x.pem")),
         [], rej("untrusted-certificate"))
    adds("signature", "A binding signed by the wrong key.", jws(k=key("mallory")), [], rej("signature"))
    adds("not-covered", "A number the certificate does not cover.", bnd(tn="+15550000001"), [],
         rej("not-authorized-for-tn"), tn="+15550000001")
    adds("expired", "An expired binding.", b0, [], rej("expired"), now=EXP)
    adds("tn-mismatch", "A valid binding for another number than the path names.", bnd(tn="+15552000000"), [],
         rej("tn-mismatch"))
    bm = bnd(did="did:web:nobody.example")
    adds("did-not-resolved", "A node resolves no DIDs: a binding whose DID it could not check is stored (steps 6–8 are "
         "the reader's).", bm, [], STORED([bm]))
    adds("same", "The same binding again.", b0, [b0], {"outcome": "kept", "reason": "same"})
    adds("bad-number-trailing-newline", "A path with a trailing LF is not E.164.", b0, [], rej("bad-number"),
         tn=TN + "\n")
    unreadable = ["x.y", "a.!!!.c", jws(p={"did": "did:web:q.example", "iat": "1", "exp": EXP}),
                  jws(p={"iat": IAT, "exp": EXP}), jws(p={"did": "did:web:r.example", "iat": IAT})]
    adds("unreadable-held-dropped", "Held entries whose payload does not read (two segments, a bad segment, a string "
         "iat, no did, no exp) are dropped like expired ones.", b0, [u for u in unreadable if u], STORED([b0]))
    b_old = bnd(iat=IAT - 100, jti="01K6Z8R8QAEXAMP1EB1NDNG002")
    adds("newer-replaces", "A newer binding for the same DID replaces the held one.", b0, [b_old], STORED([b0]))
    adds("older-kept", "An older binding for the same DID is not stored.", b_old, [b0], {"outcome": "kept", "reason": "older"})
    b_same_iat = bnd(jti="01K6Z8R8QAEXAMP1EB1NDNG003")
    adds("same-iat-different-binding", "Another binding for the same DID with the same iat: the held one stays.",
         b_same_iat, [b0], {"outcome": "kept", "reason": "older"})
    bx = bnd(did="did:web:x.example", iat=IAT - 50)
    adds("second-did-added", "A binding for another DID is added beside the held one: the reader decides (N§7).",
         bx, [b0], STORED([b0, bx]))
    b_exp = bnd(did="did:web:gone.example", iat=NOW - 90000, exp=NOW - 10)
    adds("expired-held-dropped", "An expired held binding is dropped before the new one is weighed.", b0, [b_exp],
         STORED([b0]))
    four = [bnd(did=f"did:web:h{i}.example", iat=IAT + 10 * i) for i in range(1, 5)]
    adds("full", "Four live bindings for other DIDs, all newer: kept, full.", bnd(did="did:web:new.example", iat=IAT),
         four, {"outcome": "kept", "reason": "full"})
    newest = bnd(did="did:web:new.example", iat=IAT + 100)
    adds("full-evicts-oldest", "Four held; a newer binding evicts the one with the smallest iat.", newest, four,
         STORED(four[1:] + [newest]))
    tie = [bnd(did=f"did:web:t{i}.example", iat=IAT) for i in range(1, 3)] + four[2:]
    victim = max(tie[:2])
    adds("full-evicts-greatest-text-on-tie", "Two held share the smallest iat: the greater binding text is evicted.",
         newest, tie, STORED([b for b in tie if b != victim] + [newest]))
    adds("full-equal-iat-kept", "A new binding whose iat equals the eviction candidate's is not stored.",
         bnd(did="did:web:new.example", iat=IAT + 10), four, {"outcome": "kept", "reason": "full"})

    # --- check: select (number → DID, N§6–N§7) ---------------------------------------------------------------
    def addq(vid, desc, bindings, documents, expect, tn=TN, now=NOW, context=None):
        out.append(tv(f"select-{vid}", desc, context or ctx(),
                      {"check": "select", "tn": tn, "bindings": bindings, "documents": documents, "now": now},
                      expect, ["N§6", "N§7"]))
    MAL = "did:web:mallory.example"
    docs = {DID: doc(), MAL: doc(id_=MAL)}
    b_mal = bnd(did=MAL, iat=IAT + 600, jti="01K6Z8R8QAEXAMP1EB1NDNG004")

    def found(did=DID, issued=IAT, others=(), by="Carrier Example"):
        return {"outcome": "found", "did": did, "attested_by": by, "issued": issued, "others": list(others)}
    addq("one", "One verified binding: the number's DID.", [b0], docs, found())
    addq("none-empty", "No bindings.", [], docs, {"outcome": "none"})
    addq("skips-invalid", "Bindings that fail are passed over; the valid one is found.",
         ["x.y", jws(k=key("mallory")), b0], docs, found())
    addq("skips-unclaimed", "Mallory's binding is newer, but her document does not claim the number: passed over "
         "(the two-way rule).", [b0, b_mal], {DID: doc(), MAL: doc("tel:+15550000000", id_=MAL)}, found())
    addq("skips-unresolved", "A binding whose DID did not resolve is passed over.", [b_mal, b0], {DID: doc()}, found())
    addq("both-claim-newer-wins", "Both DIDs claim the number: the newer iat wins, and the other DID is reported.",
         [b0, b_mal], docs, found(MAL, IAT + 600, [DID]))
    addq("both-claim-order-irrelevant", "Order of the returned bindings does not matter.", [b_mal, b0], docs,
         found(MAL, IAT + 600, [DID]))
    b0_older = bnd(iat=IAT - 100, jti="01K6Z8R8QAEXAMP1EB1NDNG002")
    addq("same-did-twice", "Two bindings for the same DID: the newer is the winner; `others` is empty.",
         [b0_older, b0], docs, found())
    b_mal_tie = bnd(did=MAL, iat=IAT, jti="01K6Z8R8QAEXAMP1EB1NDNG005")
    win = min(b0, b_mal_tie)
    wd = DID if win == b0 else MAL
    addq("tie-smallest-text", "Equal iat: the smallest binding text wins.", [b0, b_mal_tie], docs,
         found(wd, IAT, [MAL if wd == DID else DID]))
    addq("skips-other-number", "A binding for another number is passed over.",
         [bnd(tn="+15552000000"), b0], {DID: doc("tel:+15552000000", f"tel:{TN}")}, found())
    addq("none-all-fail", "Every binding fails.", [jws(k=key("mallory"))], docs, {"outcome": "none"})
    addq("expired-skipped", "At `exp` the only binding has expired.", [b0], docs, {"outcome": "none"}, now=EXP)
    add("order-claim-before-status", "Not claimed back, and revoked: not-claimed-by-did first.", NC,
        jws(p=claims(status=st)), context=ctx(require_status=True, status={st: "revoked"}), document=doc("tel:+15559999999"))
    return out
