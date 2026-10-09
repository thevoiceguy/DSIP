"""Number binding verification (Number Attestation Profile draft, N§3.4; README kind `tn-binding`; spec-gap 110).

Written from the README's check order. Certificates are parsed with `cryptography`; the TNAuthList extension
(RFC 8226 §9), which it does not know, is decoded here with a strict DER reader.
"""
from __future__ import annotations

import base64
import json
import binascii
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtensionOID, NameOID

from .webvh import ijson

N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
LIFETIME_MAX = 604800
IAT_TOLERANCE = 300
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
TNAUTH = "1.3.6.1.5.5.7.1.26"
KNOWN_CRITICAL = {ExtensionOID.BASIC_CONSTRAINTS.dotted_string, ExtensionOID.KEY_USAGE.dotted_string, TNAUTH}
B64U = re.compile(r"^[A-Za-z0-9_-]*$")
TN_RE = re.compile(r"^\+[1-9][0-9]{1,14}$")
ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
TEL_CHARS = set("0123456789#*")


class Reject(Exception):
    pass


def b64u(s: str) -> bytes:
    if not B64U.fullmatch(s) or len(s) % 4 == 1:
        raise Reject("malformed")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def json_object(b: bytes) -> dict:
    try:
        v = ijson(b.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Reject("malformed")
    if not isinstance(v, dict):
        raise Reject("malformed")
    return v


def is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def parse_binding(binding: str):
    parts = binding.split(".") if isinstance(binding, str) else []
    if len(parts) != 3 or not parts[2]:
        raise Reject("malformed")
    raw = [b64u(p) for p in parts]
    h, p = json_object(raw[0]), json_object(raw[1])
    x5u = h.get("x5u")
    if (h.get("alg") != "ES256" or h.get("typ") != "dsip-tn-binding+jwt" or not isinstance(x5u, str)
            or not x5u.startswith("https://") or "crit" in h):
        raise Reject("malformed")
    ok = (isinstance(p.get("tn"), str) and TN_RE.fullmatch(p["tn"])
          and isinstance(p.get("did"), str) and p["did"].startswith("did:")
          and is_int(p.get("iat")) and p["iat"] >= 0
          and is_int(p.get("exp")) and p["exp"] > p["iat"]
          and isinstance(p.get("jti"), str) and ULID_RE.fullmatch(p["jti"])
          and ("status" not in p or (isinstance(p["status"], str) and p["status"].startswith("https://"))))
    if not ok:
        raise Reject("malformed")
    return h, p, f"{parts[0]}.{parts[1]}".encode("ascii"), raw[2]


# --- strict DER for TNAuthList ---------------------------------------------------------------------------------

def der_read(b: bytes, i: int):
    """One TLV at i: (tag, content, next index). Definite, minimal lengths; single-byte tags."""
    if i + 2 > len(b):
        raise ValueError("short")
    tag, l0 = b[i], b[i + 1]
    i += 2
    if l0 < 0x80:
        n = l0
    else:
        k = l0 & 0x7F
        if k == 0 or k > 4 or i + k > len(b) or b[i] == 0:
            raise ValueError("length")
        n = int.from_bytes(b[i:i + k], "big")
        if n < 0x80:
            raise ValueError("non-minimal length")
        i += k
    if i + n > len(b):
        raise ValueError("overrun")
    return tag, b[i:i + n], i + n


def der_one(b: bytes, tag: int) -> bytes:
    t, c, end = der_read(b, 0)
    if t != tag or end != len(b):
        raise ValueError("expected exactly one element")
    return c


def der_seq(content: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(content):
        t, c, i = der_read(content, i)
        out.append((t, c))
    return out


def tel_number(t: int, c: bytes) -> str:
    if t != 0x16 or not 1 <= len(c) <= 15 or any(chr(x) not in TEL_CHARS for x in c):
        raise ValueError("TelephoneNumber")
    return c.decode("ascii")


def parse_tnauth(value: bytes) -> list[tuple]:
    entries = der_seq(der_one(value, 0x30))
    if not entries:
        raise ValueError("empty")
    out = []
    for tag, c in entries:
        if tag == 0xA0:
            s = der_one(c, 0x16)
            if not s or any(x >= 0x80 for x in s):
                raise ValueError("spc")
            out.append(("spc", s.decode("ascii")))
        elif tag == 0xA1:
            items = der_seq(der_one(c, 0x30))
            if len(items) != 2 or items[1][0] != 0x02:
                raise ValueError("range")
            start = tel_number(*items[0])
            ib = items[1][1]
            if not ib or (len(ib) > 1 and ((ib[0] == 0 and ib[1] < 0x80) or (ib[0] == 0xFF and ib[1] >= 0x80))):
                raise ValueError("integer")
            count = int.from_bytes(ib, "big", signed=True)
            if count < 2:
                raise ValueError("count")
            out.append(("range", start, count))
        elif tag == 0xA2:
            t, n, end = der_read(c, 0)
            if end != len(c):
                raise ValueError("one")
            out.append(("one", tel_number(t, n)))
        else:
            raise ValueError("entry tag")
    return out


def covers(entries, d: str, spc_numbers: dict) -> bool:
    for e in entries:
        if e[0] == "one" and e[1] == d:
            return True
        if e[0] == "range" and e[1].isdigit() and len(e[1]) == len(d) and 0 <= int(d) - int(e[1]) < e[2]:
            return True
        if e[0] == "spc" and d in (spc_numbers.get(e[1]) or []):
            return True
    return False


# --- certificates ----------------------------------------------------------------------------------------------

def der_raw(b: bytes, i: int):
    """One TLV at i, as (tag, content, the whole TLV's bytes, next index)."""
    t, c, j = der_read(b, i)
    return t, c, b[i:j], j


class Cert:
    def __init__(self, der: bytes):
        self.der = der
        # The outer structure, walked here: the names and both algorithm fields as bytes.
        t, outer, end = der_read(der, 0)
        if t != 0x30 or end != len(der):
            raise ValueError("not one SEQUENCE")
        parts, i = [], 0
        while i < len(outer):
            parts.append(der_raw(outer, i))
            i = parts[-1][3]
        if len(parts) != 3 or parts[0][0] != 0x30:
            raise ValueError("Certificate")
        tbs, i = [], 0
        while i < len(parts[0][1]):
            tbs.append(der_raw(parts[0][1], i))
            i = tbs[-1][3]
        if len(tbs) < 7 or tbs[0][0] != 0xA0:
            raise ValueError("TBSCertificate")
        if tbs[2][2] != parts[1][2]:
            raise ValueError("tbsCertificate signature differs from signatureAlgorithm")
        self.issuer, self.subject = tbs[3][2], tbs[5][2]
        self.alg_ok = parts[1][2] == bytes([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
        self.c = x509.load_der_x509_certificate(der)
        c = self.c
        if c.version != x509.Version.v3:
            raise ValueError("not v3")
        try:
            self.key = c.public_key()
        except UnsupportedAlgorithm:  # a key type outside the N§3.2 rules: the path check refuses it
            self.key = None
        self.p256 = isinstance(self.key, ec.EllipticCurvePublicKey) and isinstance(self.key.curve, ec.SECP256R1)
        self.nb, self.na = int(c.not_valid_before_utc.timestamp()), int(c.not_valid_after_utc.timestamp())
        self.bc = self.ku = self.tnauth = None
        self.unknown_critical = False
        for e in c.extensions:  # cryptography refuses duplicates, and a pathLen with cA false
            o = e.oid.dotted_string
            if e.critical and o not in KNOWN_CRITICAL:
                self.unknown_critical = True
            if o == ExtensionOID.BASIC_CONSTRAINTS.dotted_string:
                self.bc = e.value
            elif o == ExtensionOID.KEY_USAGE.dotted_string:
                self.ku = e.value
            elif o == TNAUTH:
                self.tnauth = parse_tnauth(e.value.value)

    def signed_by(self, issuer: "Cert") -> bool:
        if not issuer.p256:
            return False
        try:
            issuer.key.verify(self.c.signature, self.c.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


def padded_b64(body: str) -> bytes:
    """RFC 4648 padded base64; non-zero unused bits accepted."""
    if len(body) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", body):
        raise ValueError("base64")
    return base64.b64decode(body, validate=True)


def parse_cert(der: bytes) -> Cert:
    try:
        return Cert(der)
    except Exception:  # anything the parser refuses: not a certificate (DuplicateExtension is not a ValueError)
        raise ValueError("certificate")


def load_chain(text: str) -> list[Cert]:
    U = Reject("untrusted-certificate")
    blocks, body = [], None
    for line in text.split("\n"):
        line = line[:-1] if line.endswith("\r") else line
        if body is None:
            if line == "-----BEGIN CERTIFICATE-----":
                body = []
        elif line == "-----END CERTIFICATE-----":
            blocks.append("".join(body))
            body = None
        else:
            body.append(re.sub(r"[ \t\r\n]", "", line))
    if body is not None or not blocks:
        raise U
    try:
        return [parse_cert(padded_b64(b)) for b in blocks]
    except (ValueError, binascii.Error):
        raise U


def build_paths(chain: list[Cert], anchors: list[Cert]) -> list[list[Cert]]:
    """Every candidate path: one ending at an anchor in the chain, else one per qualifying issuing anchor."""
    anchor_ders = {a.der for a in anchors}
    path = []
    for c in chain:
        path.append(c)
        if c.der in anchor_ders:
            return [path]
    return [path + [a] for a in anchors if a.subject == path[-1].issuer and path[-1].signed_by(a)]


def check_path(path: list[Cert], now: int) -> None:
    U = Reject("untrusted-certificate")
    for i in range(len(path) - 1):
        if path[i].issuer != path[i + 1].subject or not path[i].signed_by(path[i + 1]):
            raise U
    for p, c in enumerate(path):
        if not (c.alg_ok and c.p256 and c.nb <= now <= c.na) or c.unknown_critical:
            raise U
        if p >= 1:
            if c.bc is None or not c.bc.ca:
                raise U
            if c.ku is not None and not c.ku.key_cert_sign:
                raise U
            if c.bc.path_length is not None and p - 1 > c.bc.path_length:
                raise U
    if path[0].ku is not None and not path[0].ku.digital_signature:
        raise U


def attested_by(c: Cert):
    # Walk the encoded RDNs in order; only UTF8String and PrintableString count.
    seqs = der_seq(der_one(c.subject, 0x30))
    found = {}
    for t, rdn in seqs:
        for _, atv in der_seq(rdn):
            (ot, oc), (vt, vc) = der_seq(atv)[:2]
            if vt not in (0x0C, 0x13):
                continue
            key = {b"\x55\x04\x0a": "O", b"\x55\x04\x03": "CN"}.get(oc)
            if key and key not in found:
                try:
                    found[key] = vc.decode("utf-8")
                except UnicodeDecodeError:
                    pass  # bytes that are not UTF-8: passed over
    return found.get("O", found.get("CN"))


def verify(context: dict, i: dict) -> dict:
    try:
        return _verify(context, i)
    except Reject as r:
        return {"outcome": "rejected", "reason": str(r)}


def _verify(context: dict, i: dict) -> dict:
    p, path = steps_1_to_5(context, i["binding"], i["now"])
    return steps_6_to_8(context, i, p, path)


def steps_1_to_5(context: dict, binding, now: int):
    """What a node can check without resolving a DID (README `check: "store"`)."""
    h, p, signing_input, sig = parse_binding(binding)
    # 2. the certificate path
    text = context.get("certificates", {}).get(h["x5u"])
    if not isinstance(text, str):
        raise Reject("untrusted-certificate")
    chain = load_chain(text)
    anchors = []
    for a in context.get("trust_anchors", []):
        try:  # an entry that is not padded base64 of a certificate is ignored
            anchors.append(parse_cert(padded_b64(a)))
        except (ValueError, TypeError, binascii.Error):
            pass
    path = None
    for candidate in build_paths(chain, anchors):
        try:
            check_path(candidate, now)
            path = candidate
            break
        except Reject:
            pass
    if path is None:
        raise Reject("untrusted-certificate")
    # 3. the signature
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if len(sig) != 64 or not (0 < r < N_P256 and 0 < s < N_P256):
        raise Reject("signature")
    try:
        path[0].key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Reject("signature")
    # 4. coverage
    d = p["tn"][1:]
    spc = context.get("spc_numbers", {})
    if path[0].tnauth is None or any(c.tnauth is not None and not covers(c.tnauth, d, spc) for c in path):
        raise Reject("not-authorized-for-tn")
    # 5. time
    if p["exp"] - p["iat"] > LIFETIME_MAX:
        raise Reject("lifetime-too-long")
    if p["iat"] > now + IAT_TOLERANCE:
        raise Reject("not-yet-valid")
    if now >= p["exp"]:
        raise Reject("expired")
    return p, path


def steps_6_to_8(context: dict, i: dict, p: dict, path: list) -> dict:
    # 6–7. the DID, and its claim back
    if p["did"] != i["did"]:
        raise Reject("did-mismatch")
    doc = i.get("did_document")
    if (not isinstance(doc, dict) or doc.get("id") != i["did"] or not isinstance(doc.get("alsoKnownAs"), list)
            or "tel:" + p["tn"] not in [a for a in doc["alsoKnownAs"] if isinstance(a, str)]):
        raise Reject("not-claimed-by-did")
    # 8. status, by policy
    if context.get("require_status"):
        answer = context.get("status", {}).get(p.get("status")) if "status" in p else None
        if answer == "revoked":
            raise Reject("revoked")
        if answer != "good":
            raise Reject("status-unavailable")
    return {"outcome": "verified", "tn": p["tn"], "did": p["did"], "expires": p["exp"], "attested_by": attested_by(path[0])}


def claim(context: dict, i: dict) -> dict:
    """N§4: a `tel` claim carrying a binding, verified against the envelope's signing identity."""
    c = i["claim"]
    if not (isinstance(c, dict) and c.get("type") == "tel" and "binding" in c) or isinstance(c.get("verifier"), str):
        return {"outcome": "ignored"}
    number = c.get("number")
    line = f"{number} (unverified)" if isinstance(number, str) and TN_RE.fullmatch(number) else None
    if not isinstance(c["binding"], str):
        return {"outcome": "dropped", "reason": "malformed", "line": line}
    r = verify(context, {"binding": c["binding"], "did": i["identity"], "did_document": i.get("did_document"),
                         "now": i["now"]})
    if r["outcome"] != "verified":
        return {"outcome": "dropped", "reason": r["reason"], "line": line}
    if number != r["tn"]:
        return {"outcome": "dropped", "reason": "number-mismatch", "line": line}
    by = f" by {r['attested_by']}" if r["attested_by"] is not None else ""
    _, p, _, _ = parse_binding(c["binding"])
    return {"outcome": "attested", "line": f"{r['tn']} · number attested{by} for this identity",
            "issued": p["iat"], "expires": r["expires"]}


def contact(contacts: list, attested: dict):
    """N§5: the warning when a stored contact's number is now attested for another identity."""
    tn, did = attested["tn"], attested["did"]
    listing = [c for c in contacts if tn in c.get("numbers", [])]
    if not listing or any(c["did"] == did for c in listing):
        return None
    import datetime
    date = datetime.datetime.fromtimestamp(attested["issued"], datetime.timezone.utc).strftime("%Y-%m-%d")
    by = f" by {attested['attested_by']}" if attested.get("attested_by") is not None else ""
    c = listing[0]
    return (f"{tn} now belongs to a different identity (number attested{by} since {date}). "
            f'Your contact "{c["name"]}" is {c["did"]}.')


def payload_of(binding: str) -> dict:
    return json.loads(b64u(binding.split(".")[1]))


def held_payload(h):
    """A held entry's payload, when it reads: three segments, the second an I-JSON object with a string `did` and
    integer `iat` and `exp`. The header and signature are not looked at (README `check: "store"`)."""
    try:
        parts = h.split(".")
        if len(parts) != 3:
            return None
        p = json_object(b64u(parts[1]))
    except (AttributeError, Reject, ValueError):
        return None
    ok = isinstance(p.get("did"), str) and is_int(p.get("iat")) and is_int(p.get("exp"))
    return p if ok else None


def held_order(bs: list[str]) -> list[str]:
    return sorted(bs, key=lambda b: (-payload_of(b)["iat"], b.encode()))


def store(context: dict, i: dict) -> dict:
    """A node's verify-before-store for PUT /dsip/v1/tn/<tn> (N§6 route 1)."""
    tn, b, now = i["tn"], i["binding"], i["now"]
    if not (isinstance(tn, str) and TN_RE.fullmatch(tn)):
        return {"outcome": "rejected", "reason": "bad-number"}
    try:
        p, _ = steps_1_to_5(context, b, now)
    except Reject as r:
        return {"outcome": "rejected", "reason": str(r)}
    if p["tn"] != tn:
        return {"outcome": "rejected", "reason": "tn-mismatch"}
    held_in = i["held"] if isinstance(i["held"], list) else []
    held = [h for h in held_in if held_payload(h) is not None and now < held_payload(h)["exp"]]
    same = [h for h in held if payload_of(h)["did"] == p["did"]]
    if same:
        h = same[0]
        if h == b:
            return {"outcome": "kept", "reason": "same"}
        if p["iat"] > payload_of(h)["iat"]:
            return {"outcome": "stored", "held": held_order([x for x in held if x != h] + [b])}
        return {"outcome": "kept", "reason": "older"}
    if len(held) < 4:
        return {"outcome": "stored", "held": held_order(held + [b])}
    low = min(payload_of(h)["iat"] for h in held)
    victim = max((h for h in held if payload_of(h)["iat"] == low), key=str.encode)
    if p["iat"] > payload_of(victim)["iat"]:
        return {"outcome": "stored", "held": held_order([x for x in held if x != victim] + [b])}
    return {"outcome": "kept", "reason": "full"}


def select(context: dict, i: dict) -> dict:
    """The reader's choice among the bindings a lookup returned (N§6, N§7)."""
    verified = []
    documents = i["documents"] if isinstance(i["documents"], dict) else {}
    for b in i["bindings"] if isinstance(i["bindings"], list) else []:
        try:
            did = payload_of(b)["did"] if isinstance(b, str) else None
        except Exception:
            continue
        if not isinstance(did, str):
            continue
        r = verify(context, {"binding": b, "did": did, "did_document": documents.get(did), "now": i["now"]})
        if r["outcome"] == "verified" and r["tn"] == i["tn"]:
            verified.append((payload_of(b)["iat"], b, r))
    if not verified:
        return {"outcome": "none"}
    iat, b, r = min(verified, key=lambda x: (-x[0], x[1].encode()))
    others = sorted({v[2]["did"] for v in verified if v[2]["did"] != r["did"]})
    return {"outcome": "found", "did": r["did"], "attested_by": r["attested_by"], "issued": iat, "others": others}


def run(v: dict):
    i = v["input"]
    if i.get("check") == "store":
        return store(v.get("context", {}), i)
    if i.get("check") == "select":
        return select(v.get("context", {}), i)
    if i.get("check") == "claim":
        return claim(v.get("context", {}), i)
    if i.get("check") == "contact":
        return contact(i["contacts"], i["attested"])
    return verify(v.get("context", {}), i)
