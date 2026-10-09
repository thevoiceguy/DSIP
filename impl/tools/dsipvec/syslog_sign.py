"""Signed syslog (RFC 5848, syslog-sign): a gateway's collector, as E§3 (v0.10) pins it.

Spec: E§3 (signed syslog), E§2 (the `syslog-signed` basis and its `signed` claim). The exact rules are
`impl/vectors/README.md`, component `syslog-sign`.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_der_x509_certificate

from .events_v3 import parse_syslog

VERSIONS = {"0111": ("sha1", 20, hashes.SHA1()), "0121": ("sha256", 32, hashes.SHA256())}
SIG_PARAMS = ["VER", "RSID", "SG", "SPRI", "GBC", "FMN", "CNT", "HB", "SIGN"]
CERT_PARAMS = ["VER", "RSID", "SG", "SPRI", "TPBL", "INDEX", "FLEN", "FRAG", "SIGN"]
B64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")


class Bad(Exception):
    pass


def b64(s: str) -> bytes:
    if not B64.match(s):
        raise Bad
    try:
        return base64.b64decode(s, validate=True)
    except binascii.Error:
        raise Bad from None


def mpis(b: bytes) -> list[int]:
    """OpenPGP MPIs (RFC 4880 §3.2): a 2-byte bit count, then ⌈bits/8⌉ bytes; the count gives only the length."""
    out, i = [], 0
    while i < len(b):
        if i + 2 > len(b):
            raise Bad
        n = (int.from_bytes(b[i:i + 2], "big") + 7) // 8
        if i + 2 + n > len(b):
            raise Bad
        out.append(int.from_bytes(b[i + 2:i + 2 + n], "big"))
        i += 2 + n
    return out


def dec(s: str, digits: int, lo: int = 0, hi: int | None = None) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", s) or len(s) > digits:
        raise Bad
    v = int(s)
    if v < lo or (hi is not None and v > hi):
        raise Bad
    return v


def element_end(msg: bytes, start: int):
    """The index of the `]` closing the SD element that starts at `start`: outside quotes, honouring `\\` escapes."""
    if start >= len(msg) or msg[start] != 0x5B:
        return None
    quoted, i = False, start + 1
    while i < len(msg):
        c = msg[i]
        if quoted and c == 0x5C:
            i += 2
            continue
        if c == 0x22:
            quoted = not quoted
        elif c == 0x5D and not quoted:
            return i
        i += 1
    return None


def pgp_packets(b: bytes):
    """OpenPGP packets (RFC 4880 §4.2): (tag, body) for each, or None when one does not read."""
    out, i = [], 0
    while i < len(b):
        h = b[i]
        if not h & 0x80:
            return None
        if h & 0x40:  # new format
            tag, i = h & 0x3F, i + 1
            if i >= len(b):
                return None
            f = b[i]
            if f < 192:
                n, i = f, i + 1
            elif f < 224:
                if i + 2 > len(b):
                    return None
                n, i = ((f - 192) << 8) + b[i + 1] + 192, i + 2
            elif f == 255:
                if i + 5 > len(b):
                    return None
                n, i = int.from_bytes(b[i + 1:i + 5], "big"), i + 5
            else:
                return None  # a partial body length
        else:  # old format
            tag, lt, i = (h >> 2) & 0x0F, h & 3, i + 1
            if lt == 3:
                return None  # indeterminate length
            w = 1 << lt
            if i + w > len(b):
                return None
            n, i = int.from_bytes(b[i:i + w], "big"), i + w
        if i + n > len(b):
            return None
        out.append((tag, b[i:i + n]))
        i += n
    return out


def pgp_dsa_key(blob: bytes):
    """A `P` key blob: the KeyID, then a certificate whose first packet is a v4 DSA public key (README)."""
    kid, packets = blob[:8], pgp_packets(blob[8:])
    if len(blob) < 8 or not packets or packets[0][0] != 6:
        return None
    body = packets[0][1]
    if len(body) < 6 or body[0] != 4 or body[5] != 17:
        return None
    m, i = [], 6
    while i < len(body) and len(m) < 4:
        n = (int.from_bytes(body[i:i + 2], "big") + 7) // 8
        if i + 2 + n > len(body):
            return None
        m.append(int.from_bytes(body[i + 2:i + 2 + n], "big"))
        i += 2 + n
    if len(m) != 4 or i != len(body):
        return None
    if hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).digest()[-8:] != kid:
        return None
    p, q, g, y = m
    try:
        return dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g)).public_key()
    except ValueError:
        return None


def public_key(signer: dict):
    raw = base64.b64decode(signer["key"])
    if signer["type"] == "C":
        return load_der_x509_certificate(raw).public_key()
    if signer["type"] == "P":
        return pgp_dsa_key(raw)
    p, q, g, y = mpis(raw)
    return dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g)).public_key()


class Collector:
    """A gateway's syslog-sign collector (README component `syslog-sign`)."""

    def __init__(self, ctx: dict):
        self.now, self.hold = ctx["now"], ctx["hold_s"]
        self.signers = {}
        for s in ctx["signers"]:
            raw = base64.b64decode(s["key"])
            self.signers[s["hostname"].lower()] = {**s, "raw": raw, "sha256": hashlib.sha256(raw).hexdigest(),
                                                   "pub": public_key(s)}
        self.held: list[dict] = []        # {msg, sha256, due}
        self.waiting: list[dict] = []     # {alg, hash, group, number, due}
        self.frags: dict[tuple, dict] = {}       # session -> {tpbl, bytes: {pos: byte}}
        self.sessions: dict[tuple, bytes] = {}   # session -> payload
        self.highest: dict[tuple, int] = {}      # (host, app) -> highest established RSID
        self.authed: set[tuple] = set()          # (group, number)
        self.covered: dict[tuple, int] = {}      # group -> highest number covered (gap detection)

    # --- a block -------------------------------------------------------------------------------

    def _block(self, msg: bytes, sl: dict, kind: str) -> list:
        def refused(reason):
            return [{"refused": {"block": kind, "reason": reason}}]
        sd = sl["structured_data"]
        names = CERT_PARAMS if kind == "ssign-cert" else SIG_PARAMS
        try:
            if len(sd) != 1 or [p["name"] for p in sd[0]["params"]] != names:
                raise Bad
            v = {p["name"]: p["value"] for p in sd[0]["params"]}
            if len(v["VER"]) != 4:
                raise Bad
            f = {"RSID": dec(v["RSID"], 10), "SG": dec(v["SG"], 1, 0, 3), "SPRI": dec(v["SPRI"], 3, 0, 191)}
            r_s = mpis(b64(v["SIGN"]))
            if len(r_s) != 2:
                raise Bad
            if kind == "ssign":
                f["GBC"] = dec(v["GBC"], 10)
                f["FMN"] = dec(v["FMN"], 10, 1)
                f["CNT"] = dec(v["CNT"], 2, 1, 99)
                toks = v["HB"].split(" ")
                if len(toks) != f["CNT"] or "" in toks:
                    raise Bad
                hb = [b64(t) for t in toks]
                if v["VER"] in VERSIONS and any(len(h) != VERSIONS[v["VER"]][1] for h in hb):
                    raise Bad
            else:
                f["TPBL"] = dec(v["TPBL"], 8, 1)
                f["INDEX"] = dec(v["INDEX"], 8, 1)
                f["FLEN"] = dec(v["FLEN"], 4, 1)
                frag = v["FRAG"].encode("utf-8")
                if len(frag) != f["FLEN"] or f["INDEX"] + f["FLEN"] - 1 > f["TPBL"]:
                    raise Bad
        except Bad:
            return refused("malformed-block")
        if v["VER"] not in VERSIONS:
            return refused("unsupported-version")
        host = (sl["hostname"] or "").lower()
        signer = self.signers.get(host)
        if signer is None:
            return refused("unknown-signer")
        # the signed bytes: the message without ` SIGN="…"`, which ends just before the element's `]`
        start = [i for i, c in enumerate(msg) if c == 0x20][5] + 1
        close = element_end(msg, start)
        if close is None:
            return refused("malformed-block")
        cut = b' SIGN="' + v["SIGN"].encode() + b'"'
        if msg[close - len(cut):close] != cut:
            return refused("malformed-block")
        signed = msg[:close - len(cut)] + msg[close:]
        r, s = r_s
        if signer["pub"] is None:  # a configured key that does not read (README `P`): the signer has no key
            return refused("bad-signature")
        q = signer["pub"].parameters().parameter_numbers().q
        try:
            if not (0 < r < q and 0 < s < q):
                raise InvalidSignature
            signer["pub"].verify(encode_dss_signature(r, s), signed, VERSIONS[v["VER"]][2])
        except InvalidSignature:
            return refused("bad-signature")
        app, procid, rsid = sl["app_name"], sl["procid"], f["RSID"]
        if rsid > 0 and rsid < self.highest.get((host, app), 0):
            return refused("old-session")
        session = (host, app, procid, rsid)
        if kind == "ssign-cert":
            return self._cert(session, sl, f, frag, signer, refused)
        return self._sig(session, sl, f, hb, VERSIONS[v["VER"]][0], signer, refused)

    def _cert(self, session, sl, f, frag, signer, refused) -> list:
        if session in self.sessions:
            pay = self.sessions[session]
            if len(pay) == f["TPBL"] and pay[f["INDEX"] - 1:f["INDEX"] - 1 + f["FLEN"]] == frag:
                return []
            # a different payload for an established session: it ends, and assembly starts anew
            del self.sessions[session]
            self.authed = {a for a in self.authed if a[0][0] != session}
            self.waiting = [w for w in self.waiting if w["group"][0] != session]
            self.covered = {g: c for g, c in self.covered.items() if g[0] != session}
        st = self.frags.get(session)
        if st is not None:
            if st["tpbl"] != f["TPBL"] or any(st["bytes"].get(f["INDEX"] - 1 + i, c) != c for i, c in enumerate(frag)):
                return refused("fragment-mismatch")
        else:
            st = self.frags[session] = {"tpbl": f["TPBL"], "bytes": {}}
        for i, c in enumerate(frag):
            st["bytes"][f["INDEX"] - 1 + i] = c
        if len(st["bytes"]) < st["tpbl"]:
            return []
        payload = bytes(st["bytes"][i] for i in range(st["tpbl"]))
        del self.frags[session]
        # the key blob type (RFC 5848 §5.2.1; README): C, K, P carry the configured blob; N is the configured key;
        # U has no interoperable reading
        parts = payload.split(b" ")
        if not 2 <= len(parts) <= 3 or not parts[0] or parts[1] not in (b"C", b"K", b"P", b"N", b"U"):
            return refused("payload-mismatch")
        if parts[1] == b"U":
            return refused("unsupported-key-blob")
        try:
            if parts[1] == b"N":
                if len(parts) != 2:
                    raise Bad
            elif len(parts) != 3 or parts[1].decode() != signer["type"] or b64(parts[2].decode()) != signer["raw"]:
                raise Bad
        except (Bad, UnicodeDecodeError):
            return refused("payload-mismatch")
        self.sessions[session] = payload
        key = (session[0], session[1])
        self.highest[key] = max(self.highest.get(key, 0), session[3])
        return [{"session": {"hostname": sl["hostname"], "app_name": sl["app_name"], "procid": sl["procid"],
                             "rsid": session[3], "key_sha256": signer["sha256"]}}]

    def _sig(self, session, sl, f, hb, alg, signer, refused) -> list:
        if session not in self.sessions:
            return refused("no-session")
        group = (session, f["SG"], f["SPRI"])
        out = []
        if signer.get("gaps"):
            cov = self.covered.get(group, 0)
            if cov > 0 and f["FMN"] > cov + 1:
                out.append({"gap": {"hostname": sl["hostname"], "app_name": sl["app_name"], "procid": sl["procid"],
                                    "rsid": session[3], "sg": f["SG"], "spri": f["SPRI"], "from": cov + 1,
                                    "to": f["FMN"] - 1}})
            self.covered[group] = max(cov, f["FMN"] + len(hb) - 1)
        for i, h in enumerate(hb):
            n = f["FMN"] + i
            if (group, n) in self.authed:
                continue
            claim = {"hostname": sl["hostname"], "app_name": sl["app_name"], "procid": sl["procid"],
                     "rsid": session[3], "sg": f["SG"], "spri": f["SPRI"], "message_number": n,
                     "key_sha256": signer["sha256"]}
            m = next((m for m in self.held if hashlib.new(alg, m["msg"]).digest() == h), None)
            if m is not None:
                self.held.remove(m)
                self.authed.add((group, n))
                out.append({"deposit": {"sha256": m["sha256"], "signed": claim}})
            elif not any(w["group"] == group and w["number"] == n for w in self.waiting):
                self.waiting.append({"alg": alg, "hash": h, "group": group, "number": n, "claim": claim,
                                     "due": self.now + self.hold})
        return out

    # --- the trace -------------------------------------------------------------------------------

    def receive(self, msg: bytes) -> list:
        sha = hashlib.sha256(msg).hexdigest()
        p = parse_syslog(msg)
        sl = p.get("syslog")
        if sl is None or sl["format"] != "rfc5424" or sl["hostname"] is None:
            return [{"deposit": {"sha256": sha, "signed": None}}]
        ids = [e["id"] for e in sl["structured_data"]]
        kind = next((i for i in ids if i in ("ssign", "ssign-cert")), None)
        if kind is not None:
            return self._block(msg, sl, kind)
        if sl["hostname"].lower() not in self.signers:
            return [{"deposit": {"sha256": sha, "signed": None}}]
        w = next((w for w in self.waiting if hashlib.new(w["alg"], msg).digest() == w["hash"]), None)
        if w is not None:
            self.waiting.remove(w)
            self.authed.add((w["group"], w["number"]))
            return [{"deposit": {"sha256": sha, "signed": w["claim"]}}]
        self.held.append({"msg": msg, "sha256": sha, "due": self.now + self.hold})
        return []

    def advance(self, n: int) -> list:
        self.now += n
        out = [{"deposit": {"sha256": m["sha256"], "signed": None}} for m in self.held if m["due"] <= self.now]
        self.held = [m for m in self.held if m["due"] > self.now]
        lost = [w for w in self.waiting if w["due"] <= self.now and self.signers[w["group"][0][0]].get("gaps")]
        self.waiting = [w for w in self.waiting if w["due"] > self.now]
        lost.sort(key=lambda w: ((w["group"][0][0], w["group"][0][1] or "", w["group"][0][2] or "", w["group"][0][3]),
                                 w["group"][1], w["group"][2], w["number"]))
        for w in lost:
            c = w["claim"]
            last = out[-1]["gap"] if out and "gap" in out[-1] else None
            if last is not None and last["_group"] == w["group"] and last["to"] + 1 == w["number"]:
                last["to"] = w["number"]
            else:
                out.append({"gap": {"hostname": c["hostname"], "app_name": c["app_name"], "procid": c["procid"],
                                    "rsid": c["rsid"], "sg": c["sg"], "spri": c["spri"], "from": w["number"],
                                    "to": w["number"], "_group": w["group"]}})
        for o in out:
            if "gap" in o:
                o["gap"].pop("_group", None)
        return out

    def step(self, ev: dict) -> dict:
        if "receive" in ev:
            emit = self.receive(bytes.fromhex(ev["receive"]["message"]))
        else:
            emit = self.advance(ev["advance"])
        return {"emit": emit, "held": [m["sha256"] for m in self.held], "waiting": len(self.waiting)}


def run(v: dict) -> list:
    c = Collector(v["context"])
    return [c.step(st["event"]) for st in v["input"]["steps"]]
