"""Device Events inputs beyond v1/v2c: SNMPv3 with USM, and syslog (RFC 5424 and RFC 3164).

Spec: E§2 (the claim an authenticated basis adds), E§3 (USM as RFC 3414 §3.2 orders it; RFC 7860 SHA-2 HMACs;
RFC 3826 AES-128-CFB; syslog parsed into `raw.syslog`), E§4 (syslog rules). The exact rules are in
`impl/vectors/README.md` (`check: "syslog"`, `check: "usm-key"`, component `snmpv3`).

Impl (spec-gap 103): noAuthNoPriv and DES refused; a password user may be engine-wildcard; a trap engine's cache is
seeded by its first authenticated message; Reports only for discovery and time synchronization; RFC 3164 accepted.
"""
from __future__ import annotations

import hashlib
import hmac
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:  # CFB moved to the "decrepit" module in cryptography 47+
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.modes import CFB

HASHES = {"md5": hashlib.md5, "sha": hashlib.sha1, "sha224": hashlib.sha224, "sha256": hashlib.sha256,
          "sha384": hashlib.sha384, "sha512": hashlib.sha512}
MAC_LEN = {"md5": 12, "sha": 12, "sha224": 16, "sha256": 24, "sha384": 32, "sha512": 48}
WINDOW = 150
MAX31 = 2**31 - 1


class Malformed(Exception):
    pass


# --- BER ----------------------------------------------------------------------------------------

def tlv(b: bytes, pos: int, end: int):
    """(tag, content start, content end) of the TLV at pos, within end."""
    if pos + 2 > end:
        raise Malformed
    tag = b[pos]
    if tag & 0x1F == 0x1F:
        raise Malformed
    first = b[pos + 1]
    off = pos + 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        if k == 0 or k > 4 or off + k > end:
            raise Malformed
        n = int.from_bytes(b[off:off + k], "big")
        off += k
    if off + n > end:
        raise Malformed
    return tag, off, off + n


class R:
    def __init__(self, b: bytes, start: int = 0, end: int | None = None):
        self.b, self.pos, self.end = b, start, len(b) if end is None else end

    def next(self):
        tag, s, e = tlv(self.b, self.pos, self.end)
        self.pos = e
        return tag, s, e

    def expect(self, tag):
        t, s, e = self.next()
        if t != tag:
            raise Malformed
        return s, e

    def done(self):
        return self.pos >= self.end


def ber_int(b: bytes) -> int:
    if not 1 <= len(b) <= 8:
        raise Malformed
    return int.from_bytes(b, "big", signed=True)


def ber_uint(b: bytes) -> int:
    if not 1 <= len(b) <= 9 or (len(b) == 9 and b[0] != 0):
        raise Malformed
    return int.from_bytes(b, "big")


def ber_oid(b: bytes) -> str:
    if not b or b[-1] & 0x80:
        raise Malformed
    subs, acc = [], 0
    for x in b:
        acc = (acc << 7) | (x & 0x7F)
        if acc > 2**64 - 1:
            raise Malformed
        if not x & 0x80:
            subs.append(acc)
            acc = 0
    x = subs[0]
    head = [0, x] if x < 40 else [1, x - 40] if x < 80 else [2, x - 80]
    return ".".join(str(n) for n in head + subs[1:])


def _printable(b: bytes):
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) <= 0x1F or 0x7F <= ord(c) <= 0x9F for c in s):
        return None
    return s


def ber_value(tag: int, c: bytes):
    if tag == 0x02:
        return "Integer32", str(ranged(ber_int(c), -2**31, MAX31))
    if tag == 0x04:
        t = _printable(c)
        return "OCTET STRING", t if t is not None else c.hex()
    if tag == 0x05:
        if c:
            raise Malformed
        return "NULL", ""
    if tag == 0x06:
        return "OBJECT IDENTIFIER", ber_oid(c)
    if tag == 0x40:
        if len(c) != 4:
            raise Malformed
        return "IpAddress", ".".join(str(x) for x in c)
    names = {0x41: "Counter32", 0x42: "Gauge32", 0x43: "TimeTicks", 0x46: "Counter64"}
    if tag in names:
        v = ber_uint(c)
        if tag != 0x46 and v > 2**32 - 1:
            raise Malformed
        return names[tag], str(v)
    if tag == 0x44:
        return "Opaque", c.hex()
    raise Malformed


def ranged(v, lo, hi):
    if not lo <= v <= hi:
        raise Malformed
    return v


def parse_scoped_pdu(b: bytes):
    """Bytes that are exactly one ScopedPDU → (pdu tag, request id, varbinds)."""
    r = R(b)
    ss, se = r.expect(0x30)
    if not r.done():
        raise Malformed
    return scoped_content(b, ss, se)


def scoped_content(b: bytes, ss: int, se: int):
    """The content b[ss:se] of a ScopedPDU SEQUENCE → (pdu tag, request id, varbinds)."""
    q = R(b, ss, se)
    q.expect(0x04)
    q.expect(0x04)
    tag, ps, pe = q.next()
    if not q.done():
        raise Malformed
    p = R(b, ps, pe)
    a, z = p.expect(0x02)
    rid = ranged(ber_int(b[a:z]), -2**31, MAX31)
    for _ in range(2):
        a, z = p.expect(0x02)
        ber_int(b[a:z])
    vs, ve = p.expect(0x30)
    if not p.done():
        raise Malformed
    vbs, v = [], R(b, vs, ve)
    while not v.done():
        bs, be = v.expect(0x30)
        one = R(b, bs, be)
        os_, oe = one.expect(0x06)
        t, cs, ce = one.next()
        if not one.done():
            raise Malformed
        typ, val = ber_value(t, b[cs:ce])
        vbs.append({"oid": ber_oid(b[os_:oe]), "type": typ, "value": val})
    return tag, rid, vbs


def parse_v3(b: bytes) -> dict:
    """Step 1 of the README's pipeline: the structure, or Malformed."""
    top = R(b)
    ms, me = top.expect(0x30)
    if not top.done():
        raise Malformed
    m = R(b, ms, me)
    a, z = m.expect(0x02)
    if ber_int(b[a:z]) != 3:
        raise Malformed
    gs, ge = m.expect(0x30)
    g = R(b, gs, ge)
    a, z = g.expect(0x02)
    msg_id = ranged(ber_int(b[a:z]), 0, MAX31)
    a, z = g.expect(0x02)
    ranged(ber_int(b[a:z]), 484, MAX31)
    a, z = g.expect(0x04)
    if z - a != 1:
        raise Malformed
    flags = b[a]
    a, z = g.expect(0x02)
    model = ranged(ber_int(b[a:z]), 0, MAX31)
    if not g.done():
        raise Malformed
    auth, priv, reportable = bool(flags & 1), bool(flags & 2), bool(flags & 4)
    if priv and not auth:
        raise Malformed
    ps, pe = m.expect(0x04)
    sp = R(b, ps, pe)
    ss, se = sp.expect(0x30)
    if not sp.done():
        raise Malformed
    u = R(b, ss, se)
    a, z = u.expect(0x04)
    engine = b[a:z]
    if len(engine) not in (0,) and not 5 <= len(engine) <= 32:
        raise Malformed
    a, z = u.expect(0x02)
    boots = ranged(ber_int(b[a:z]), 0, MAX31)
    a, z = u.expect(0x02)
    etime = ranged(ber_int(b[a:z]), 0, MAX31)
    a, z = u.expect(0x04)
    user = b[a:z]
    if len(user) > 32:
        raise Malformed
    auth_s, auth_e = u.expect(0x04)
    a, z = u.expect(0x04)
    priv_params = b[a:z]
    if not u.done():
        raise Malformed
    out = {"msg_id": msg_id, "flags": flags, "auth": auth, "priv": priv, "reportable": reportable, "model": model,
           "engine": engine, "boots": boots, "time": etime, "user": user, "auth_span": (auth_s, auth_e),
           "priv_params": priv_params}
    if priv:
        a, z = m.expect(0x04)
        out["encrypted"] = b[a:z]
    else:
        s, e = m.expect(0x30)
        out["pdu"] = scoped_content(b, s, e)
    if not m.done():
        raise Malformed
    return out


# --- SNMPv3 over TLS: TLSTM (RFC 6353) and TSM (RFC 5591), E§3 v0.10 ----------------------------

TLS_MAX = 65536
LOCAL_ENGINE_ID = bytes.fromhex("8000000006")  # RFC 5343 §3.1
SNMP_ENGINE_ID_OID = "1.3.6.1.6.3.10.2.1.1.0"


def tls_frames(stream: bytes) -> dict:
    """Split a TLS byte stream into whole BER messages (README `check: "tls-frames"`)."""
    msgs, pos = [], 0
    while True:
        rest = stream[pos:]
        if len(rest) < 2:
            return {"messages": msgs, "pending": rest.hex()}
        if rest[0] != 0x30 or rest[1] == 0x80 or rest[1] >= 0x85:
            return {"messages": msgs, "pending": rest.hex(), "close": True}
        if rest[1] < 0x80:
            hdr, n = 2, rest[1]
        else:
            k = rest[1] & 0x7F
            if len(rest) < 2 + k:
                return {"messages": msgs, "pending": rest.hex()}
            hdr, n = 2 + k, int.from_bytes(rest[2:2 + k], "big")
        if hdr + n > TLS_MAX:
            return {"messages": msgs, "pending": rest.hex(), "close": True}
        if len(rest) < hdr + n:
            return {"messages": msgs, "pending": rest.hex()}
        msgs.append(rest[:hdr + n].hex())
        pos += hdr + n


def dtls_record(record: bytes) -> dict:
    """A DTLS record is exactly one message (README `check: "dtls-record"`; E§3 v0.11)."""
    f = tls_frames(record)
    if len(f["messages"]) == 1 and f["pending"] == "" and not f.get("close"):
        return {"message": f["messages"][0]}
    return {"error": "not-one-message"}


def parse_tsm(b: bytes):
    """Step 1 for TSM: USM's structure, except securityParameters is any OCTET STRING and msgData always a
    ScopedPDU → (msgSecurityModel, (tag, request id, varbinds))."""
    top = R(b)
    ms, me = top.expect(0x30)
    if not top.done():
        raise Malformed
    m = R(b, ms, me)
    a, z = m.expect(0x02)
    if ber_int(b[a:z]) != 3:
        raise Malformed
    gs, ge = m.expect(0x30)
    g = R(b, gs, ge)
    a, z = g.expect(0x02)
    ranged(ber_int(b[a:z]), 0, MAX31)
    a, z = g.expect(0x02)
    ranged(ber_int(b[a:z]), 484, MAX31)
    a, z = g.expect(0x04)
    if z - a != 1:
        raise Malformed
    flags = b[a]
    a, z = g.expect(0x02)
    model = ranged(ber_int(b[a:z]), 0, MAX31)
    if not g.done():
        raise Malformed
    if flags & 2 and not flags & 1:
        raise Malformed
    m.expect(0x04)
    s, e = m.expect(0x30)
    pdu = scoped_content(b, s, e)
    if not m.done():
        raise Malformed
    q = R(b, s, e)
    a, z = q.expect(0x04)
    return model, pdu, b[a:z]


def tsm_receive(b: bytes) -> dict:
    """One message from a TLS connection (README `check: "tsm"`)."""
    try:
        model, (tag, rid, vbs), ctx_engine = parse_tsm(b)
    except (Malformed, IndexError):
        return {"refused": {"reason": "malformed"}}
    if model != 4:
        return {"refused": {"reason": "unsupported-security-model"}}
    if tag == 0xA0 and ctx_engine == LOCAL_ENGINE_ID and len(vbs) == 1 and vbs[0]["oid"] == SNMP_ENGINE_ID_OID:
        return {"discovery": {"request_id": rid}}
    if tag not in (0xA7, 0xA6):
        return {"refused": {"reason": "not-a-notification"}}
    trap = {"version": "v3", "varbinds": vbs}
    if tag == 0xA6:
        trap["inform"] = {"request_id": rid}
    return {"accepted": {"trap": trap}}


def _lower_ascii(s: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def _san_name(san: dict):
    t, v = san.get("type"), san.get("value")
    if not isinstance(v, str):
        return None
    if t == "rfc822":
        if "@" not in v:
            return None
        i = v.rindex("@")
        return v[:i + 1] + _lower_ascii(v[i + 1:])
    if t == "dns":
        return _lower_ascii(v)
    if t == "ip":
        try:
            a = bytes.fromhex(v)
        except ValueError:
            return None
        if len(a) == 4:
            return ".".join(str(x) for x in a)
        if len(a) == 16:
            return a.hex()
        return None
    return None


def tsm_name(cert: dict, table: list) -> dict:
    """RFC 6353's snmpTlstmCertToTSNTable as E§3 pins it (README `check: "tsm-name"`)."""
    fps = {cert["sha256"].lower(), *(c.lower() for c in cert.get("chain", []))}
    sans = cert.get("san", [])
    for row in sorted(table, key=lambda r: r["id"]):
        if not isinstance(row.get("fingerprint"), str) or row["fingerprint"].lower() not in fps:
            continue
        mp, name = row.get("map"), None
        if mp == "specified":
            name = row.get("data") if isinstance(row.get("data"), str) else None
        elif mp in ("san-rfc822", "san-dns", "san-ip"):
            want = mp[4:]
            first = next((s for s in sans if s.get("type") == want), None)
            name = _san_name(first) if first else None
        elif mp == "san-any":
            first = next((s for s in sans if s.get("type") in ("rfc822", "dns", "ip")), None)
            name = _san_name(first) if first else None
        elif mp == "common-name":
            cn = cert.get("cn", [])
            name = cn[0] if cn and isinstance(cn[0], str) else None
        if name is not None and 1 <= len(name.encode("utf-8")) <= 32:
            return {"security_name": name, "row": row["id"]}
    return {"error": "no-security-name"}


# --- USM keys -----------------------------------------------------------------------------------

def password_to_key(auth: str, password: bytes, engine_id: bytes) -> bytes:
    h = HASHES[auth]
    rep = (password * (1048576 // len(password) + 1))[:1048576]
    ku = h(rep).digest()
    return h(ku + engine_id + ku).digest()


def usm_key(i: dict) -> dict:
    pw = i["password"].encode()
    if not pw:
        return {"error": "bad-password"}
    k = password_to_key(i["auth"], pw, bytes.fromhex(i["engine_id"]))
    return {"auth_key": k.hex(), "priv_key": k[:16].hex()}


def aes_cfb(key: bytes, iv: bytes, data: bytes, decrypt: bool) -> bytes:
    c = Cipher(algorithms.AES(key), CFB(iv))
    x = c.decryptor() if decrypt else c.encryptor()
    return x.update(data) + x.finalize()


# --- the USM receiver ---------------------------------------------------------------------------

class UsmReceiver:
    """A gateway's USM receiver (E§3; README component `snmpv3`)."""

    def __init__(self, ctx: dict):
        self.now = ctx["now"]
        self.start = ctx["now"]
        loc = ctx["local"]
        self.engine = bytes.fromhex(loc["engine_id"])
        self.boots, self.time0 = loc["boots"], loc["time"]
        self.users = ctx["users"]
        self.cache: dict[bytes, dict] = {}

    def local_time(self):
        return self.time0 + (self.now - self.start)

    def _user(self, engine: bytes, name: bytes):
        try:
            uname = name.decode("utf-8")
        except UnicodeDecodeError:
            return None
        for u in self.users:
            if u.get("engine_id") is not None and bytes.fromhex(u["engine_id"]) == engine and u["user"] == uname:
                return u
        for u in self.users:
            if u.get("engine_id") is None and u["user"] == uname:
                return u
        return None

    def keys(self, u: dict, engine: bytes):
        if "auth_key" in u:
            ak = bytes.fromhex(u["auth_key"])
        else:
            ak = password_to_key(u["auth"], u["auth_password"].encode(), engine)
        pk = None
        if u.get("priv"):
            pk = bytes.fromhex(u["priv_key"])[:16] if "priv_key" in u else \
                password_to_key(u["auth"], u["priv_password"].encode(), engine)[:16]
        return ak, pk

    def receive(self, b: bytes) -> dict:
        def refused(reason, report=False):
            return {"refused": {"reason": reason, "report": report}}
        try:
            m = parse_v3(b)
        except (Malformed, IndexError):
            return refused("malformed")
        if m["model"] != 3:
            return refused("unsupported-security-model")
        if not m["engine"]:
            return refused("unknown-engine-id", m["reportable"])
        u = self._user(m["engine"], m["user"])
        if u is None:
            return refused("unknown-user")
        if not m["auth"] or (m["priv"] and not u.get("priv")):
            return refused("unsupported-security-level")
        ak, pk = self.keys(u, m["engine"])
        L = MAC_LEN[u["auth"]]
        s, e = m["auth_span"]
        if e - s != L:
            return refused("wrong-digest")
        zeroed = b[:s] + bytes(L) + b[e:]
        mac = hmac.new(ak, zeroed, HASHES[u["auth"]]).digest()[:L]
        if not hmac.compare_digest(mac, b[s:e]):
            return refused("wrong-digest")
        authoritative = m["engine"] == self.engine
        if authoritative:
            if self.boots == MAX31 or m["boots"] != self.boots or abs(m["time"] - self.local_time()) > WINDOW:
                return refused("not-in-time-window", m["reportable"])
        else:
            c = self.cache.get(m["engine"])
            if c is None or m["boots"] > c["boots"] or (m["boots"] == c["boots"] and m["time"] > c["latest"]):
                c = self.cache[m["engine"]] = {"boots": m["boots"], "time": m["time"], "latest": m["time"],
                                               "at": self.now}
            if c["boots"] == MAX31 or m["boots"] < c["boots"] or \
                    (m["boots"] == c["boots"] and m["time"] < c["time"] + (self.now - c["at"]) - WINDOW):
                return refused("not-in-time-window")
        if m["priv"]:
            if len(m["priv_params"]) != 8:
                return refused("decryption-error")
            iv = m["boots"].to_bytes(4, "big") + m["time"].to_bytes(4, "big") + m["priv_params"]
            plain = aes_cfb(pk, iv, m["encrypted"], True)
            try:
                pdu = parse_scoped_pdu(plain)
            except (Malformed, IndexError):
                return refused("decryption-error")
        else:
            pdu = m["pdu"]
        tag, rid, vbs = pdu
        if tag not in (0xA7, 0xA6):
            return refused("not-a-notification")
        if (tag == 0xA7) == authoritative:
            return refused("engine-id-mismatch")
        trap = {"version": "v3", "varbinds": vbs}
        if tag == 0xA6:
            trap["inform"] = {"request_id": rid}
        return {"accepted": {"trap": trap, "usm": {"engine_id": m["engine"].hex(), "user": u["user"],
                                                   "level": "authPriv" if m["priv"] else "authNoPriv"}}}

    def snapshot(self):
        return [{"engine_id": k.hex(), "boots": c["boots"], "time": c["time"] + (self.now - c["at"]),
                 "latest": c["latest"]} for k, c in sorted(self.cache.items(), key=lambda kv: kv[0].hex())]

    def step(self, ev: dict) -> list:
        if "receive" in ev:
            return [self.receive(bytes.fromhex(ev["receive"]["datagram"]))]
        if "advance" in ev:
            self.now += ev["advance"]
            return []
        raise ValueError(ev)


# --- syslog -------------------------------------------------------------------------------------

MONTHS = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"]
TAG_BYTES = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-/")


def _text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _msg(b: bytes) -> str:
    return _text(b).rstrip("\r\n")


def _token(b: bytes, pos: int, maxlen: int | None):
    """A header token at pos (bytes 33–126 up to a space or the end) → (value or None for '-', next pos)."""
    end = pos
    while end < len(b) and b[end] != 0x20:
        if not 33 <= b[end] <= 126:
            raise Malformed
        end += 1
    tok = b[pos:end]
    if not tok or (maxlen is not None and len(tok) > maxlen):
        raise Malformed
    return (None if tok == b"-" else tok.decode("ascii")), end


def _sd_name(b: bytes, pos: int):
    end = pos
    while end < len(b) and 33 <= b[end] <= 126 and b[end] not in b'= ]"':
        end += 1
    if not 1 <= end - pos <= 32:
        raise Malformed
    return b[pos:end].decode("ascii"), end


def _parse_5424(b: bytes, pos: int, out: dict) -> dict:
    fields = [("timestamp", None), ("hostname", 255), ("app_name", 48), ("procid", 128), ("msgid", 32)]
    for name, mx in fields:
        if pos >= len(b) or b[pos] != 0x20:
            raise Malformed
        out[name], pos = _token(b, pos + 1, mx)
    if pos >= len(b) or b[pos] != 0x20:
        raise Malformed
    pos += 1
    sd = []
    if b[pos:pos + 1] == b"-":
        pos += 1
    else:
        if b[pos:pos + 1] != b"[":
            raise Malformed
        while b[pos:pos + 1] == b"[":
            sid, pos = _sd_name(b, pos + 1)
            params = []
            while b[pos:pos + 1] == b" ":
                pname, pos = _sd_name(b, pos + 1)
                if b[pos:pos + 2] != b'="':
                    raise Malformed
                pos += 2
                val = bytearray()
                while True:
                    if pos >= len(b):
                        raise Malformed
                    c = b[pos]
                    if c == 0x5C and pos + 1 < len(b) and b[pos + 1] in b'"\\]':
                        val.append(b[pos + 1])
                        pos += 2
                    elif c == 0x5C and pos + 1 < len(b):
                        val += b[pos:pos + 2]
                        pos += 2
                    elif c == 0x22:
                        pos += 1
                        break
                    else:
                        val.append(c)
                        pos += 1
                params.append({"name": pname, "value": _text(bytes(val))})
            if b[pos:pos + 1] != b"]":
                raise Malformed
            pos += 1
            sd.append({"id": sid, "params": params})
    out["structured_data"] = sd
    if pos == len(b):
        out["msg"] = ""
    elif b[pos] == 0x20:
        m = b[pos + 1:]
        if m.startswith(b"\xef\xbb\xbf"):
            m = m[3:]
        out["msg"] = _msg(m)
    else:
        raise Malformed
    return out


def _ts3164(b: bytes) -> bool:
    if len(b) < 16 or b[15] != 0x20 or b[:3] not in MONTHS or b[3] != 0x20 or b[6] != 0x20:
        return False
    dd = b[4:6]
    if not ((dd[0] == 0x20 and 0x31 <= dd[1] <= 0x39) or (dd.isdigit() and 10 <= int(dd) <= 31)):
        return False
    t = b[7:15]
    if not re.fullmatch(rb"[0-9]{2}:[0-9]{2}:[0-9]{2}", t):
        return False
    return int(t[:2]) <= 23 and int(t[3:5]) <= 59 and int(t[6:8]) <= 59


def _parse_3164(rest: bytes, out: dict) -> dict:
    out.update({"format": "rfc3164", "timestamp": None, "hostname": None, "msgid": None, "structured_data": []})
    content = rest
    if _ts3164(rest):
        out["timestamp"] = rest[:15].decode("ascii")
        after = rest[16:]
        end = 0
        while end < len(after) and 33 <= after[end] <= 126:
            end += 1
        if end > 0 and end < len(after) and after[end] == 0x20:
            out["hostname"] = after[:end].decode("ascii")
            content = after[end + 1:]
        else:
            content = after
    run = 0
    while run < len(content) and content[run] in TAG_BYTES:
        run += 1
    app, pid, msg = None, None, content
    if 1 <= run <= 32:
        m = re.match(rb"\[([0-9]{1,10})\]:", content[run:])
        if content[run:run + 1] == b":":
            app, rest_at = content[:run].decode("ascii"), run + 1
        elif m:
            app, pid, rest_at = content[:run].decode("ascii"), m.group(1).decode("ascii"), run + m.end()
        if app is not None:
            msg = content[rest_at:]
            if msg[:1] == b" ":
                msg = msg[1:]
    out.update({"app_name": app, "procid": pid, "msg": _msg(msg)})
    return out


def parse_syslog(b: bytes) -> dict:
    m = re.match(rb"<([0-9]{1,3})>", b)
    if not m or (len(m.group(1)) > 1 and m.group(1)[0] == 0x30) or int(m.group(1)) > 191:
        return {"error": "malformed-syslog"}
    pri = int(m.group(1))
    out = {"format": None, "facility": pri // 8, "severity": pri % 8}
    rest = b[m.end():]
    v = re.match(rb"([1-9][0-9]{0,2}) ", rest)
    try:
        if v:
            if v.group(1) != b"1":
                raise Malformed
            out["format"] = "rfc5424"
            res = _parse_5424(b, m.end() + len(v.group(1)), out)
        else:
            res = _parse_3164(rest, out)
    except Malformed:
        return {"error": "malformed-syslog"}
    keys = ["format", "facility", "severity", "timestamp", "hostname", "app_name", "procid", "msgid",
            "structured_data", "msg"]
    return {"syslog": {k: res[k] for k in keys}}


def map_syslog(raw: dict, rules: list, source: str, table: dict | None, severity_of) -> dict:
    sl = raw["syslog"]
    for r in rules:
        want = r.get("syslog")
        if not isinstance(want, dict):
            continue
        ok = all(sl.get(k) is not None and sl.get(k) == want[k] for k in ("app_name", "msgid", "hostname") if k in want)
        if ok and "facility" in want:
            ok = sl["facility"] == want["facility"]
        if ok and "msg_contains" in want:
            ok = want["msg_contains"] in sl["msg"]
        if not ok:
            continue
        if r["action"] == "notify":
            return {"notify": True}
        resource = source
        rsd = r.get("resource_sd")
        if rsd:
            el = next((x for x in sl["structured_data"] if x["id"] == rsd["id"]), None)
            p = next((x for x in el["params"] if x["name"] == rsd["param"]), None) if el else None
            if p is not None:
                resource = f"{source}/{p['value']}"
        if r["action"] == "clear":
            return {"alarm": {"resource": resource, "type": r["type"], "qualifier": "", "severity": None,
                              "cleared": True}}
        sev = r.get("severity") if r.get("severity") is not None else severity_of(sl["severity"], table)
        if sev is None:
            return {"notify": True}
        return {"alarm": {"resource": resource, "type": r["type"], "qualifier": "", "severity": sev, "cleared": False}}
    sev = severity_of(sl["severity"], table)
    if sev is None:
        return {"notify": True}
    return {"alarm": {"resource": source, "type": "syslog", "qualifier": sl["app_name"] or "", "severity": sev,
                      "cleared": False}}
