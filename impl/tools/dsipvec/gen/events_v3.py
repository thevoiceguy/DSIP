"""`device-events/` vectors for SNMPv3 (USM) and syslog (E§2–E§4; spec-gap 103).

Datagrams are built here by a small encoder so that each negative breaks exactly one rule. Each expectation is written
from what was sent: the varbinds, the user, the level, the clock. Three traps captured from pysnmp 7.1 (an
independent USM implementation) are included verbatim, and the RFC 3414 A.3 key-localization results are pinned.
"""
from __future__ import annotations

import hashlib
import hmac

from ..events_v3 import MAC_LEN, aes_cfb, password_to_key
from .events import ev, trace

NOW = 1_790_000_000
LOCAL = "80001f8880aaaaaaaaaaaaaaaa"  # the gateway's engine ID
DEV = "80001f8880bbbbbbbbbbbbbbbb"  # a device's engine ID
DEV2 = "80001f8880cccccccccccccccc"
FROM = "192.0.2.7:161"
UP, TOID = "1.3.6.1.2.1.1.3.0", "1.3.6.1.6.3.1.1.4.1.0"
LINKDOWN, IFINDEX = "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.2.1.2.2.1.1.3"
MAX31 = 2**31 - 1
AUTH_PW, PRIV_PW = "auth-pass-1", "priv-pass-2"


# --- a BER/USM encoder (test fixture only) --------------------------------------------------------

def blen(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + blen(len(body)) + body


def bint(v: int) -> bytes:
    n = 1
    while not -(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1)):
        n += 1
    return tlv(0x02, v.to_bytes(n, "big", signed=True))


def boid(oid: str) -> bytes:
    p = [int(x) for x in oid.split(".")]
    subs = [p[0] * 40 + p[1]] + p[2:]
    out = bytearray()
    for s in subs:
        chunk = [s & 0x7F]
        s >>= 7
        while s:
            chunk.append(0x80 | (s & 0x7F))
            s >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def buint(tag: int, v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return tlv(tag, b)


def varbind(oid: str, value: bytes) -> bytes:
    return tlv(0x30, boid(oid) + value)


def std_vbs(uptime=1234, trap_oid=LINKDOWN, extra=None) -> list[bytes]:
    return [varbind(UP, buint(0x43, uptime)), varbind(TOID, boid(trap_oid))] + (extra or [varbind(IFINDEX, bint(3))])


def scoped(tag=0xA7, rid=1, vbs=None, ctx_engine=b"") -> bytes:
    pdu = tlv(tag, bint(rid) + bint(0) + bint(0) + tlv(0x30, b"".join(std_vbs() if vbs is None else vbs)))
    return tlv(0x30, tlv(0x04, ctx_engine) + tlv(0x04, b"") + pdu)


def v3(engine=DEV, boots=1, time=100, user="ops", auth="sha", key=None, priv_key=None, flags=None, model=3,
       pdu=None, salt=b"\x00\x00\x00\x00\x00\x00\x00\x01", msg_id=7, max_size=65507, mac_len=None,
       priv_params=None, tamper=None, version=3, flags_bytes=None) -> str:
    """A whole SNMPv3 message, hex. `key`/`priv_key` are localized keys; `auth=None` sends noAuthNoPriv."""
    eng = bytes.fromhex(engine)
    pdu = scoped() if pdu is None else pdu
    if flags is None:
        flags = (1 if auth else 0) | (2 if priv_key else 0)
    L = MAC_LEN[auth] if auth else 0
    L = L if mac_len is None else mac_len
    pp = b""
    data = pdu
    if priv_key:
        pp = salt if priv_params is None else priv_params
        iv = boots.to_bytes(4, "big") + time.to_bytes(4, "big") + salt
        data = tlv(0x04, aes_cfb(priv_key[:16], iv, pdu, False))
    elif priv_params is not None:
        pp = priv_params
    uname = user if isinstance(user, bytes) else user.encode()
    sec = tlv(0x30, tlv(0x04, eng) + bint(boots) + bint(time) + tlv(0x04, uname) + tlv(0x04, bytes(L))
              + tlv(0x04, pp))
    fb = bytes([flags]) if flags_bytes is None else flags_bytes
    glob = tlv(0x30, bint(msg_id) + bint(max_size) + tlv(0x04, fb) + bint(model))
    msg = bytearray(tlv(0x30, bint(version) + glob + tlv(0x04, sec) + data))
    if auth and L:
        # the authParams content ends where the privParams TLV, the last thing in sec, begins
        at = bytes(msg).index(sec) + len(sec) - len(tlv(0x04, pp)) - L
        assert msg[at:at + L] == bytes(L)
        mac = hmac.new(key, bytes(msg), getattr(hashlib, {"sha": "sha1"}.get(auth, auth))).digest()[:L]
        msg[at:at + L] = mac
    if tamper:
        tamper(msg)
    return bytes(msg).hex()


def key(auth="sha", engine=DEV, pw=AUTH_PW) -> bytes:
    return password_to_key(auth, pw.encode(), bytes.fromhex(engine))


def pkey(auth="sha", engine=DEV) -> bytes:
    return key(auth, engine, PRIV_PW)[:16]


def ctx(users, local_boots=1, local_time=500):
    return {"component": "snmpv3", "now": NOW, "local": {"engine_id": LOCAL, "boots": local_boots, "time": local_time},
            "users": users}


def user(name="ops", auth="sha", priv=None, engine=None, keys=False):
    u = {"engine_id": engine, "user": name, "auth": auth}
    if keys:
        u["auth_key"] = key(auth, engine).hex()
    else:
        u["auth_password"] = AUTH_PW
    u["priv"] = priv
    if priv:
        if keys:
            u["priv_key"] = pkey(auth, engine).hex()
        else:
            u["priv_password"] = PRIV_PW
    return u


def recv(dgram: str) -> dict:
    return {"receive": {"from": FROM, "datagram": dgram}}


def acc(level="authNoPriv", user_="ops", engine=DEV, vbs=None, inform=None):
    trap = {"version": "v3", "varbinds": vbs if vbs is not None else STD_OUT}
    if inform is not None:
        trap["inform"] = {"request_id": inform}
    return {"accepted": {"trap": trap, "usm": {"engine_id": engine, "user": user_, "level": level}}}


def ref(reason, report=False):
    return {"refused": {"reason": reason, "report": report}}


def eng(engine=DEV, boots=1, time=100, latest=None):
    return {"engine_id": engine, "boots": boots, "time": time, "latest": time if latest is None else latest}


STD_OUT = [{"oid": UP, "type": "TimeTicks", "value": "1234"},
           {"oid": TOID, "type": "OBJECT IDENTIFIER", "value": LINKDOWN},
           {"oid": IFINDEX, "type": "Integer32", "value": "3"}]

# Captured from pysnmp 7.1.30 (hlapi v3arch send_notification, engine 80001f8880a1b2c3d4e5f60718): a linkDown trap with
# ifIndex.3 = 3 and ifDescr.3 = "Gi0/3", users configured by password ("authpass-123", "privpass-456").
PYSNMP = {
    "sha-aes": "3081c902010330100203327678020300ffe30401030201030440303e040d80001f8880a1b2c3d4e5f60718020103020100040f7079736e6d702d6175746870726976040cb8ca75124fe98eea0751679d04086c2e2bab3060bc540470c97151db23b30d623b598a9c95cf645bb018886486d28718c57db47f0043affd098ce7609fab0afa2283c918ba3b4104a55eace5dc47de5c45dc7cac5d7c99572b665de3b29986945ae9bbe6dbd74fa0c2e387eb4025e8ec9bb2ca202982f83c599a4312debba919a55855b2a34f4498",
    "sha256-auth": "3081c702010330100203327679020300ffe30401010201030440303e040d80001f8880a1b2c3d4e5f60718020104020100040b7079736e6d702d617574680418ca71f5abe18979720df23e2dd0deca3a8d78556183253a150400306e040d80001f8880a1b2c3d4e5f607180400a75b02036dc5c2020100020100304e300d06082b060102010103004301003017060a2b06010603010104010006092b0601060301010503300f060a2b0601020102020101030201033013060a2b06010201020201020304054769302f33",
    "md5-aes": "3081c40201033010020332767a020300ffe3040103020103043b3039040d80001f8880a1b2c3d4e5f60718020105020100040a7079736e6d702d6d6435040cfd63c6c8595bcc02092e372504086c2e2bab3060bc550470d31f4ddc1ea8005871d5ef0093b6caac2d2d7bb75e83bc6b9f0c49cc92dcf03ef525bc2078cf97991bf1294f6bc85a28a4f66c74661e7a4db5a23d3636cdece8053c0b0686529514694407551cb1800452ae33ba6c16d07b3a100d5c8a2a83a9579cb0733338260dce80c69ebdcde957",
}
PYSNMP_ENGINE = "80001f8880a1b2c3d4e5f60718"
PYSNMP_OUT = [{"oid": UP, "type": "TimeTicks", "value": "0"},
              {"oid": TOID, "type": "OBJECT IDENTIFIER", "value": LINKDOWN},
              {"oid": "1.3.6.1.2.1.2.2.1.1.3", "type": "Integer32", "value": "3"},
              {"oid": "1.3.6.1.2.1.2.2.1.2.3", "type": "OCTET STRING", "value": "Gi0/3"}]


def snmpv3_vectors() -> list[dict]:
    out = []
    R = ["E§3"]
    k = key()
    one = [user()]

    out.append(trace("snmpv3-pysnmp-traps", "Three traps from pysnmp (SHA+AES, SHA-256, MD5+AES), users by password from any engine.",
                     R, ctx([
                         {"engine_id": None, "user": "pysnmp-authpriv", "auth": "sha", "auth_password": "authpass-123",
                          "priv": "aes128", "priv_password": "privpass-456"},
                         {"engine_id": None, "user": "pysnmp-auth", "auth": "sha256", "auth_password": "authpass-123", "priv": None},
                         {"engine_id": None, "user": "pysnmp-md5", "auth": "md5", "auth_password": "authpass-123",
                          "priv": "aes128", "priv_password": "privpass-456"}]), [
                         (recv(PYSNMP["sha-aes"]), {"emit": [acc("authPriv", "pysnmp-authpriv", PYSNMP_ENGINE, PYSNMP_OUT)],
                                                    "engines": [eng(PYSNMP_ENGINE, 3, 0)]}),
                         (recv(PYSNMP["sha256-auth"]), {"emit": [acc("authNoPriv", "pysnmp-auth", PYSNMP_ENGINE, PYSNMP_OUT)],
                                                        "engines": [eng(PYSNMP_ENGINE, 4, 0)]}),
                         (recv(PYSNMP["md5-aes"]), {"emit": [acc("authPriv", "pysnmp-md5", PYSNMP_ENGINE, PYSNMP_OUT)],
                                                    "engines": [eng(PYSNMP_ENGINE, 5, 0)]}),
                     ]))

    steps = []
    for i, a in enumerate(["md5", "sha", "sha224", "sha256", "sha384", "sha512"]):
        steps.append((recv(v3(user=f"u-{a}", auth=a, key=key(a), time=100 + i)),
                      {"emit": [acc(user_=f"u-{a}")], "engines": [eng(time=100 + i)]}))
    out.append(trace("snmpv3-every-auth-protocol", "authNoPriv traps under each authentication protocol, keys localized from passwords.",
                     R, ctx([user(f"u-{a}", a) for a in ["md5", "sha", "sha224", "sha256", "sha384", "sha512"]]), steps))

    steps = []
    for i, a in enumerate(["md5", "sha", "sha256", "sha512"]):
        steps.append((recv(v3(user=f"p-{a}", auth=a, key=key(a), priv_key=pkey(a), time=100 + i)),
                      {"emit": [acc("authPriv", f"p-{a}")], "engines": [eng(time=100 + i)]}))
    out.append(trace("snmpv3-authpriv-aes128", "authPriv traps: AES-128-CFB, the privacy key localized with the auth hash and cut to 16 bytes.",
                     R, ctx([user(f"p-{a}", a, "aes128") for a in ["md5", "sha", "sha256", "sha512"]]), steps))

    out.append(trace("snmpv3-localized-keys", "A user configured with keys already localized for its engine.", R,
                     ctx([user(priv="aes128", engine=DEV, keys=True)]), [
                         (recv(v3(key=k, priv_key=pkey())), {"emit": [acc("authPriv")], "engines": [eng()]}),
                     ]))

    out.append(trace("snmpv3-key-user-other-engine", "A user given keys for one engine is unknown from another; a password user would match.",
                     R, ctx([user(engine=DEV, keys=True)]), [
                         (recv(v3(engine=DEV2, key=key(engine=DEV2))), {"emit": [ref("unknown-user")], "engines": []}),
                         (recv(v3(user="nobody", key=k)), {"emit": [ref("unknown-user")], "engines": []}),
                     ]))

    out.append(trace("snmpv3-engine-specific-before-wildcard", "An entry for the engine wins over a wildcard of the same name.",
                     R, ctx([user(auth="md5"), user(engine=DEV, keys=True)]), [
                         (recv(v3(key=k)), {"emit": [acc()], "engines": [eng()]}),
                     ]))

    def flip(at):
        def f(m):
            m[at] ^= 0x01
        return f
    good = bytes.fromhex(v3(key=k))
    out.append(trace("snmpv3-wrong-digest", "A changed byte, a wrong key, or a short authParams is wrong-digest, and leaves the cache alone.",
                     R, ctx(one), [
                         (recv(v3(key=k, tamper=flip(len(good) - 1))), {"emit": [ref("wrong-digest")], "engines": []}),
                         (recv(v3(key=key(pw="not-the-password"))), {"emit": [ref("wrong-digest")], "engines": []}),
                         (recv(v3(key=k, mac_len=11)), {"emit": [ref("wrong-digest")], "engines": []}),
                     ]))

    out.append(trace("snmpv3-security-levels", "noAuthNoPriv is refused; so is the priv flag for a user without privacy.",
                     R, ctx(one), [
                         (recv(v3(auth=None)), {"emit": [ref("unsupported-security-level")], "engines": []}),
                         (recv(v3(key=k, priv_key=pkey())), {"emit": [ref("unsupported-security-level")], "engines": []}),
                     ]))

    out.append(trace("snmpv3-other-security-model", "A security model other than USM (3) is refused.", R, ctx(one), [
        (recv(v3(key=k, model=4)), {"emit": [ref("unsupported-security-model")], "engines": []}),
    ]))

    disc = scoped(tag=0xA0, rid=99, vbs=[])
    out.append(trace("snmpv3-discovery", "An empty engine ID is unknown-engine-id, reported when the message is reportable (RFC 3414 §4).",
                     R, ctx(one), [
                         (recv(v3(engine="", user="", auth=None, flags=0x04, pdu=disc)),
                          {"emit": [ref("unknown-engine-id", True)], "engines": []}),
                         (recv(v3(engine="", user="", auth=None, flags=0x00, pdu=disc)),
                          {"emit": [ref("unknown-engine-id", False)], "engines": []}),
                     ]))

    rep = v3(key=k, time=100)
    out.append(trace("snmpv3-replayed-trap", "The same trap replayed: accepted while within 150 s of the engine's advancing clock, refused after.",
                     R, ctx(one), [
                         (recv(rep), {"emit": [acc()], "engines": [eng()]}),
                         ({"advance": 150}, {"emit": [], "engines": [eng(time=250, latest=100)]}),
                         (recv(rep), {"emit": [acc()], "engines": [eng(time=250, latest=100)]}),
                         ({"advance": 1}, {"emit": [], "engines": [eng(time=251, latest=100)]}),
                         (recv(rep), {"emit": [ref("not-in-time-window")], "engines": [eng(time=251, latest=100)]}),
                     ]))

    out.append(trace("snmpv3-trap-clock", "A newer time updates the cache; a lower boots is outside; a higher boots resets it.",
                     R, ctx(one), [
                         (recv(v3(key=k, boots=5, time=1000)), {"emit": [acc()], "engines": [eng(boots=5, time=1000)]}),
                         (recv(v3(key=k, boots=5, time=1200)), {"emit": [acc()], "engines": [eng(boots=5, time=1200)]}),
                         (recv(v3(key=k, boots=5, time=1100)), {"emit": [acc()], "engines": [eng(boots=5, time=1200)]}),
                         (recv(v3(key=k, boots=5, time=1049)), {"emit": [ref("not-in-time-window")], "engines": [eng(boots=5, time=1200)]}),
                         (recv(v3(key=k, boots=4, time=9000)), {"emit": [ref("not-in-time-window")], "engines": [eng(boots=5, time=1200)]}),
                         (recv(v3(key=k, boots=6, time=3)), {"emit": [acc()], "engines": [eng(boots=6, time=3)]}),
                     ]))

    out.append(trace("snmpv3-boots-latched", "An engine whose boots reached 2^31−1 is always outside the window.", R, ctx(one), [
        (recv(v3(key=k, boots=MAX31, time=5)), {"emit": [ref("not-in-time-window")], "engines": [eng(boots=MAX31, time=5)]}),
    ]))

    out.append(trace("snmpv3-cache-updated-before-decryption", "Timeliness runs before decryption, so a bad privParams still moves the cache.",
                     R, ctx([user(priv="aes128")]), [
                         (recv(v3(key=k, priv_key=pkey(), time=400, priv_params=b"\x00" * 7)),
                          {"emit": [ref("decryption-error")], "engines": [eng(time=400)]}),
                         (recv(v3(key=k, priv_key=pkey(), time=200)), {"emit": [ref("not-in-time-window")], "engines": [eng(time=400)]}),
                     ]))

    out.append(trace("snmpv3-decryption-error", "With the wrong privacy key the plaintext is not a ScopedPDU.", R,
                     ctx([user(priv="aes128")]), [
                         (recv(v3(key=k, priv_key=key(pw="wrong-priv")[:16])), {"emit": [ref("decryption-error")], "engines": [eng()]}),
                     ]))

    lk = key(engine=LOCAL)
    inform = scoped(tag=0xA6, rid=4242)
    out.append(trace("snmpv3-inform-authoritative", "An inform names the gateway's engine and is checked against the gateway's clock.",
                     R, ctx(one, local_boots=7, local_time=500), [
                         (recv(v3(engine=LOCAL, key=lk, boots=7, time=500, pdu=inform, flags=0x05)),
                          {"emit": [acc(engine=LOCAL, inform=4242)], "engines": []}),
                         ({"advance": 100}, {"emit": [], "engines": []}),
                         (recv(v3(engine=LOCAL, key=lk, boots=7, time=750, pdu=inform, flags=0x05)),
                          {"emit": [acc(engine=LOCAL, inform=4242)], "engines": []}),
                         (recv(v3(engine=LOCAL, key=lk, boots=7, time=751, pdu=inform, flags=0x05)),
                          {"emit": [ref("not-in-time-window", True)], "engines": []}),
                         (recv(v3(engine=LOCAL, key=lk, boots=6, time=600, pdu=inform, flags=0x05)),
                          {"emit": [ref("not-in-time-window", True)], "engines": []}),
                         (recv(v3(engine=LOCAL, key=lk, boots=7, time=449, pdu=inform, flags=0x01)),
                          {"emit": [ref("not-in-time-window", False)], "engines": []}),
                     ]))

    out.append(trace("snmpv3-inform-authpriv", "An authPriv inform, answered later at its own level.", R,
                     ctx([user(priv="aes128")]), [
                         (recv(v3(engine=LOCAL, key=lk, priv_key=pkey(engine=LOCAL), boots=1, time=500, pdu=inform)),
                          {"emit": [acc("authPriv", engine=LOCAL, inform=4242)], "engines": []}),
                     ]))

    out.append(trace("snmpv3-engine-id-mismatch", "A trap claiming the gateway's engine, or an inform naming another engine.",
                     R, ctx(one), [
                         (recv(v3(engine=LOCAL, key=lk, time=500)), {"emit": [ref("engine-id-mismatch")], "engines": []}),
                         (recv(v3(key=k, pdu=inform)), {"emit": [ref("engine-id-mismatch")], "engines": [eng()]}),
                     ]))

    out.append(trace("snmpv3-not-a-notification", "A GetRequest is authenticated and timely but not a notification.", R, ctx(one), [
        (recv(v3(key=k, pdu=scoped(tag=0xA0, vbs=[varbind(UP, tlv(0x05, b""))]))),
         {"emit": [ref("not-a-notification")], "engines": [eng()]}),
    ]))

    def append(extra):
        def f(m):
            m.extend(extra)
        return f
    mal = [
        ("trailing", v3(key=k, tamper=append(b"\x00"))),
        ("flags-two-bytes", None),
        ("priv-without-auth", v3(key=k, flags=0x02)),
        ("engine-id-4-bytes", v3(engine="80001f88", key=key(engine="80001f88"))),
        ("max-size-below-484", v3(key=k, max_size=400)),
        ("version-2", None),
        ("indefinite-length", None),
    ]
    hdr = 2 + (good[1] & 0x7F if good[1] & 0x80 else 0)
    mal[1] = ("flags-two-bytes", v3(key=k, flags_bytes=b"\x01\x00"))
    mal[5] = ("version-2", v3(key=k, version=2))
    mal[6] = ("indefinite-length", (b"\x30\x80" + good[hdr:] + b"\x00\x00").hex())
    out.append(trace("snmpv3-malformed", "Structural failures: trailing bytes, a 2-byte msgFlags, priv without auth, a 4-byte engine ID, "
                     "msgMaxSize below 484, version 2, an indefinite length.", R, ctx(one),
                     [(recv(d), {"emit": [ref("malformed")], "engines": []}) for _, d in mal]))

    vbs = [varbind(UP, buint(0x43, 7)), varbind(TOID, boid("1.3.6.1.4.1.9999.1.0.1")),
           varbind("1.3.6.1.4.1.9999.2.1", buint(0x46, 2**64 - 1)),
           varbind("1.3.6.1.4.1.9999.2.2", tlv(0x40, bytes([10, 0, 0, 1]))),
           varbind("1.3.6.1.4.1.9999.2.3", tlv(0x04, b"\x00\x01\xff")),
           varbind("1.3.6.1.4.1.9999.2.4", tlv(0x04, "café".encode())),
           varbind("1.3.6.1.4.1.9999.2.5", tlv(0x44, b"\xde\xad")),
           varbind("1.3.6.1.4.1.9999.2.6", tlv(0x05, b"")),
           varbind("1.3.6.1.4.1.9999.2.7", boid("2.999.1")),
           varbind("1.3.6.1.4.1.9999.2.8", bint(-5)),
           varbind("1.3.6.1.4.1.9999.2.9", buint(0x41, 4294967295)),
           varbind("1.3.6.1.4.1.9999.2.10", tlv(0x04, b"tab\there"))]
    want = [{"oid": UP, "type": "TimeTicks", "value": "7"},
            {"oid": TOID, "type": "OBJECT IDENTIFIER", "value": "1.3.6.1.4.1.9999.1.0.1"},
            {"oid": "1.3.6.1.4.1.9999.2.1", "type": "Counter64", "value": "18446744073709551615"},
            {"oid": "1.3.6.1.4.1.9999.2.2", "type": "IpAddress", "value": "10.0.0.1"},
            {"oid": "1.3.6.1.4.1.9999.2.3", "type": "OCTET STRING", "value": "0001ff"},
            {"oid": "1.3.6.1.4.1.9999.2.4", "type": "OCTET STRING", "value": "café"},
            {"oid": "1.3.6.1.4.1.9999.2.5", "type": "Opaque", "value": "dead"},
            {"oid": "1.3.6.1.4.1.9999.2.6", "type": "NULL", "value": ""},
            {"oid": "1.3.6.1.4.1.9999.2.7", "type": "OBJECT IDENTIFIER", "value": "2.999.1"},
            {"oid": "1.3.6.1.4.1.9999.2.8", "type": "Integer32", "value": "-5"},
            {"oid": "1.3.6.1.4.1.9999.2.9", "type": "Counter32", "value": "4294967295"},
            {"oid": "1.3.6.1.4.1.9999.2.10", "type": "OCTET STRING", "value": "7461620968657265"}]
    out.append(trace("snmpv3-value-types", "Every value type: Counter64 at its maximum, IpAddress, binary and UTF-8 strings, a control "
                     "character forcing hex, Opaque, NULL, an OID whose first subidentifier needs two bytes, a negative Integer32.",
                     R, ctx(one), [
                         (recv(v3(key=k, pdu=scoped(vbs=vbs))), {"emit": [acc(vbs=want)], "engines": [eng()]}),
                     ]))

    # pinned after the second implementation's questions (spec-gap 103)
    out.append(trace("snmpv3-username-not-utf8", "A userName that is not UTF-8 matches no user.", R, ctx(one), [
        (recv(v3(user=b"op\xff", key=k)), {"emit": [ref("unknown-user")], "engines": []}),
    ]))
    bad_vals = [("empty OID", varbind(IFINDEX, tlv(0x06, b""))),
                ("NULL with content", varbind(IFINDEX, tlv(0x05, b"\x00"))),
                ("Integer32 2^31", varbind(IFINDEX, bint(2**31))),
                ("Integer32 -2^31-1", varbind(IFINDEX, bint(-2**31 - 1))),
                ("Counter32 2^32", varbind(IFINDEX, buint(0x41, 2**32))),
                ("Gauge32 2^32", varbind(IFINDEX, buint(0x42, 2**32))),
                ("TimeTicks 2^32", varbind(IFINDEX, buint(0x43, 2**32)))]
    out.append(trace("snmpv3-value-bounds", "Malformed values: " + ", ".join(d for d, _ in bad_vals) + ".", R, ctx(one),
                     [(recv(v3(key=k, pdu=scoped(vbs=std_vbs(extra=[x])))), {"emit": [ref("malformed")], "engines": []})
                      for _, x in bad_vals]))
    edge = std_vbs(extra=[varbind("1.3.6.1.4.1.9999.3.1", bint(-2**31)), varbind("1.3.6.1.4.1.9999.3.2", bint(2**31 - 1)),
                          varbind("1.3.6.1.4.1.9999.3.3", buint(0x42, 2**32 - 1)), varbind("1.3.6.1.4.1.9999.3.4", buint(0x43, 2**32 - 1))])
    edge_out = STD_OUT[:2] + [{"oid": "1.3.6.1.4.1.9999.3.1", "type": "Integer32", "value": "-2147483648"},
                              {"oid": "1.3.6.1.4.1.9999.3.2", "type": "Integer32", "value": "2147483647"},
                              {"oid": "1.3.6.1.4.1.9999.3.3", "type": "Gauge32", "value": "4294967295"},
                              {"oid": "1.3.6.1.4.1.9999.3.4", "type": "TimeTicks", "value": "4294967295"}]
    out.append(trace("snmpv3-value-bounds-edges", "Values exactly at the 32-bit bounds are accepted.", R, ctx(one), [
        (recv(v3(key=k, pdu=scoped(vbs=edge))), {"emit": [acc(vbs=edge_out)], "engines": [eng()]}),
    ]))

    def pdu_raw(tag, body):
        return tlv(0x30, tlv(0x04, b"") + tlv(0x04, b"") + tlv(tag, body))
    vl = tlv(0x30, b"".join(std_vbs()))
    out.append(trace("snmpv3-sequence-exact", "An extra element in the PDU, or in a varbind, is malformed.", R, ctx(one), [
        (recv(v3(key=k, pdu=pdu_raw(0xA7, bint(1) + bint(0) + bint(0) + vl + bint(9)))), {"emit": [ref("malformed")], "engines": []}),
        (recv(v3(key=k, pdu=pdu_raw(0xA7, bint(1) + bint(0) + bint(0) + tlv(0x30, tlv(0x30, boid(UP) + buint(0x43, 1) + bint(5)))))),
         {"emit": [ref("malformed")], "engines": []}),
    ]))
    # BER, not DER: a padded INTEGER, a long-form length that fits the short form, a 0x80-led OID subidentifier
    padded_oid = tlv(0x06, bytes([0x2b, 6, 1, 4, 1, 0x80, 0x80, 7]))  # 1.3.6.1.4.1.7
    nonmin = [varbind(UP, buint(0x43, 1)), varbind(TOID, boid(LINKDOWN)),
              (lambda body: bytes([0x30, 0x81, len(body)]) + body)(boid("1.3.6.1.4.1.9999.4.1") + tlv(0x02, b"\x00\x00\x05")),
              tlv(0x30, padded_oid + bint(1))]
    nonmin_out = [{"oid": UP, "type": "TimeTicks", "value": "1"},
                  {"oid": TOID, "type": "OBJECT IDENTIFIER", "value": LINKDOWN},
                  {"oid": "1.3.6.1.4.1.9999.4.1", "type": "Integer32", "value": "5"},
                  {"oid": "1.3.6.1.4.1.7", "type": "Integer32", "value": "1"}]
    out.append(trace("snmpv3-ber-not-der", "Non-minimal BER is accepted: a padded INTEGER, a long-form length that fits "
                     "the short form, 0x80 bytes leading an OID subidentifier.", R, ctx(one), [
                         (recv(v3(key=k, pdu=scoped(vbs=nonmin))), {"emit": [acc(vbs=nonmin_out)], "engines": [eng()]}),
                     ]))
    out.append(trace("snmpv3-primitive-pdu-tag", "A PDU's constructed bit is not checked: a primitive tag with PDU content is "
                     "not a notification, not malformed.", R, ctx(one), [
                         (recv(v3(key=k, pdu=pdu_raw(0x87, bint(1) + bint(0) + bint(0) + vl))),
                          {"emit": [ref("not-a-notification")], "engines": [eng()]}),
                     ]))

    out.append(trace("snmpv3-unsupported-value-type", "A value tag outside the table (noSuchObject, 0x80) is malformed.", R, ctx(one), [
        (recv(v3(key=k, pdu=scoped(vbs=std_vbs(extra=[varbind(IFINDEX, tlv(0x80, b""))])))),
         {"emit": [ref("malformed")], "engines": []}),
    ]))
    return out


def usm_key_vectors() -> list[dict]:
    out = []
    eid = "000000000000000000000002"
    # RFC 3414 A.3.1 and A.3.2
    out.append(ev("usm-key-rfc3414-md5", "RFC 3414 A.3.1: \"maplesyrup\", MD5.", ["E§3"],
                  {"check": "usm-key", "auth": "md5", "password": "maplesyrup", "engine_id": eid},
                  {"auth_key": "526f5eed9fcce26f8964c2930787d82b", "priv_key": "526f5eed9fcce26f8964c2930787d82b"}))
    out.append(ev("usm-key-rfc3414-sha", "RFC 3414 A.3.2: \"maplesyrup\", SHA-1; the privacy key is its first 16 bytes.", ["E§3"],
                  {"check": "usm-key", "auth": "sha", "password": "maplesyrup", "engine_id": eid},
                  {"auth_key": "6695febc9288e36282235fc7151f128497b38f3f", "priv_key": "6695febc9288e36282235fc7151f1284"}))
    # RFC 7860 SHA-2: values from pysnmp 7.1.30 (localize_key_* with "maplesyrup", the same engine ID)
    for a, kk in ORACLE_SHA2.items():
        out.append(ev(f"usm-key-rfc7860-{a}", f"RFC 7860: \"maplesyrup\", {a.upper()} (pysnmp's value).", ["E§3"],
                      {"check": "usm-key", "auth": a, "password": "maplesyrup", "engine_id": eid},
                      {"auth_key": kk, "priv_key": kk[:32]}))
    out.append(ev("usm-key-empty-password", "An empty password cannot be expanded.", ["E§3"],
                  {"check": "usm-key", "auth": "sha", "password": "", "engine_id": eid}, {"error": "bad-password"}))
    return out


# --- SNMPv3 over TLS (E§3, v0.10): TSM messages, TLS framing, the certificate-to-name table -------------------------

def tsm(pdu=None, flags=0x03, model=4, sec=b"", msg_id=7, max_size=65507, data=None, version=3, sec_tag=0x04,
        trailing=b"") -> str:
    """A whole TSM message, hex: securityParameters empty unless given, msgData a plaintext ScopedPDU."""
    glob = tlv(0x30, bint(msg_id) + bint(max_size) + tlv(0x04, bytes([flags])) + bint(model))
    d = data if data is not None else (scoped() if pdu is None else pdu)
    return (tlv(0x30, bint(version) + glob + tlv(sec_tag, sec) + d) + trailing).hex()


ENGINE_OID = "1.3.6.1.6.3.10.2.1.1.0"
LOCAL_ENGINE = bytes.fromhex("8000000006")
# Captured from net-snmp 5.9.5.2 (Debian forky) over TLS 1.3 with a client certificate:
#   snmptrap -v 3 --defSecurityModel=tsm -l authPriv tls:… 1234 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.3 i 3
#   snmpinform … (its first message: RFC 5343 discovery, noAuthNoPriv + reportable)
NETSNMP_TRAP = ("307902010330110204013f3813020300ffe30401030201040400305f041180001f8880e61eda2ed341c56a000000000400a748"
                "02040e7219ae020100020100303a300e06082b06010201010300430204d23017060a2b06010603010104010006092b06010603"
                "01010503300f060a2b060102010202010103020103")
NETSNMP_DISCOVERY = ("3043020103301102043a39be96020300ffe304010402010404003029040580000000060400a01e02040a2c0710020100020100"
                     "3010300e060a2b060106030a020101000500")


def tsm_vectors() -> list[dict]:
    out = []

    def t(name, desc, msg, expect):
        out.append(ev(f"tsm-{name}", desc, ["E§3"], {"check": "tsm", "message": msg}, expect))
    acc_ = lambda vbs=None, inform=None: {"accepted": {"trap": {"version": "v3", "varbinds": STD_OUT if vbs is None else vbs,  # noqa: E731
                                                                 **({"inform": {"request_id": inform}} if inform is not None else {})}}}
    rf = lambda r: {"refused": {"reason": r}}  # noqa: E731
    disc = lambda vbs=None, ctx=LOCAL_ENGINE, rid=5: scoped(tag=0xA0, rid=rid, ctx_engine=ctx,  # noqa: E731
                                                            vbs=[varbind(ENGINE_OID, b"\x05\x00")] if vbs is None else vbs)
    t("trap", "A trap under TSM (authPriv flags, empty securityParameters).", tsm(), acc_())
    t("inform", "An inform under TSM carries its request-id.", tsm(scoped(tag=0xA6, rid=42)), acc_(inform=42))
    t("netsnmp-trap", "net-snmp 5.9.5.2's trap over TLS (captured).", NETSNMP_TRAP,
      acc_([{"oid": UP, "type": "TimeTicks", "value": "1234"}, {"oid": TOID, "type": "OBJECT IDENTIFIER", "value": LINKDOWN},
            {"oid": IFINDEX, "type": "Integer32", "value": "3"}]))
    t("netsnmp-discovery", "net-snmp 5.9.5.2's RFC 5343 discovery before an inform (captured; noAuthNoPriv, reportable).",
      NETSNMP_DISCOVERY, {"discovery": {"request_id": 170657552}})
    t("level-noauth", "noAuthNoPriv flags are accepted: the TLS connection provides authPriv (RFC 5591 §5.2 step 4).",
      tsm(flags=0x00), acc_())
    t("level-authnopriv-reportable", "authNoPriv with reportable is accepted.", tsm(flags=0x05), acc_())
    t("security-parameters-ignored", "securityParameters' content is not read.", tsm(sec=b"\x30\x03\x02\x01\x01junk"), acc_())
    t("priv-without-auth", "Priv without auth is malformed, as for USM.", tsm(flags=0x02), rf("malformed"))
    t("encrypted-pdu-malformed", "msgData as an OCTET STRING is malformed: TSM never encrypts in the message.",
      tsm(data=tlv(0x04, b"\x01\x02\x03")), rf("malformed"))
    t("security-parameters-not-octet-string", "securityParameters must be an OCTET STRING.", tsm(sec_tag=0x30), rf("malformed"))
    t("trailing-bytes", "Nothing may follow the message.", tsm(trailing=b"\x00"), rf("malformed"))
    t("version-v2c", "msgVersion 1 is malformed here.", tsm(version=1), rf("malformed"))
    t("msg-max-size-small", "msgMaxSize below 484 is malformed.", tsm(max_size=483), rf("malformed"))
    t("usm-over-tls", "USM (model 3) over TLS is refused.", tsm(model=3), rf("unsupported-security-model"))
    t("model-zero", "Model 0 is refused.", tsm(model=0), rf("unsupported-security-model"))
    t("model-before-pdu", "The model is checked before the PDU.", tsm(scoped(tag=0xA2), model=3), rf("unsupported-security-model"))
    t("response-pdu", "A Response-PDU is not a notification.", tsm(scoped(tag=0xA2)), rf("not-a-notification"))
    t("get-not-discovery", "A GetRequest with an empty contextEngineID is not discovery.", tsm(disc(ctx=b"")), rf("not-a-notification"))
    t("discovery", "RFC 5343 discovery: GetRequest, contextEngineID 8000000006, only snmpEngineID.0.", tsm(disc()),
      {"discovery": {"request_id": 5}})
    t("discovery-any-value", "Discovery's varbind value may be any valid value.",
      tsm(disc(vbs=[varbind(ENGINE_OID, bint(0))])), {"discovery": {"request_id": 5}})
    t("discovery-two-varbinds", "Discovery has exactly one varbind.",
      tsm(disc(vbs=[varbind(ENGINE_OID, b"\x05\x00"), varbind(UP, b"\x05\x00")])), rf("not-a-notification"))
    t("discovery-other-oid", "Discovery asks for snmpEngineID.0 only.", tsm(disc(vbs=[varbind(UP, b"\x05\x00")])),
      rf("not-a-notification"))
    t("discovery-other-context", "Discovery names RFC 5343's localEngineID, not a real engine.",
      tsm(disc(ctx=bytes.fromhex(DEV))), rf("not-a-notification"))
    t("discovery-getnext", "A GetNextRequest is not discovery.", tsm(scoped(tag=0xA1, ctx_engine=LOCAL_ENGINE,
                                                                              vbs=[varbind(ENGINE_OID, b"\x05\x00")])),
      rf("not-a-notification"))
    t("discovery-usm-model", "Discovery under USM over TLS is refused by the model check first.", tsm(disc(), model=3),
      rf("unsupported-security-model"))
    return out


def tls_frames_vectors() -> list[dict]:
    out = []
    a, b = tsm(), tsm(scoped(tag=0xA6, rid=9))

    def f(name, desc, stream, msgs, pending, close=False):
        e = {"messages": msgs, "pending": pending}
        if close:
            e["close"] = True
        out.append(ev(f"tls-frames-{name}", desc, ["E§3"], {"check": "tls-frames", "stream": stream}, e))
    f("two", "Two whole messages.", a + b, [a, b], "")
    f("one-and-a-half", "A partial message waits.", a + b[:20], [a], b[:20])
    f("empty", "An empty stream.", "", [], "")
    f("one-byte", "A single byte waits.", "30", [], "30")
    f("one-stray-byte", "A single byte waits even when it is not 0x30: step 1 comes first.", a + "ff", [a], "ff")
    f("long-length-incomplete", "A long-form length whose bytes have not all arrived waits.", "3082ff", [], "3082ff")
    f("not-a-sequence", "A first byte other than 0x30 closes.", "0401aa" + a, [], "0401aa" + a, True)
    f("indefinite", "The indefinite length closes.", "308002010300", [], "308002010300", True)
    f("five-length-bytes", "A long form with 5 length bytes closes.", "30850000000003020101", [], "30850000000003020101", True)
    f("garbage-after", "A message, then something unframeable: the message is taken, then close.", a + "ff00", [a], "ff00", True)
    f("at-limit-waits", "A header announcing exactly 65,536 bytes in all waits for them.", "3082fffc", [], "3082fffc")
    f("over-limit", "A header announcing 65,537 bytes in all closes.", "3082fffd", [], "3082fffd", True)
    f("non-minimal-length", "A long-form length that fits the short form is accepted (BER).", "3081" + "03020101",
      ["308103020101"], "")
    f("four-length-bytes", "A long form with 4 length bytes.", "308400000003020101" + "30", ["308400000003020101"], "30")
    return out


def tsm_name_vectors() -> list[dict]:
    out = []
    LEAF, CA, OTHER = "ab" * 32, "cd" * 32, "ef" * 32
    base = {"sha256": LEAF, "chain": [CA], "san": [{"type": "dns", "value": "SW1.Example.NET"}, {"type": "ip", "value": "c0000207"}],
            "cn": ["sw1"]}

    def n(name, desc, table, expect, cert=None):
        out.append(ev(f"tsm-name-{name}", desc, ["E§3"], {"check": "tsm-name", "certificate": cert or base, "table": table},
                      expect))
    ok = lambda s, row: {"security_name": s, "row": row}  # noqa: E731
    none = {"error": "no-security-name"}
    row = lambda i, fp, m, data=None: {"id": i, "fingerprint": fp, "map": m, **({"data": data} if data is not None else {})}  # noqa: E731
    cert = lambda **kw: {**base, **kw}  # noqa: E731
    n("specified", "The leaf's fingerprint, map specified.", [row(10, LEAF, "specified", "sw1-core")], ok("sw1-core", 10))
    n("ca-san-dns", "A CA in the verified path matches; the first dNSName, lowercased.", [row(10, CA, "san-dns")],
      ok("sw1.example.net", 10))
    n("ascending-id", "Rows are considered in ascending id, whatever their order.",
      [row(20, LEAF, "specified", "b"), row(10, LEAF, "specified", "a")], ok("a", 10))
    n("fingerprint-case", "Fingerprints compare without case.", [row(1, LEAF.upper(), "specified", "x")], ok("x", 1))
    n("no-match", "No row's fingerprint matches.", [row(1, OTHER, "specified", "x")], none)
    n("empty-table", "An empty table maps nothing.", [], none)
    n("unmatched-row-skipped", "A row for another certificate is passed over.",
      [row(1, OTHER, "specified", "x"), row(2, CA, "specified", "y")], ok("y", 2))
    n("specified-no-data-next", "specified without data fails; the next row is tried.",
      [row(1, LEAF, "specified"), row(2, LEAF, "san-dns")], ok("sw1.example.net", 2))
    n("specified-empty-next", "An empty name fails the row.", [row(1, LEAF, "specified", ""), row(2, LEAF, "specified", "z")], ok("z", 2))
    n("specified-not-string", "Non-string data fails the row.",
      [{"id": 1, "fingerprint": LEAF, "map": "specified", "data": 7}, row(2, LEAF, "specified", "z")], ok("z", 2))
    n("exactly-32", "32 bytes is allowed.", [row(1, LEAF, "specified", "n" * 32)], ok("n" * 32, 1))
    n("too-long-next", "33 bytes fails the row.", [row(1, LEAF, "specified", "n" * 33), row(2, LEAF, "specified", "s")], ok("s", 2))
    n("utf8-bytes-counted", "The limit counts UTF-8 bytes: 16 × é is 32 bytes, 17 × é is 34.",
      [row(1, LEAF, "specified", "é" * 17), row(2, LEAF, "specified", "é" * 16)], ok("é" * 16, 2))
    n("san-rfc822", "RFC 6353's example: the host part lowercased, the local part kept.",
      [row(1, LEAF, "san-rfc822")], ok("FooBar@example.com", 1), cert(san=[{"type": "rfc822", "value": "FooBar@Example.COM"}]))
    n("san-rfc822-last-at", "The host part is after the last @.", [row(1, LEAF, "san-rfc822")], ok("A@B@ex.com", 1),
      cert(san=[{"type": "rfc822", "value": "A@B@EX.com"}]))
    n("san-rfc822-no-at", "An rfc822Name without @ fails.", [row(1, LEAF, "san-rfc822")], none,
      cert(san=[{"type": "rfc822", "value": "nobody"}]))
    n("san-rfc822-absent-next", "No rfc822Name: the row fails, the next is tried.",
      [row(1, LEAF, "san-rfc822"), row(2, LEAF, "common-name")], ok("sw1", 2))
    n("san-dns-ascii-only", "Only A–Z are lowercased.", [row(1, LEAF, "san-dns")], ok("sw1.Éxample", 1),
      cert(san=[{"type": "dns", "value": "SW1.ÉXAMPLE"}]))
    n("san-dns-first", "The first dNSName is used.", [row(1, LEAF, "san-dns")], ok("a.example", 1),
      cert(san=[{"type": "dns", "value": "A.example"}, {"type": "dns", "value": "b.example"}]))
    n("san-dns-first-only", "Only the first dNSName is tried: when it is too long, the row fails.", [row(1, LEAF, "san-dns")],
      none, cert(san=[{"type": "dns", "value": "x" * 33}, {"type": "dns", "value": "ok.example"}]))
    n("san-ip-v4", "An IPv4 address is a dotted quad.", [row(1, LEAF, "san-ip")], ok("192.0.2.7", 1))
    n("san-ip-v4-no-leading-zeros", "No leading zeros.", [row(1, LEAF, "san-ip")], ok("10.0.0.1", 1),
      cert(san=[{"type": "ip", "value": "0a000001"}]))
    n("san-ip-v6", "An IPv6 address is 32 lowercase hex digits.", [row(1, LEAF, "san-ip")],
      ok("20010db8000000000000000000000001", 1), cert(san=[{"type": "ip", "value": "20010DB8000000000000000000000001"}]))
    n("san-ip-bad-length", "An address of another length fails.", [row(1, LEAF, "san-ip")], none,
      cert(san=[{"type": "ip", "value": "c000020700"}]))
    n("san-any-skips-other-types", "san-any takes the first SAN of the three types.", [row(1, LEAF, "san-any")],
      ok("192.0.2.7", 1), cert(san=[{"type": "uri", "value": "https://x.example"}, {"type": "ip", "value": "c0000207"},
                                    {"type": "dns", "value": "sw1.example"}]))
    n("san-any-rfc822", "san-any maps an rfc822Name as san-rfc822 does.", [row(1, LEAF, "san-any")], ok("Ops@noc.example", 1),
      cert(san=[{"type": "rfc822", "value": "Ops@NOC.example"}]))
    n("san-any-first-only", "san-any does not fall through to a later SAN when the first fails.",
      [row(1, LEAF, "san-any")], none, cert(san=[{"type": "dns", "value": "x" * 33}, {"type": "dns", "value": "ok.example"}]))
    n("san-any-none", "No SAN of the three types: the row fails.", [row(1, LEAF, "san-any")], none,
      cert(san=[{"type": "uri", "value": "https://x.example"}]))
    n("common-name", "The first CommonName.", [row(1, LEAF, "common-name")], ok("sw1", 1), cert(cn=["sw1", "second"]))
    n("common-name-absent", "No CommonName: the row fails.", [row(1, LEAF, "common-name")], none, cert(cn=[]))
    n("unknown-map-next", "An unknown map fails the row.", [row(1, LEAF, "san-uri"), row(2, LEAF, "specified", "k")], ok("k", 2))
    n("ca-not-in-path", "A fingerprint of a CA outside the verified path does not match.",
      [row(1, CA, "specified", "x")], none, cert(chain=[]))
    return out


# pysnmp 7.1.30: localkey.localize_key(localkey.hash_passphrase("maplesyrup", H), 000000000000000000000002, H)
ORACLE_SHA2 = {
    "sha224": "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674",
    "sha256": "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b",
    "sha384": "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6f0455a53689a3937eea07319a633d2ccba78",
    "sha512": "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b",
}


# --- syslog -------------------------------------------------------------------------------------

def sl(fmt="rfc5424", fac=1, sev=5, ts=None, host=None, app=None, pid=None, mid=None, sd=None, msg=""):
    return {"syslog": {"format": fmt, "facility": fac, "severity": sev, "timestamp": ts, "hostname": host,
                       "app_name": app, "procid": pid, "msgid": mid, "structured_data": sd or [], "msg": msg}}


MAL = {"error": "malformed-syslog"}


def syslog_vectors() -> list[dict]:
    out = []
    R = ["E§3"]

    def chk(vid, desc, data: bytes, want):
        out.append(ev(f"syslog-{vid}", desc, R, {"check": "syslog", "datagram": data.hex()}, want))

    # RFC 5424 §6.5's examples
    chk("rfc5424-example-1", "RFC 5424 §6.5 example 1: a BOM before the message, NILVALUE structured data.",
        b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \xef\xbb\xbf'su root' failed for lonvick on /dev/pts/8",
        sl(fac=4, sev=2, ts="2003-10-11T22:14:15.003Z", host="mymachine.example.com", app="su", mid="ID47",
           msg="'su root' failed for lonvick on /dev/pts/8"))
    chk("rfc5424-example-3", "RFC 5424 §6.5 example 3: one structured-data element with three parameters.",
        b'<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" '
        b'eventSource="Application" eventID="1011"] An application event log entry...',
        sl(fac=20, sev=5, ts="2003-10-11T22:14:15.003Z", host="mymachine.example.com", app="evntslog", mid="ID47",
           sd=[{"id": "exampleSDID@32473", "params": [{"name": "iut", "value": "3"},
                                                       {"name": "eventSource", "value": "Application"},
                                                       {"name": "eventID", "value": "1011"}]}],
           msg="An application event log entry..."))
    chk("rfc5424-example-4", "RFC 5424 §6.5 example 4: two elements, no message.",
        b'<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" '
        b'eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]',
        sl(fac=20, sev=5, ts="2003-10-11T22:14:15.003Z", host="mymachine.example.com", app="evntslog", mid="ID47",
           sd=[{"id": "exampleSDID@32473", "params": [{"name": "iut", "value": "3"},
                                                       {"name": "eventSource", "value": "Application"},
                                                       {"name": "eventID", "value": "1011"}]},
               {"id": "examplePriority@32473", "params": [{"name": "class", "value": "high"}]}]))
    chk("rfc5424-all-nil", "Every header field NILVALUE, no message.", b"<14>1 - - - - - -", sl(fac=1, sev=6))
    chk("rfc5424-escapes", "Parameter escapes: \\\", \\\\ and \\] are unescaped; any other backslash is kept.",
        b'<14>1 - h a - - [x@1 v="q\\"b\\\\s\\]e\\n"]',
        sl(fac=1, sev=6, host="h", app="a", sd=[{"id": "x@1", "params": [{"name": "v", "value": 'q"b\\s]e\\n'}]}]))
    chk("rfc5424-sd-no-params", "An element with no parameters.", b"<14>1 - - - - - [x@1] m",
        sl(fac=1, sev=6, sd=[{"id": "x@1", "params": []}], msg="m"))
    chk("rfc5424-trailing-newlines", "Trailing CR and LF are removed from the message, not inner ones.",
        b"<14>1 - - - - - - line one\nline two\r\n\n", sl(fac=1, sev=6, msg="line one\nline two"))
    chk("rfc5424-invalid-utf8", "Invalid UTF-8 in the message: each maximal invalid subpart becomes U+FFFD.",
        b"<14>1 - - - - - - a\xffb\xe2\x82c\xf0\x9f\x98\x80", sl(fac=1, sev=6, msg="a\ufffdb\ufffdc\U0001F600"))
    chk("rfc5424-pri-zero", "<0> is kernel emergency.", b"<0>1 - - - - - -", sl(fac=0, sev=0))
    chk("rfc5424-pri-191", "<191> is local7 debug, the largest value.", b"<191>1 - - - - - -", sl(fac=23, sev=7))
    chk("rfc5424-app-name-48", "APP-NAME at its 48-byte limit.", b"<14>1 - - " + b"a" * 48 + b" - - -",
        sl(fac=1, sev=6, app="a" * 48))
    for vid, desc, data in [
        ("pri-192", "PRI above 191.", b"<192>1 - - - - - -"),
        ("pri-leading-zero", "PRI with a leading zero.", b"<013>1 - - - - - -"),
        ("pri-double-zero", "<00>: the value 0 is written as the single digit 0.", b"<00>1 - - - - - -"),
        ("no-pri", "No PRI at all.", b"Oct 11 22:14:15 host msg"),
        ("pri-unclosed", "PRI without its >.", b"<14 hello"),
        ("version-2", "RFC 5424 version 2 is not version 1.", b"<14>2 - - - - - -"),
        ("app-name-49", "APP-NAME over 48 bytes.", b"<14>1 - - " + b"a" * 49 + b" - - -"),
        ("double-space", "Two spaces between header fields.", b"<14>1 -  - - - - -"),
        ("missing-sd", "The header ends before the structured data.", b"<14>1 - - - - -"),
        ("sd-unclosed", "An element without its ].", b'<14>1 - - - - - [x@1 a="b"'),
        ("sd-garbage-after", "Bytes right after the structured data with no space.", b"<14>1 - - - - - [x@1]m"),
        ("sd-value-unterminated", "A parameter value without its closing quote.", b'<14>1 - - - - - [x@1 a="b]'),
        ("header-control-byte", "A control byte inside a header token.", b"<14>1 - h\x01 - - - -"),
    ]:
        chk(f"malformed-{vid}", desc, data, MAL)

    # RFC 3164
    chk("rfc3164-example", "RFC 3164 §5.4's first example: timestamp, hostname, tag.",
        b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        sl("rfc3164", 4, 2, "Oct 11 22:14:15", "mymachine", "su", msg="'su root' failed for lonvick on /dev/pts/8"))
    chk("rfc3164-pid", "A tag with a process id, a space-padded day, a trailing CR LF.",
        b"<13>Oct  5 12:00:00 host sshd[1234]: hello\r\n",
        sl("rfc3164", 1, 5, "Oct  5 12:00:00", "host", "sshd", "1234", msg="hello"))
    chk("rfc3164-cisco-sequence", "Cisco's sequence-number prefix has no valid timestamp, and its number reads as a tag.",
        b"<189>123: *Mar  1 18:46:11: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n",
        sl("rfc3164", 23, 5, app="123", msg="*Mar  1 18:46:11: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down"))
    chk("rfc3164-no-hostname-token", "After the timestamp, a token followed by a space is taken as the hostname, as RFC 3164 does.",
        b"<13>Oct  5 12:00:00 sshd[1]: hi",
        sl("rfc3164", 1, 5, "Oct  5 12:00:00", "sshd[1]:", msg="hi"))
    chk("rfc3164-timestamp-only", "A timestamp then a lone token: no hostname, the token is the content.",
        b"<13>Oct  5 12:00:00 lonely", sl("rfc3164", 1, 5, "Oct  5 12:00:00", msg="lonely"))
    chk("rfc3164-day-zero-padded", "\"Oct 05\" is not an RFC 3164 timestamp, so all of it is the message.",
        b"<13>Oct 05 12:00:00 host x", sl("rfc3164", 1, 5, msg="Oct 05 12:00:00 host x"))
    chk("rfc3164-hour-24", "Hour 24 is not a timestamp.", b"<13>Oct  5 24:00:00 host x",
        sl("rfc3164", 1, 5, msg="Oct  5 24:00:00 host x"))
    chk("rfc3164-tag-33", "A 33-byte tag is not a tag.", b"<13>" + b"t" * 33 + b": x",
        sl("rfc3164", 1, 5, msg="t" * 33 + ": x"))
    chk("rfc3164-tag-32", "A 32-byte tag is a tag.", b"<13>" + b"t" * 32 + b": x",
        sl("rfc3164", 1, 5, app="t" * 32, msg="x"))
    chk("rfc3164-no-colon", "Without a colon there is no tag.", b"<13>kernel panic", sl("rfc3164", 1, 5, msg="kernel panic"))
    chk("rfc3164-empty", "Only a PRI: an empty RFC 3164 message.", b"<13>", sl("rfc3164", 1, 5))
    chk("rfc3164-pid-not-digits", "A bracket that is not [digits]: is not a tag.", b"<13>app[x]: m",
        sl("rfc3164", 1, 5, msg="app[x]: m"))

    # E§4: syslog → alarm
    def mp(vid, desc, raw, rules, want, table=None):
        i = {"check": "map", "raw": raw, "rules": rules, "source": "192.0.2.9"}
        if table is not None:
            i["syslog_table"] = table
        out.append(ev(f"map-syslog-{vid}", desc, ["E§4", "E§3"], i, want))

    def al(res, typ, sev, q="", cleared=False):
        return {"alarm": {"resource": res, "type": typ, "qualifier": q, "severity": sev, "cleared": cleared}}
    link = sl("rfc5424", 23, 3, app="linkd", mid="LINKDOWN", host="sw1",
              sd=[{"id": "if@32473", "params": [{"name": "ifIndex", "value": "3"}]}], msg="port 3 down")
    up = sl("rfc5424", 23, 5, app="linkd", mid="LINKUP", host="sw1",
            sd=[{"id": "if@32473", "params": [{"name": "ifIndex", "value": "3"}]}], msg="port 3 up")
    rules = [{"syslog": {"app_name": "linkd", "msgid": "LINKDOWN"}, "action": "raise", "type": "link-down",
              "resource_sd": {"id": "if@32473", "param": "ifIndex"}},
             {"syslog": {"app_name": "linkd", "msgid": "LINKUP"}, "action": "clear", "type": "link-down",
              "resource_sd": {"id": "if@32473", "param": "ifIndex"}}]
    mp("raise-table-severity", "A raise rule without severity takes the table's (3 → major); the resource from structured data.",
       link, rules, al("192.0.2.9/3", "link-down", "major"))
    mp("clear", "A clear rule clears the same alarm.", up, rules, al("192.0.2.9/3", "link-down", None, cleared=True))
    mp("rule-severity", "A rule's own severity overrides the table.", link,
       [dict(rules[0], severity="critical")], al("192.0.2.9/3", "link-down", "critical"))
    mp("raise-but-table-none", "A raise rule without severity on a notice (5): the table gives none, so no alarm.",
       sl(sev=5, app="linkd", mid="LINKDOWN"), rules[:1], {"notify": True})
    mp("resource-sd-first-element", "Two elements share the id: only the first is searched, and it lacks the parameter.",
       sl(sev=3, app="linkd", mid="LINKDOWN", sd=[{"id": "if@32473", "params": [{"name": "other", "value": "1"}]},
                                                   {"id": "if@32473", "params": [{"name": "ifIndex", "value": "7"}]}]),
       rules[:1], al("192.0.2.9", "link-down", "major"))
    mp("resource-sd-missing", "resource_sd names no parameter present: the resource is the source.",
       sl(sev=3, app="linkd", mid="LINKDOWN"), rules[:1], al("192.0.2.9", "link-down", "major"))
    mp("unmatched-warning", "No rule: a warning (4) raises (source, syslog, app_name) at warning.",
       sl(sev=4, app="sshd", msg="x"), rules, al("192.0.2.9", "syslog", "warning", "sshd"))
    mp("unmatched-no-app", "No rule and no app_name: the qualifier is empty.",
       sl("rfc3164", sev=2, msg="x"), rules, al("192.0.2.9", "syslog", "critical"))
    mp("unmatched-info", "No rule: informational (6) is an event, not an alarm.", sl(sev=6, app="sshd"), rules, {"notify": True})
    mp("table-override", "The gateway's table turns notices (5) into minor alarms.",
       sl(sev=5, app="ntpd"), [], al("192.0.2.9", "syslog", "minor", "ntpd"), table={"5": "minor"})
    mp("msg-contains-and-facility", "msg_contains and facility both must match.",
       sl(fac=4, sev=2, app="su", msg="'su root' failed"),
       [{"syslog": {"facility": 4, "msg_contains": "failed"}, "action": "raise", "type": "auth-failure", "severity": "minor"}],
       al("192.0.2.9", "auth-failure", "minor"))
    mp("hostname-null-never-matches", "A rule's hostname never matches a null hostname; the table decides.",
       sl(sev=3, app="x"), [{"syslog": {"hostname": "sw1"}, "action": "notify", "type": "t"}],
       al("192.0.2.9", "syslog", "major", "x"))
    mp("trap-rule-ignored", "A trap rule never matches syslog.",
       sl(sev=3, app="x"), [{"trap_oid": "1.3.6.1.6.3.1.1.5.3", "action": "notify", "type": "t"}],
       al("192.0.2.9", "syslog", "major", "x"))
    mp("notify-rule", "A notify rule makes even an error (3) an event.",
       sl(sev=3, app="x"), [{"syslog": {"app_name": "x"}, "action": "notify", "type": "t"}], {"notify": True})
    out.append(ev("map-trap-ignores-syslog-rule", "A syslog rule never matches a trap.", ["E§4"],
                  {"check": "map", "source": "192.0.2.9", "rules": [{"syslog": {}, "action": "raise", "type": "t", "severity": "major"}],
                   "raw": {"snmp": {"version": "v2c", "uptime": 1, "trap_oid": "1.3.6.1.6.3.1.1.5.3", "varbinds": []}}},
                  {"notify": True}))
    return out
