"""Signed syslog (RFC 5848) traces: a gateway's collector (E§3, v0.10; README component `syslog-sign`).

The signer here is a test fixture: DSA with a deterministic nonce, so the vectors regenerate byte for byte. Its
output is checked by hand-written expectations, and the interop anchor is RFC 5848's own two examples, carried
verbatim (a Certificate Block with a `K` key and a Signature Block, both from the RFC's signer), which must verify.
"""
from __future__ import annotations

import base64
import hashlib

from .events import trace

# RFC 5848 §5.3.2.9 and §4.2.9, joined as the RFC says (Certificate Block: no space where FRAG/SIGN lines break).
RFC_CERT = (b'<110>1 2009-05-03T14:00:39.519307+02:00 host.example.org syslogd 2138 - [ssign-cert VER="0111" RSID="1" '
            b'SG="0" SPRI="0" TPBL="587" INDEX="1" FLEN="587" FRAG="2009-05-03T14:00:39.519005+02:00 K BACsLMZ'
            b'NCV2NUAwe4RAeAnSQuvv2KS51SnHFAaWJNU2XVDYvW1LjmJgg4vKvQPo3HEOD+2hEkt1z'
            b'cXADe03u5pmHoWy5FGiyCbglYxJkUJJrQqlTSS6vID9yhsmEnh07w3pOsxmb4qYo0uWQr'
            b'AAenBweVMlBgV3ZA5IMA8xq8l+i8wCgkWJjCjfLar7s+0X3HVrRroyARv8EAIYoxofh9m'
            b'N8n821BTTuQnz5hp40d6Z3UudKePu2di5Mx3GFelwnV0Qh5mSs0YkuHJg0mcXyUAoeYry'
            b'5X6482fUxbm+gOHVmYSDtBmZEB8PTEt8Os8aedWgKEt/E4dT+Hmod4omECLteLXxtScTM'
            b'gDXyC+bSBMjRRCaeWhHrYYdYBACCWMdTc12hRLJTn8LX99kv1I7qwgieyna8GCJv/rEgC'
            b'ssS9E1qARM+h19KovIUOhl4VzBw3rK7v8Dlw/CJyYDd5kwSvCwjhO21LiReeS90VPYuZF'
            b'RC1B82Sub152zOqIcAWsgd4myCCiZbWBsuJ8P0gtarFIpleNacCc6OV3i2Rg==" '
            b'SIGN="AKAQEUiQptgpd0lKcXbuggGXH/dCdQCgdysrTBLUlbeGAQ4vwrnLOqSL7+c="]')
RFC_SIG = (b'<110>1 2009-05-03T14:00:39.529966+02:00 host.example.org syslogd 2138 - [ssign VER="0111" RSID="1" SG="0" '
           b'SPRI="0" GBC="2" FMN="1" CNT="7" HB="K6wzcombEvKJ+UTMcn9bPryAeaU= zrkDcIeaDluypaPCY8WWzwHpPok= '
           b'zgrWOdpx16ADc7UmckyIFY53icE= XfopJ+S8/hODapiBBCgVQaLqBKg= J67gKMFl/OauTC20ibbydwIlJC8= '
           b'M5GziVgB6KPY3ERU1HXdSi2vtdw= Wxd/lU7uG/ipEYT9xeqnsfohyH0=" '
           b'SIGN="AKBbX4J7QkrwuwdbV7Taujk2lvOf8gCgC62We1QYfnrNHz7FzAvdySuMyfM="]')
RFC_K = RFC_CERT.split(b'FRAG="')[1].split(b'"')[0].split(b" ")[2].decode()

# A DSA-2048/224 certificate made once with openssl (CN=sw9.example), and its private x.
CERT_DER_B64 = 'MIIEVjCCBASgAwIBAgIBBzALBglghkgBZQMEAwIwFjEUMBIGA1UEAwwLc3c5LmV4YW1wbGUwIBcNMjYxMDA2MTk1MDI3WhgPMjEyNjA5MTIxOTUwMjdaMBYxFDASBgNVBAMMC3N3OS5leGFtcGxlMIIDRDCCAjYGByqGSM44BAEwggIpAoIBAQDpO8SzvGc+KDVjYkQFcPdFRLflMMMT+pvJmA5n7T1imk79F2peboEmNl64XGr7r0lidxfdX59xm9JptdmNKhc9PQ9eeHdNey4i7SCmrcTIED3ULGV42/5Y06CSQt+O5YcbanfK+99+PN5ZNOmR7G0FtAx7rdpcye5NW5bhxXu3OkF3HbiB46BD9hrC2II8I0jEnd+zKvI698SHGKd8RzAz1mLzQaXu/Y5ALWiWdfiotzPfT8f1aCAmlexwOrbOok7RMujNOsr6f1xfeqUY0bc0H0Qu9PwafAQ89iJjgvQOcZL4UMjt11Mz0pNK+GIEULIk4c/jtjdufDeBX1CLEVsFAh0AotJ9UCdq/d1W2JnWSTOg3oOqBq4yiOdUTOuEGQKCAQEApz06qJ4wOeIt+XJrEKCTOinBDEnRlXo7fXJeDx0IX3e3+lAqt/3YuwWzOTHN4SZkz4QAT/BsamXTuSI+gY2EIj0oYJAvkHn5jpeApFq6Q48dkKNqQx4Ks865X0+KQY+p7114kvVVwDn2MYUFlSx7fLxXurBN4SFQAMWd72tNTPzlYgm+Ez5xgoPuPatb8TYDvVsvb4iie0GAhVMBQuVt0f9e+8y73PSTclgiJvc5MLLsul2tsuU4btYbtLsRuNdTM5jcf3Wr49oRgch3sXDwcKV1V0BDPmj4EnbDfry2e48o14IVvD/+nynxoz633XskbVacwsMzJNfrZ/CR9/APUAOCAQYAAoIBAQDJFYtsTsve00670i8YfAFPav8kifO12aQTez7OS/uzhbVhhcocCCI7G1iAkC+9ZBbgci86FP5b5yELUH3RtiYzJjmNPsLE6cPZzOrcLp66QNTVL6/PkaGLU1hreGi3kgOsdtrM/XzM6/B2/rPoBZ4TDGwIf1q7TZsav5hWQUni3CycAEU3w95vqE7qb5PgC1falO2qbcs4iTQqgI84P2OMsJ6p20UVk4jUmfWk31gSC2Eraw46f23LqwNNfAHBlelw73Rti7LCAWAFPQXPbtTvTqFm+Ek+NxoCQjr6S+U2MJtCgHMK8QCIwiRzcaI4clfgq3Ea6M/z1ctlW0XB2Ozno1MwUTAdBgNVHQ4EFgQUktYyal6fEkyCe9xviPW3Yjg7CkQwHwYDVR0jBBgwFoAUktYyal6fEkyCe9xviPW3Yjg7CkQwDwYDVR0TAQH/BAUwAwEB/zALBglghkgBZQMEAwIDPwAwPAIcFk1tA3280P74APwst69burp5VcewnQ+NegC0IgIcPVTlskE91NcEqKBFHbL80jUccfpZx2LobtPq2Q=='
CERT_X = 0x4b5c2a476b9a961d4aeea8822af07e95a85d26c423cdf6ddde710fe6


def mpi(v: int, bits: int | None = None) -> bytes:
    bits = v.bit_length() if bits is None else bits
    return bits.to_bytes(2, "big") + v.to_bytes((bits + 7) // 8, "big")


def mpis(b: bytes) -> list[int]:
    out, i = [], 0
    while i < len(b):
        n = (int.from_bytes(b[i:i + 2], "big") + 7) // 8
        out.append(int.from_bytes(b[i + 2:i + 2 + n], "big"))
        i += 2 + n
    return out


P_RFC, Q_RFC, G_RFC, _ = mpis(base64.b64decode(RFC_K))


class Key:
    """A fixture signer: DSA with a deterministic nonce (test fixture only)."""

    def __init__(self, p, q, g, x, kind, blob: bytes):
        self.p, self.q, self.g, self.x, self.kind, self.blob = p, q, g, x, kind, blob

    @classmethod
    def raw(cls, label: str):
        x = int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % (Q_RFC - 1) + 1
        y = pow(G_RFC, x, P_RFC)
        return cls(P_RFC, Q_RFC, G_RFC, x, "K", mpi(P_RFC) + mpi(Q_RFC) + mpi(G_RFC) + mpi(y))

    @classmethod
    def cert(cls):
        from cryptography.x509 import load_der_x509_certificate
        der = base64.b64decode(CERT_DER_B64)
        n = load_der_x509_certificate(der).public_key().public_numbers().parameter_numbers
        return cls(n.p, n.q, n.g, CERT_X, "C", der)

    def signer(self, hostname: str) -> dict:
        return {"hostname": hostname, "type": self.kind, "key": base64.b64encode(self.blob).decode()}

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.blob).hexdigest()

    def sign(self, data: bytes, alg: str, r_bits=None, r_override=None) -> str:
        h = hashlib.new(alg, data).digest()
        qb = self.q.bit_length()
        z = int.from_bytes(h, "big") >> max(0, len(h) * 8 - qb)
        k = int.from_bytes(hashlib.sha256(b"k" + self.x.to_bytes(32, "big") + data).digest(), "big") % (self.q - 1) + 1
        r = pow(self.g, k, self.p) % self.q
        s = pow(k, -1, self.q) * (z + self.x * r) % self.q
        if r_override is not None:
            r = r_override
        return base64.b64encode(mpi(r, r_bits) + mpi(s)).decode()


K1, K2, KC = Key.raw("dsip syslog-sign K1"), Key.raw("dsip syslog-sign K2"), Key.cert()
ALG = {"0111": "sha1", "0121": "sha256"}


def msg(text: str, host="sw1.example", app="linkd", procid="-", msgid="LINK", sd="-", pri=187,
        ts="2026-10-06T12:00:00Z") -> bytes:
    return f"<{pri}>1 {ts} {host} {app} {procid} {msgid} {sd} {text}".encode()


def block(key: Key, kind: str, params: list[tuple[str, str]], host="sw1.example", app="syslogd", procid="77",
          ver="0111", sign_with=None, tamper=None, r_bits=None, r_override=None, extra_sd="") -> bytes:
    """A block message: the element without SIGN is signed, then ` SIGN="…"` is put before `]`."""
    body = " ".join(f'{n}="{v}"' for n, v in [("VER", ver)] + params)
    head = f"<110>1 2026-10-06T12:00:01Z {host} {app} {procid} -".encode()
    unsigned = head + b" [" + kind.encode() + b" " + body.encode() + b"]" + extra_sd.encode()
    if tamper:
        unsigned_signed = unsigned
        unsigned = tamper(unsigned)
    else:
        unsigned_signed = unsigned
    sig = (sign_with or key).sign(unsigned_signed, ALG.get(ver, "sha1"), r_bits, r_override)
    close = unsigned.index(b"]")
    return unsigned[:close] + f' SIGN="{sig}"'.encode() + unsigned[close:]


def payload(key: Key, ts="2026-10-06T12:00:00Z", kind=None, blob=None) -> str:
    return f"{ts} {kind or key.kind} {base64.b64encode(blob or key.blob).decode()}"


def cert(key: Key, rsid=1, sg=0, spri=0, pay=None, index=1, flen=None, tpbl=None, **kw) -> bytes:
    pay = payload(key) if pay is None else pay
    frag = pay[index - 1:index - 1 + (flen or len(pay))]
    return block(key, "ssign-cert", [("RSID", str(rsid)), ("SG", str(sg)), ("SPRI", str(spri)),
                                     ("TPBL", str(tpbl or len(pay))), ("INDEX", str(index)), ("FLEN", str(len(frag))),
                                     ("FRAG", frag)], **kw)


def sig(key: Key, msgs: list[bytes], rsid=1, sg=0, spri=0, gbc=0, fmn=1, ver="0111", hb=None, cnt=None, **kw) -> bytes:
    hashes = hb if hb is not None else " ".join(base64.b64encode(hashlib.new(ALG.get(ver, "sha1"), m).digest()).decode()
                                                 for m in msgs)
    return block(key, "ssign", [("RSID", str(rsid)), ("SG", str(sg)), ("SPRI", str(spri)), ("GBC", str(gbc)),
                                ("FMN", str(fmn)), ("CNT", str(cnt or len(msgs))), ("HB", hashes)], ver=ver, **kw)


def sha(m: bytes) -> str:
    return hashlib.sha256(m).hexdigest()


def recv(m: bytes) -> dict:
    return {"receive": {"message": m.hex()}}


def vectors() -> list[dict]:
    out = []
    ctx = lambda *signers, hold=10: {"component": "syslog-sign", "now": 1000, "hold_s": hold, "signers": list(signers)}  # noqa: E731
    S1 = K1.signer("sw1.example")
    st = lambda emit, held=(), waiting=0: {"emit": emit, "held": list(held), "waiting": waiting}  # noqa: E731
    dep = lambda m, signed=None: {"deposit": {"sha256": sha(m), "signed": signed}}  # noqa: E731
    ref = lambda kind, reason: {"refused": {"block": kind, "reason": reason}}  # noqa: E731

    def claim(n, key=K1, host="sw1.example", app="syslogd", procid="77", rsid=1, sg=0, spri=0):
        return {"hostname": host, "app_name": app, "procid": procid, "rsid": rsid, "sg": sg, "spri": spri,
                "message_number": n, "key_sha256": key.sha256}

    def session(key=K1, host="sw1.example", app="syslogd", procid="77", rsid=1):
        return {"session": {"hostname": host, "app_name": app, "procid": procid, "rsid": rsid, "key_sha256": key.sha256}}

    def t(name, desc, c, steps):
        out.append(trace(f"syslog-sign-{name}", desc, ["E§3"], c, steps))

    # --- the interop anchor: RFC 5848's own examples ---------------------------------------------------------------
    rfc_signer = {"hostname": "host.example.org", "type": "K", "key": RFC_K}
    rfc_sha = hashlib.sha256(base64.b64decode(RFC_K)).hexdigest()
    t("rfc5848-examples", "RFC 5848's Certificate Block (a K key, FRAG carrying the payload text) and Signature Block "
      "verify; the session is established and the seven signed hashes wait for their messages.", ctx(rfc_signer), [
          (recv(RFC_CERT), st([{"session": {"hostname": "host.example.org", "app_name": "syslogd", "procid": "2138",
                                            "rsid": 1, "key_sha256": rfc_sha}}])),
          (recv(RFC_SIG), st([], waiting=7)),
      ])
    t("rfc5848-signature-before-certificate", "The RFC's Signature Block before its Certificate Block: no-session.",
      ctx(rfc_signer), [(recv(RFC_SIG), st([ref("ssign", "no-session")])),
                        (recv(RFC_CERT), st([{"session": {"hostname": "host.example.org", "app_name": "syslogd",
                                                          "procid": "2138", "rsid": 1, "key_sha256": rfc_sha}}]))])

    # --- the flow ------------------------------------------------------------------------------------------------
    m1, m2, m3 = msg("port 1 down"), msg("port 2 down"), msg("port 3 down")
    t("signed-after-messages", "Messages are held; the Signature Block that lists them deposits them signed, in order.",
      ctx(S1), [(recv(cert(K1)), st([session()])),
                (recv(m1), st([], [sha(m1)])),
                (recv(m2), st([], [sha(m1), sha(m2)])),
                (recv(sig(K1, [m1, m2])), st([dep(m1, claim(1)), dep(m2, claim(2))]))])
    S9 = KC.signer("sw9.example")
    n1 = msg("fan failed", host="sw9.example")
    t("certificate-key-sha256", "A C (certificate) signer, version 0121: SHA-256 hashes, the DSA digest truncated to q's "
      "224 bits.", ctx(S9), [
          (recv(cert(KC, host="sw9.example", ver="0121")), st([session(KC, "sw9.example")])),
          (recv(n1), st([], [sha(n1)])),
          (recv(sig(KC, [n1], ver="0121", host="sw9.example")), st([dep(n1, claim(1, KC, "sw9.example"))]))])
    t("hold-expires-unsigned", "A held message whose signature never comes is deposited unsigned after hold_s.", ctx(S1), [
        (recv(cert(K1)), st([session()])),
        (recv(m1), st([], [sha(m1)])),
        ({"advance": 9}, st([], [sha(m1)])),
        ({"advance": 1}, st([dep(m1)]))])
    t("expiry-in-arrival-order", "Held messages due together come out in arrival order.", ctx(S1), [
        (recv(m2), st([], [sha(m2)])), (recv(m1), st([], [sha(m2), sha(m1)])), ({"advance": 10}, st([dep(m2), dep(m1)]))])
    t("signature-before-message", "A signed hash waits; its message, arriving later, is deposited signed at once.", ctx(S1), [
        (recv(cert(K1)), st([session()])),
        (recv(sig(K1, [m1])), st([], waiting=1)),
        (recv(m1), st([dep(m1, claim(1))]))])
    t("waiting-expires", "A signed hash waits hold_s; after that its message is only held.", ctx(S1), [
        (recv(cert(K1)), st([session()])),
        (recv(sig(K1, [m1])), st([], waiting=1)),
        ({"advance": 10}, st([])),
        (recv(m1), st([], [sha(m1)]))])
    other = msg("hello", host="pc7.example")
    t("other-host-passes", "A message from a host that is not a configured signer is deposited at once.", ctx(S1), [
        (recv(other), st([dep(other)]))])
    bsd = b"<187>Oct  6 12:00:00 sw1.example linkd: port 1 down"
    t("rfc3164-passes", "An RFC 3164 message cannot be signed: deposited at once.", ctx(S1), [(recv(bsd), st([dep(bsd)]))])
    nohost = msg("x", host="-")
    t("nil-hostname-passes", "An RFC 5424 message with HOSTNAME '-' is deposited at once.", ctx(S1), [(recv(nohost), st([dep(nohost)]))])
    up = msg("port 1 up", host="SW1.Example")
    t("hostname-without-case", "Hostnames compare without case, for held messages and for blocks.",
      ctx(K1.signer("Sw1.EXAMPLE")), [
          (recv(cert(K1, host="sw1.example")), st([session()])),
          (recv(up), st([], [sha(up)])),
          (recv(sig(K1, [up], host="SW1.EXAMPLE")), st([dep(up, claim(1, host="SW1.EXAMPLE"))]))])
    t("no-session", "A Signature Block before any Certificate Block is no-session; the message stays held.", ctx(S1), [
        (recv(m1), st([], [sha(m1)])),
        (recv(sig(K1, [m1])), st([ref("ssign", "no-session")], [sha(m1)]))])
    t("duplicate-block-ignored", "A Signature Block received twice: its numbers are authenticated; the copy does nothing.",
      ctx(S1), [(recv(cert(K1)), st([session()])), (recv(m1), st([], [sha(m1)])),
                (recv(sig(K1, [m1])), st([dep(m1, claim(1))])),
                (recv(m1), st([], [sha(m1)])),
                (recv(sig(K1, [m1])), st([], [sha(m1)]))])
    t("overlapping-blocks", "Overlapping Signature Blocks: authenticated numbers are skipped, new ones used.", ctx(S1), [
        (recv(cert(K1)), st([session()])),
        (recv(m1), st([], [sha(m1)])), (recv(m2), st([], [sha(m1), sha(m2)])), (recv(m3), st([], [sha(m1), sha(m2), sha(m3)])),
        (recv(sig(K1, [m1, m2])), st([dep(m1, claim(1)), dep(m2, claim(2))], [sha(m3)])),
        (recv(sig(K1, [m2, m3], fmn=2)), st([dep(m3, claim(3))]))])
    t("same-message-twice", "The same message twice: a block listing its hash twice deposits both, in arrival order.",
      ctx(S1), [(recv(cert(K1)), st([session()])), (recv(m1), st([], [sha(m1)])), (recv(m1), st([], [sha(m1), sha(m1)])),
                (recv(sig(K1, [m1, m1])), st([dep(m1, claim(1)), dep(m1, claim(2))]))])
    t("groups-number-separately", "Signature Groups number separately: SPRI 13 and 14 both start at 1.", ctx(S1), [
        (recv(cert(K1)), st([session()])), (recv(m1), st([], [sha(m1)])), (recv(m2), st([], [sha(m1), sha(m2)])),
        (recv(sig(K1, [m1], sg=1, spri=13)), st([dep(m1, claim(1, sg=1, spri=13))], [sha(m2)])),
        (recv(sig(K1, [m2], sg=1, spri=14)), st([dep(m2, claim(1, sg=1, spri=14))]))])
    t("waiting-not-duplicated", "A (group, number) already waiting does not wait twice.", ctx(S1), [
        (recv(cert(K1)), st([session()])), (recv(sig(K1, [m1])), st([], waiting=1)), (recv(sig(K1, [m1])), st([], waiting=1))])

    # --- refusals ------------------------------------------------------------------------------------------------
    t("unknown-signer", "A block from a host with no configured key.", ctx(S1), [
        (recv(cert(K1, host="sw2.example")), st([ref("ssign-cert", "unknown-signer")]))])
    t("bad-signature-tampered", "A Signature Block changed after signing.", ctx(S1), [
        (recv(cert(K1)), st([session()])),
        (recv(sig(K1, [m1], tamper=lambda b: b.replace(b'GBC="0"', b'GBC="5"'))), st([ref("ssign", "bad-signature")]))])
    t("bad-signature-wrong-key", "A Signature Block signed by another key.", ctx(S1), [
        (recv(cert(K1)), st([session()])), (recv(sig(K1, [m1], sign_with=K2)), st([ref("ssign", "bad-signature")]))])
    t("bad-signature-certificate-block", "A Certificate Block signed by another key.", ctx(S1), [
        (recv(cert(K1, sign_with=K2)), st([ref("ssign-cert", "bad-signature")]))])
    t("bad-signature-r-is-q", "r must be below q.", ctx(S1), [
        (recv(cert(K1, r_override=Q_RFC)), st([ref("ssign-cert", "bad-signature")]))])
    t("mpi-bit-count-only-a-length", "An MPI whose bit count overstates the value (as the RFC's example does) is accepted.",
      ctx(S1), [(recv(cert(K1, r_bits=160)), st([session()]))])
    t("unsupported-version", "VER 0112: a well-formed version this profile does not support.", ctx(S1), [
        (recv(sig(K1, [m1], ver="0112")), st([ref("ssign", "unsupported-version")], []))])
    t("old-session", "After RSID 2 is established, an authentic RSID 1 block is old-session, even under a new PROCID.",
      ctx(S1), [(recv(cert(K1, rsid=2)), st([session(rsid=2)])),
                (recv(cert(K1, rsid=1)), st([ref("ssign-cert", "old-session")])),
                (recv(sig(K1, [m1], rsid=1, procid="99")), st([ref("ssign", "old-session")])),
                (recv(cert(K1, rsid=3, procid="99")), st([session(procid="99", rsid=3)]))])
    t("rsid-zero-unordered", "RSID 0 cannot be ordered: accepted after a higher RSID.", ctx(S1), [
        (recv(cert(K1, rsid=5)), st([session(rsid=5)])), (recv(cert(K1, rsid=0)), st([session(rsid=0)]))])
    p_new = p_new0 = payload(K1, ts="2026-10-06T13:00:00Z")
    t("rsid-zero-reboot-resets", "RSID 0: a new payload (a reboot) ends the session; numbers start over.", ctx(S1), [
        (recv(cert(K1, rsid=0)), st([session(rsid=0)])), (recv(m1), st([], [sha(m1)])),
        (recv(sig(K1, [m1], rsid=0)), st([dep(m1, claim(1, rsid=0))])),
        (recv(cert(K1, rsid=0, pay=p_new)), st([session(rsid=0)])), (recv(m2), st([], [sha(m2)])),
        (recv(sig(K1, [m2], rsid=0)), st([dep(m2, claim(1, rsid=0))]))])
    t("session-end-drops-waiting", "A different payload ends the session: its waiting hashes go with its numbers.", ctx(S1), [
        (recv(cert(K1, rsid=0)), st([session(rsid=0)])),
        (recv(sig(K1, [m1, m2], rsid=0)), st([], waiting=2)),
        # bytes 12–19 are the payload's time, 13:00:00 against the established 12:00:00: a different payload
        (recv(cert(K1, rsid=0, pay=p_new0, index=12, flen=8)), st([])),
        (recv(m1), st([], [sha(m1)]))])
    good = cert(K1)
    i = good.index(b' SIGN="') + 7
    sig_b64 = good[i:good.index(b'"', i)].decode()
    pad = len(sig_b64) - len(sig_b64.rstrip("="))
    assert pad, "the fixture's SIGN must end in padding"
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    bumped = alpha[alpha.index(sig_b64[-1 - pad]) | 1]  # an unused low bit set: the same bytes decode
    t("base64-trailing-bits", "SIGN with non-zero unused bits in its last character is accepted (RFC 4648 §3.5).",
      ctx(S1), [(recv(good.replace(sig_b64.encode(), (sig_b64[:-1 - pad] + bumped + "=" * pad).encode())),
                 st([session()]))])
    t("malformed-empty-hb-token-unsupported-version", "An empty HB token is malformed whatever the version.", ctx(S1), [
        (recv(sig(K1, [], ver="0112", cnt=2, hb="AAAA  AAAA")), st([ref("ssign", "malformed-block")]))])
    t("two-block-elements", "A message with both elements: the first names the block, which is malformed.", ctx(S1), [
        (recv(sig(K1, [m1], extra_sd='[ssign-cert VER="0111"]')), st([ref("ssign", "malformed-block")]))])
    pay = payload(K1)
    half = len(pay) // 2
    t("fragments-reassembled", "A payload in two Certificate Blocks, the second first.", ctx(S1), [
        (recv(cert(K1, pay=pay, index=half + 1)), st([])),
        (recv(cert(K1, pay=pay, index=1, flen=half)), st([session()]))])
    t("fragment-duplicate-after-session", "A Certificate Block repeating the established payload is ignored.", ctx(S1), [
        (recv(cert(K1)), st([session()])), (recv(cert(K1)), st([]))])
    t("fragment-tpbl-mismatch", "A fragment whose TPBL differs from the stored one's.", ctx(S1), [
        (recv(cert(K1, pay=pay, index=1, flen=half)), st([])),
        (recv(cert(K1, pay=pay + " ", index=half + 1, flen=5)), st([ref("ssign-cert", "fragment-mismatch")]))])
    t("fragment-overlap-mismatch", "Overlapping fragments that disagree.", ctx(S1), [
        (recv(cert(K1, pay=pay, index=1, flen=half)), st([])),
        (recv(cert(K1, pay=pay[:half - 3] + "ZZZ" + pay[half:], index=half - 2, flen=6)),
         st([ref("ssign-cert", "fragment-mismatch")]))])
    t("payload-other-key", "A payload naming another key than the configured one, though signed by it.", ctx(S1), [
        (recv(cert(K1, pay=payload(K1, blob=K2.blob))), st([ref("ssign-cert", "payload-mismatch")]))])
    t("payload-other-type", "A payload of key blob type N.", ctx(S1), [
        (recv(cert(K1, pay="2026-10-06T12:00:00Z N")), st([ref("ssign-cert", "payload-mismatch")]))])
    mal = [
        ("param-order", "Parameters out of order.", lambda: sig(K1, [m1]).replace(b'SG="0" SPRI="0"', b'SPRI="0" SG="0"')),
        ("leading-zero", "A number with a leading zero.", lambda: sig(K1, [m1], rsid="01")),
        ("count-mismatch", "CNT differs from the number of hashes.", lambda: sig(K1, [m1, m2], cnt=3)),
        ("hash-size", "A SHA-1 version carrying a 32-byte hash.", lambda: sig(K1, [], hb=base64.b64encode(bytes(32)).decode(), cnt=1)),
        ("sg-range", "SG 4.", lambda: sig(K1, [m1], sg=4)),
        ("spri-range", "SPRI 192.", lambda: sig(K1, [m1], spri=192)),
        ("fmn-zero", "FMN 0.", lambda: sig(K1, [m1], fmn=0)),
        ("extra-element", "Another SD element beside the block.", lambda: sig(K1, [m1], extra_sd='[x@1 a="b"]')),
        ("double-space", "Hashes separated by two spaces.", lambda: sig(K1, [], cnt=2, hb=" ".join(
            base64.b64encode(hashlib.sha1(m).digest()).decode() for m in (m1, m2)).replace(" ", "  "))),
        ("sign-three-mpis", "SIGN holding three MPIs.", lambda: sig(K1, [m1]).replace(b'"]', b'AAEB"]') if False else
         sig(K1, [m1]).replace(b' SIGN="', b' SIGN="AAEB', 1)),
        ("sign-not-base64", "SIGN that is not base64.", lambda: sig(K1, [m1]).replace(b' SIGN="', b' SIGN="*', 1)),
    ]
    for name, desc, mk in mal:
        t(f"malformed-{name}", desc, ctx(S1), [(recv(mk()), st([ref("ssign", "malformed-block")]))])
    t("malformed-flen", "FRAG's length differs from FLEN.", ctx(S1), [
        (recv(cert(K1).replace(b'FLEN="', b'FLEN="1', 1)), st([ref("ssign-cert", "malformed-block")]))])
    t("malformed-past-tpbl", "INDEX + FLEN − 1 beyond TPBL.", ctx(S1), [
        (recv(cert(K1, pay=pay, index=2, flen=len(pay) - 1, tpbl=len(pay) - 1)), st([ref("ssign-cert", "malformed-block")]))])
    return out
