"""did:webvh v1.0 resolution for DSIP — reference for the `did-webvh/` vectors.

Spec: §7.2, §8.1, §8.4 (v0.9; spec-gap 101), and the did:webvh v1.0 method specification
(https://identity.foundation/didwebvh/v1.0/, DIF Ratified).

A resolver verifies the whole log and returns the latest document, or rejects it with one reason
token. The check order is normative for the suite (impl/vectors/README.md, `did-webvh` row), so
that three implementations agree on the reason when a log has more than one fault.

Impl (spec-gap 101): any invalid entry rejects the log (fail closed); DSIP resolvers MUST cache the
highest verified versionId per DID and reject a log that does not reach it (`rollback`) or that
has a different entry there (`fork`); watchers are optional. JCS (RFC 8785) is used only inside
this method's own proofs and hashes — it never touches a DSIP envelope (§10.2 rule 3 of CLAUDE.md).

The module also builds logs (`LogBuilder`) for the vector generator: deterministic keys, past
timestamps, eddsa-jcs-2022 proofs.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone

from .crypto import KeyPair, b58_decode, b58_encode, ed25519_verify, keypair_from_seed_name

MH_SHA256 = b"\x12\x20"
ED25519_PUB = b"\xed\x01"
METHOD = "did:webvh:1.0"
ENTRY_KEYS = {"versionId", "versionTime", "parameters", "state", "proof"}
PARAMS = {"method", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "portable", "deactivated", "ttl"}
FUTURE_TOLERANCE_S = 300  # did:webvh §Read: SHOULD be at most 5 minutes
B58 = "[1-9A-HJ-NP-Za-km-z]"
# Unicode White_Space (README `did-webvh` step 1); U+FEFF is not one.
WHITE_SPACE = set("\t\n\x0b\x0c\r \x85\xa0\u1680\u2028\u2029\u202f\u205f\u3000") | {chr(c) for c in range(0x2000, 0x200B)}


class Reject(Exception):
    """A resolution failure carrying one reason token (README `did-webvh` row)."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


# --- primitives ------------------------------------------------------------------------------

def jcs(v) -> bytes:
    """RFC 8785 for the values did:webvh logs use: objects, arrays, strings, integers, booleans, null.

    Impl: a float is refused (no did:webvh field is one); keys are sorted by UTF-16 code units.
    """
    def enc(x) -> str:
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            return str(x)
        if isinstance(x, float):
            raise Reject("log-malformed", "a number that is not an integer")
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, list):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            keys = sorted(x, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k]) for k in keys) + "}"
        raise Reject("log-malformed", f"unsupported value {type(x).__name__}")
    return enc(v).encode("utf-8")


MAX_SAFE = 2**53 - 1


def ijson(text: str):
    """Parse I-JSON (RFC 7493): no duplicate names, no lone surrogates, integers within ±(2^53−1).

    Raises ValueError otherwise. Spec: did:webvh's JCS (RFC 8785) assumes I-JSON.
    """
    def pairs(kv):
        d = {}
        for k, v in kv:
            if k in d:
                raise ValueError("duplicate member name")
            d[k] = v
        return d

    def no_float(_s):
        raise ValueError("not an integer")

    def check(x):
        if isinstance(x, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
                raise ValueError("lone surrogate")
        elif isinstance(x, bool) or x is None:
            pass
        elif isinstance(x, int):
            if not -MAX_SAFE <= x <= MAX_SAFE:
                raise ValueError("integer out of range")
        elif isinstance(x, list):
            for i in x:
                check(i)
        elif isinstance(x, dict):
            for k, v in x.items():
                check(k)
                check(v)
    v = json.loads(text, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float)
    check(v)
    return v


def mh_b58(data: bytes) -> str:
    """base58btc(multihash sha2-256(data)), without a multibase prefix."""
    return b58_encode(MH_SHA256 + hashlib.sha256(data).digest())


def is_mh(s) -> bool:
    if not isinstance(s, str) or not re.fullmatch(f"{B58}+", s):
        return False
    raw = b58_decode(s)
    return raw[:2] == MH_SHA256 and len(raw) == 34


def multikey(pub: bytes) -> str:
    return "z" + b58_encode(ED25519_PUB + pub)


def multikey_pub(mk) -> bytes | None:
    if not isinstance(mk, str) or not re.fullmatch(f"z{B58}+", mk):
        return None
    raw = b58_decode(mk[1:])
    return raw[2:] if raw[:2] == ED25519_PUB and len(raw) == 34 else None


def parse_time(s) -> int | None:
    """versionTime → nanoseconds since the epoch; None unless ISO 8601 UTC with `Z` or `+00:00`."""
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|\+00:00)", s) if isinstance(s, str) else None
    if not m:
        return None
    try:
        t = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    frac = (m.group(2) or "").ljust(9, "0")
    return int(t.timestamp()) * 1_000_000_000 + int(frac or 0)


# --- DID syntax --------------------------------------------------------------------------------

def check_did(did) -> str:
    """Validate a did:webvh DID (method spec §Method-Specific Identifier); return its SCID.

    Impl (spec-gap 101): the domain is ASCII LDH labels (an IDN appears in its `xn--` form); a
    percent-encoded domain other than the `%3A` port separator is refused.
    """
    if not isinstance(did, str) or not did.startswith("did:webvh:"):
        raise Reject("invalid-did", "not did:webvh")
    parts = did[len("did:webvh:"):].split(":")
    if len(parts) < 2:
        raise Reject("invalid-did", "no domain")
    scid, domain, path = parts[0], parts[1], parts[2:]
    if not re.fullmatch(f"{B58}{{46}}", scid):
        raise Reject("invalid-did", "SCID is not 46 base58btc characters")
    host, _, port = domain.partition("%3A")
    if port and (not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535):
        raise Reject("invalid-did", "bad port")
    labels = host.split(".")
    if len(labels) < 2 or not all(re.fullmatch(r"[A-Za-z0-9-]{1,63}", lb) for lb in labels):
        raise Reject("invalid-did", "domain is not at least two LDH labels")
    if all(lb.isdigit() for lb in labels):
        raise Reject("invalid-did", "domain is an IP address")
    for seg in path:
        if not re.fullmatch(r"(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+", seg):
            raise Reject("invalid-did", "bad path segment")
        raw = re.sub(rb"%([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), seg.encode())
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Reject("invalid-did", "path segment is not UTF-8")
        if dec in (".", "..") or any(c in dec for c in "/\\\x00") or dec[:1] in WHITE_SPACE or dec[-1:] in WHITE_SPACE:
            raise Reject("invalid-did", "bad decoded path segment")
    return scid


# --- proofs ------------------------------------------------------------------------------------

def proof_input(document: dict, proof: dict) -> bytes:
    """eddsa-jcs-2022 signing input: sha256(JCS(proof config)) ‖ sha256(JCS(document))."""
    cfg = {k: v for k, v in proof.items() if k != "proofValue"}
    return hashlib.sha256(jcs(cfg)).digest() + hashlib.sha256(jcs(document)).digest()


def vm_multikey(vm) -> str | None:
    m = re.fullmatch(f"did:key:(z{B58}+)#(z{B58}+)", vm) if isinstance(vm, str) else None
    return m.group(1) if m and m.group(1) == m.group(2) else None


def proof_ok(document: dict, proof, pub: bytes) -> bool:
    if not isinstance(proof, dict) or proof.get("type") != "DataIntegrityProof" \
            or proof.get("cryptosuite") != "eddsa-jcs-2022" or proof.get("proofPurpose") != "assertionMethod":
        return False
    pv = proof.get("proofValue")
    if not isinstance(pv, str) or not re.fullmatch(f"z{B58}+", pv):
        return False
    return ed25519_verify(pub, proof_input(document, proof), b58_decode(pv[1:]))


# --- parameters --------------------------------------------------------------------------------

def check_params(p: dict, n: int, prev: dict) -> None:
    """Allowed keys and types, first-entry rules (did:webvh §Parameters). Raises `parameters`."""
    def bad(why):
        raise Reject("parameters", f"entry {n}: {why}")
    if not isinstance(p, dict):
        bad("not an object")
    if set(p) - PARAMS:
        bad(f"unknown {sorted(set(p) - PARAMS)}")
    if n == 1:
        for k in ("method", "scid", "updateKeys"):
            if k not in p:
                bad(f"{k} missing")
    elif "scid" in p:
        bad("scid after the first entry")
    if "method" in p and p["method"] != METHOD:
        bad("method is not did:webvh:1.0")
    if "scid" in p and not is_mh(p["scid"]):
        bad("scid is not a sha2-256 multihash")
    for k in ("updateKeys", "nextKeyHashes", "watchers"):
        if k in p and (not isinstance(p[k], list) or not all(isinstance(x, str) for x in p[k])):
            bad(f"{k} is not a list of strings")
    if "updateKeys" in p and not all(multikey_pub(k) for k in p["updateKeys"]):
        bad("updateKeys holds a key that is not an Ed25519 multikey")
    for k in ("portable", "deactivated"):
        if k in p and not isinstance(p[k], bool):
            bad(f"{k} is not a boolean")
    if "ttl" in p and (not isinstance(p["ttl"], int) or isinstance(p["ttl"], bool) or not 0 <= p["ttl"] <= 2**31):
        bad("ttl")
    if n > 1 and p.get("portable") is True:
        bad("portable: true after the first entry")
    if "witness" in p:
        w = p["witness"]
        if not isinstance(w, dict):
            bad("witness is not an object")
        if w:
            ids = [x.get("id") if isinstance(x, dict) else None for x in w.get("witnesses", [])] \
                if isinstance(w.get("witnesses"), list) else []
            t = w.get("threshold")
            if set(w) != {"threshold", "witnesses"} or not ids or len(set(ids)) != len(ids) \
                    or not all(isinstance(i, str) and i.startswith("did:key:") and multikey_pub(i[8:]) for i in ids) \
                    or not isinstance(t, int) or isinstance(t, bool) or not 1 <= t <= len(ids):
                bad("malformed witness")


# --- resolution --------------------------------------------------------------------------------

def resolve(did, log: str, witness: str | None, cache: dict | None, now: int) -> dict:
    """Resolve `did` from its log text. Returns the README `did-webvh` outcome object."""
    try:
        return _resolve(did, log, witness, cache, now)
    except Reject as r:
        return {"outcome": "rejected", "reason": r.reason}


def _resolve(did, log, witness, cache, now) -> dict:
    scid_did = check_did(did)                                                   # 1. requested DID
    lines = log.split("\n")
    if lines and lines[-1] == "":
        lines.pop()                                                             # one trailing newline
    if not lines:
        raise Reject("log-malformed", "empty log")
    entries, active, prev_vid, prev_time, prev_id, scid = [], {}, None, None, None, None
    witness_due: list[tuple[int, dict]] = []
    for i, line in enumerate(lines):
        n = i + 1
        try:
            e = ijson(line)
        except ValueError:
            raise Reject("log-malformed", f"entry {n} is not I-JSON")
        # 2. structure
        if not isinstance(e, dict) or set(e) != ENTRY_KEYS or not isinstance(e["state"], dict) \
                or not isinstance(e["proof"], list) or not e["proof"] or not isinstance(e["versionId"], str):
            raise Reject("log-malformed", f"entry {n} shape")
        # 3. versionId number, entryHash form
        m = re.fullmatch(f"([1-9][0-9]*)-({B58}+)", e["versionId"])
        if not m or int(m.group(1)) != n:
            raise Reject("version-number", f"entry {n}")
        if not is_mh(m.group(2)):
            raise Reject("entry-hash", f"entry {n}: not a multihash")
        # 4. versionTime
        t = parse_time(e["versionTime"])
        if t is None or (prev_time is not None and t <= prev_time) or t > (now + FUTURE_TOLERANCE_S) * 1_000_000_000:
            raise Reject("version-time", f"entry {n}")
        # 5. parameters
        p = e["parameters"]
        if n > 1 and active.get("deactivated"):
            raise Reject("after-deactivation", f"entry {n}")
        check_params(p, n, active)
        prev = dict(active)
        if n == 1:
            active = {"nextKeyHashes": [], "witness": {}, "watchers": [], "portable": False, "deactivated": False,
                      "ttl": 3600}
        active.update(p)
        # 6. SCID (entry 1)
        if n == 1:
            scid = p["scid"]
            pre = {k: v for k, v in e.items() if k != "proof"}
            pre["versionId"] = "{SCID}"
            text = json.dumps(pre, ensure_ascii=False).replace(scid, "{SCID}")
            if mh_b58(jcs(json.loads(text))) != scid:
                raise Reject("scid", "recomputed SCID differs")
        # 7. entryHash and the chain
        h = {k: v for k, v in e.items() if k != "proof"}
        h["versionId"] = scid if n == 1 else prev_vid
        if mh_b58(jcs(h)) != m.group(2):
            raise Reject("entry-hash", f"entry {n}")
        # 8. pre-rotation
        prerot = n > 1 and bool(prev.get("nextKeyHashes"))
        if prerot:
            if "updateKeys" not in p or "nextKeyHashes" not in p:
                raise Reject("pre-rotation", f"entry {n}: updateKeys and nextKeyHashes must be explicit")
            if not all(mh_b58(k.encode()) in prev["nextKeyHashes"] for k in p["updateKeys"]):
                raise Reject("pre-rotation", f"entry {n}: a key was not committed")
        # 9. proofs: at least one valid proof by an active update key
        keys = p["updateKeys"] if (n == 1 or prerot) else prev["updateKeys"]
        doc = {k: v for k, v in e.items() if k != "proof"}
        authorized = False
        for pr in e["proof"]:
            mk = vm_multikey(pr.get("verificationMethod") if isinstance(pr, dict) else None)
            if mk is None:
                raise Reject("proof", f"entry {n}: verificationMethod")
            if mk not in keys:
                continue
            if not proof_ok(doc, pr, multikey_pub(mk)):
                raise Reject("proof", f"entry {n}: proof does not verify")
            authorized = True
        if not authorized:
            raise Reject("unauthorized-key", f"entry {n}")
        # 10. state.id: a bare did:webvh DID with the log's SCID; a move needs portability
        sid = e["state"].get("id")
        try:
            sid_scid = check_did(sid)
        except Reject:
            raise Reject("identity", f"entry {n}: state.id")
        if sid_scid != scid:
            raise Reject("identity", f"entry {n}: state.id SCID")
        if prev_id is not None and sid != prev_id:
            aka = e["state"].get("alsoKnownAs", [])
            if not active["portable"] or not isinstance(aka, list) or prev_id not in aka:
                raise Reject("identity", f"entry {n}: moved without portability")
        # witness requirement (did:webvh §Witnesses timing)
        wcfg = active["witness"] if (n == 1 or prev.get("witness", {}) == {}) else prev["witness"]
        if wcfg:
            witness_due.append((i, wcfg))
        entries.append(e)
        prev_vid, prev_time, prev_id = e["versionId"], t, sid
    # 11. the requested DID is this log's
    if scid_did != scid or not any(x["state"]["id"] == did for x in entries):
        raise Reject("identity", "requested DID")
    # 12. witnesses
    if witness_due:
        if witness is None:
            raise Reject("witness", "no witness file")
        try:
            records = ijson(witness)
        except ValueError:
            raise Reject("witness", "witness file is not I-JSON")
        vids = [x["versionId"] for x in entries]
        approvals: dict[int, set] = {}
        for rec in records if isinstance(records, list) else []:
            if not isinstance(rec, dict) or rec.get("versionId") not in vids:
                continue
            j = vids.index(rec["versionId"])
            for pr in rec.get("proof", []) if isinstance(rec.get("proof"), list) else []:
                mk = vm_multikey(pr.get("verificationMethod") if isinstance(pr, dict) else None)
                if mk and proof_ok({"versionId": rec["versionId"]}, pr, multikey_pub(mk)):
                    approvals.setdefault(j, set()).add("did:key:" + mk)
        for i, cfg in witness_due:
            ids = {x["id"] for x in cfg["witnesses"]}
            got = set().union(*[s & ids for j, s in approvals.items() if j >= i]) if approvals else set()
            if len(got) < cfg["threshold"]:
                raise Reject("witness", f"entry {i + 1}: {len(got)}/{cfg['threshold']}")
    # 13. DSIP: rollback and fork against the cached versionId (spec-gap 101)
    last = entries[-1]
    cvid = cache.get("versionId") if isinstance(cache, dict) else None
    if isinstance(cvid, str) and re.fullmatch(r"[1-9][0-9]*-.+", cvid, re.DOTALL):
        k = int(cvid.split("-", 1)[0])
        if len(entries) < k:
            raise Reject("rollback", f"log ends at {len(entries)}, cache holds {k}")
        if entries[k - 1]["versionId"] != cvid:
            raise Reject("fork", f"entry {k} differs from the cached one")
    # 14. outcome
    if active["deactivated"]:
        return {"outcome": "deactivated", "versionId": last["versionId"], "cache": last["versionId"]}
    return {"outcome": "resolved", "versionId": last["versionId"], "versionTime": last["versionTime"],
            "document": last["state"], "ttl": active["ttl"], "cache": last["versionId"]}


# --- building logs (vector generator) ------------------------------------------------------------

def kp(name: str) -> KeyPair:
    return keypair_from_seed_name(f"webvh-{name}")


def sign_proof(document: dict, key: KeyPair, created: str) -> dict:
    mk = multikey(key.public)
    proof = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
             "verificationMethod": f"did:key:{mk}#{mk}", "created": created, "proofPurpose": "assertionMethod"}
    proof["proofValue"] = "z" + b58_encode(key.sign(proof_input(document, proof)))
    return proof


def key_hash(key: KeyPair) -> str:
    return mh_b58(multikey(key.public).encode())


class LogBuilder:
    """Builds a valid did:webvh log one entry at a time; tamper with `entries` afterwards for negatives."""

    def __init__(self, domain: str = "example.com", path: tuple = (), start: str = "2026-01-01T00:00:00Z"):
        self.domain, self.path = domain, list(path)
        self.entries: list[dict] = []
        self.minute = 0
        self.start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    def _time(self) -> str:
        self.minute += 1
        t = self.start.timestamp() + 60 * self.minute
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def did_for(self, scid: str, domain: str | None = None, path=None) -> str:
        return ":".join(["did:webvh", scid, domain or self.domain] + list(self.path if path is None else path))

    @property
    def did(self) -> str:
        return self.entries[-1]["state"]["id"]

    @property
    def scid(self) -> str:
        return self.entries[0]["parameters"]["scid"]

    def document(self, did: str, key: KeyPair, extra: dict | None = None) -> dict:
        doc = {"@context": ["https://www.w3.org/ns/did/v1"], "id": did,
               "verificationMethod": [{"id": f"{did}#key-1", "type": "Multikey", "controller": did,
                                       "publicKeyMultibase": multikey(key.public)}],
               "authentication": [f"{did}#key-1"], "assertionMethod": [f"{did}#key-1"]}
        doc.update(extra or {})
        return doc

    def create(self, signer: KeyPair, params: dict | None = None, doc_key: KeyPair | None = None,
               doc_extra: dict | None = None) -> "LogBuilder":
        did_t = self.did_for("{SCID}")
        p = {"method": METHOD, "scid": "{SCID}", "updateKeys": [multikey(signer.public)]}
        p.update(params or {})
        pre = {"versionId": "{SCID}", "versionTime": self._time(), "parameters": p,
               "state": self.document(did_t, doc_key or signer, doc_extra)}
        scid = mh_b58(jcs(pre))
        e = json.loads(json.dumps(pre, ensure_ascii=False).replace("{SCID}", scid))
        h = dict(e)
        h["versionId"] = scid
        e["versionId"] = "1-" + mh_b58(jcs(h))
        e["proof"] = [sign_proof(e, signer, e["versionTime"])]
        self.entries.append(e)
        return self

    def update(self, signer: KeyPair, params: dict | None = None, state: dict | None = None,
               doc_extra: dict | None = None) -> "LogBuilder":
        prev = self.entries[-1]
        st = copy.deepcopy(state if state is not None else prev["state"])
        st.update(doc_extra or {})
        e = {"versionId": prev["versionId"], "versionTime": self._time(), "parameters": params or {}, "state": st}
        h = dict(e)
        e["versionId"] = f"{len(self.entries) + 1}-{mh_b58(jcs(h))}"
        e["proof"] = [sign_proof(e, signer, e["versionTime"])]
        self.entries.append(e)
        return self

    def resign(self, index: int, signer: KeyPair) -> "LogBuilder":
        """Recompute entry `index`'s hash (and every later one's) and re-sign — after a deliberate edit."""
        for j in range(index, len(self.entries)):
            e = self.entries[j]
            e.pop("proof", None)
            h = dict(e)
            h["versionId"] = self.scid if j == 0 else self.entries[j - 1]["versionId"]
            e["versionId"] = f"{j + 1}-{mh_b58(jcs(h))}"
            e["proof"] = [sign_proof({k: v for k, v in e.items() if k != "proof"}, signer, e["versionTime"])]
        return self

    def text(self) -> str:
        return "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in self.entries)

    def witness_file(self, approvals: list[tuple[str, KeyPair]]) -> str:
        """`[(versionId, witness key)]` → did-witness.json text."""
        out: dict[str, list] = {}
        for vid, key in approvals:
            out.setdefault(vid, []).append(sign_proof({"versionId": vid}, key, "2026-01-02T00:00:00Z"))
        return json.dumps([{"versionId": v, "proof": p} for v, p in out.items()], separators=(",", ":"))
