"""Ed25519 keys, base64url, base58btc, and `did:key` (spec §7.2, §10.2).

Keys are derived from named seeds so every signed vector is byte-reproducible.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

# multicodec ed25519-pub = 0xed, varint-encoded as 0xed 0x01
ED25519_PUB_MULTICODEC = b"\xed\x01"
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Strict base64url decode (no padding accepted on the wire)."""
    if not isinstance(s, str) or s == "":
        raise ValueError("empty")
    for ch in s:
        if not (ch.isalnum() or ch in "-_") or ord(ch) > 127:
            raise ValueError("bad alphabet")
    pad = (-len(s)) % 4
    if pad == 3:
        raise ValueError("bad length")
    return base64.urlsafe_b64decode(s + "=" * pad)


def b58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(B58_ALPHABET[r])
    # leading zero bytes → '1'
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return (b"1" * pad + bytes(reversed(out))).decode("ascii")


def b58_decode(s: str) -> bytes:
    n = 0
    for ch in s.encode("ascii"):
        idx = B58_ALPHABET.find(bytes([ch]))
        if idx < 0:
            raise ValueError("bad base58 char")
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def did_key_from_public(pub: bytes) -> str:
    """`did:key` for an Ed25519 public key: multibase(base58btc, multicodec(ed25519-pub) || key)."""
    return "did:key:z" + b58_encode(ED25519_PUB_MULTICODEC + pub)


def public_from_did_key(did: str) -> bytes:
    """Inverse of `did_key_from_public`. Raises ValueError for anything that is not an Ed25519 did:key."""
    if not did.startswith("did:key:z"):
        raise ValueError("not a base58btc did:key")
    raw = b58_decode(did[len("did:key:z"):])
    if not raw.startswith(ED25519_PUB_MULTICODEC) or len(raw) != 2 + 32:
        raise ValueError("not an ed25519-pub did:key")
    return raw[2:]


@dataclass(frozen=True)
class KeyPair:
    name: str
    signing_key: SigningKey

    @property
    def public(self) -> bytes:
        return bytes(self.signing_key.verify_key)

    @property
    def did(self) -> str:
        return did_key_from_public(self.public)

    @property
    def kid(self) -> str:
        """Default verification-method DID URL for a did:key: `did:key:z6Mk…#z6Mk…`."""
        mb = self.did[len("did:key:"):]
        return f"{self.did}#{mb}"

    def sign(self, data: bytes) -> bytes:
        return bytes(self.signing_key.sign(data).signature)


def keypair_from_seed_name(name: str) -> KeyPair:
    seed = hashlib.sha256(f"dsip-vector:{name}".encode()).digest()
    return KeyPair(name, SigningKey(seed))


def ed25519_verify(pub: bytes, data: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(pub).verify(data, sig)
        return True
    except (BadSignatureError, ValueError):
        return False
