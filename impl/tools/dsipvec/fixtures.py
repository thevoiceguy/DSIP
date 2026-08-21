"""Deterministic fixture set shared by every vector (see vectors/README.md "Fixed fixtures")."""
from __future__ import annotations

import json

from .crypto import KeyPair, keypair_from_seed_name, b58_encode, ED25519_PUB_MULTICODEC
from . import envelope as env

NOW = 1760000000  # receiver clock used by default

NAMES = ["alice", "alice-phone", "alice-laptop", "bob", "bob-phone", "bob-laptop",
         "relay", "carol", "carol-phone", "mallory", "bob-next"]

KEYS: dict[str, KeyPair] = {n: keypair_from_seed_name(n) for n in NAMES}

# did:web identities map onto fixture keys
BOB_WEB = "did:web:example.com:users:bob"
RELAY_WEB = "did:web:relay.example.com"
WEB_IDENTITIES = {BOB_WEB: "bob", RELAY_WEB: "relay"}

VERSION = {"core": "1.0", "min_core": "1.0", "profiles": ["interactive-media/1.0"],
           "extensions": [], "critical": []}
VERSION_TRANSPORT = {**VERSION, "profiles": []}
SUPPORTED = {"core": "1.0", "profiles": ["interactive-media/1.0", "verified-broadcast/1.0"],
             "extensions": []}   # v0.7: provenance is a core message (§22.3), no extension id


def did(name: str) -> str:
    return KEYS[name].did


def kid(name: str) -> str:
    return KEYS[name].kid


def web_kid(web_did: str) -> str:
    return f"{web_did}#key-1"


def multibase_pub(name: str) -> str:
    return "z" + b58_encode(ED25519_PUB_MULTICODEC + KEYS[name].public)


def did_web_document(web_did: str, signaling_uri: str = "wss://relay.example.com/dsip") -> dict:
    """Minimal DID document for a did:web identity (spec §13.2 endpoint advertisement)."""
    name = WEB_IDENTITIES[web_did]
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": web_did,
        "verificationMethod": [{
            "id": f"{web_did}#key-1",
            "type": "Multikey",
            "controller": web_did,
            "publicKeyMultibase": multibase_pub(name),
        }],
        "authentication": [f"{web_did}#key-1"],
        "assertionMethod": [f"{web_did}#key-1"],
        "service": [{
            "id": f"{web_did}#dsip-signaling",
            "type": "DSIPSignaling",
            "serviceEndpoint": {"uri": signaling_uri, "bindings": ["ws/1.0"]},
        }],
    }


def did_documents() -> dict[str, dict]:
    return {d: did_web_document(d) for d in WEB_IDENTITIES}


def did_web_document_rotated(web_did: str, new_name: str, new_frag: str = "key-2") -> dict:
    """The same did:web identity after key rotation (spec §7.5): the previous verification
    method is gone and a new one under a new fragment is in its place. DSIP has no rotation
    record on the wire in v0.6 (spec-gap 22); what a verifier observes is the DID document
    state, which is authoritative (§8.1)."""
    doc = did_web_document(web_did)
    doc["verificationMethod"] = [{
        "id": f"{web_did}#{new_frag}",
        "type": "Multikey",
        "controller": web_did,
        "publicKeyMultibase": multibase_pub(new_name),
    }]
    doc["authentication"] = [f"{web_did}#{new_frag}"]
    doc["assertionMethod"] = [f"{web_did}#{new_frag}"]
    return doc


# ---------------------------------------------------------------- delegations (§7.4)

def delegation_payload(subject: str, device: str, issued_at: int, expires_at: int,
                       capabilities=("dsip.signaling", "dsip.media.interactive")) -> dict:
    return {
        "type": "DeviceDelegation",
        "subject": subject,
        "device": device,
        "capabilities": list(capabilities),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }


def make_delegation(subject_signer: KeyPair, subject: str, device: str, *,
                    issued_at: int = NOW - 86400, expires_at: int = NOW + 86400 * 30,
                    capabilities=("dsip.signaling", "dsip.media.interactive"),
                    signer_kid: str | None = None) -> dict:
    payload = delegation_payload(subject, device, issued_at, expires_at, capabilities)
    return env.sign(payload, subject_signer, signer_kid or subject_signer.kid)


def standard_delegations() -> list[dict]:
    """The delegation set a receiver holds for the alice/bob fixture identities."""
    a, b = KEYS["alice"], KEYS["bob"]
    return [
        make_delegation(a, did("alice"), did("alice-phone")),
        make_delegation(a, did("alice"), did("alice-laptop")),
        make_delegation(b, did("bob"), did("bob-phone")),
        make_delegation(b, did("bob"), did("bob-laptop")),
        # bob's did:web identity delegates the same devices (signed by the did:web key-1)
        make_delegation(b, BOB_WEB, did("bob-phone"), signer_kid=web_kid(BOB_WEB)),
        make_delegation(b, BOB_WEB, did("bob-laptop"), signer_kid=web_kid(BOB_WEB)),
    ]


def public_fixtures() -> dict:
    """What `fixtures.json` records (public material only)."""
    return {
        "keys": {n: {"did": KEYS[n].did, "kid": KEYS[n].kid, "public_key_multibase": multibase_pub(n)} for n in NAMES},
        "web_identities": {w: did(n) for w, n in WEB_IDENTITIES.items()},
        "did_documents": did_documents(),
        "delegations": standard_delegations(),
        "now": NOW,
        "supported": SUPPORTED,
    }


if __name__ == "__main__":
    print(json.dumps(public_fixtures(), indent=2))
