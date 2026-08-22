# DSIP Gateway — STIR/SHAKEN, RCD, and CNAM findings (Phase 4 G4)

**Date:** 2026-08-22. **Scope:** what a DSIP↔SIP gateway can *verify* about a PSTN caller's
identity inbound, what it can *assert* about a DSIP caller outbound, and under which operator
status — the evidence behind Gateway Profile §G§5/§G§11 and the §6.3 downgrade rule. Companion to
`v0.8/dsip-gateway-profile-v0.8-draft.md`.

The honest one-line answer, stated up front: **inbound verification is fully available today;
outbound assertion depends entirely on whether the operator is an authorized service provider, and
for most DSIP deployments it will not be — so most outbound PSTN crossings are `gateway.downgraded`.**

---

## 1. What the stack already provides

- **siphon-rs `sip-identity`** parses the RFC 8224 `Identity` header and its RFC 8225 PASSporT,
  verifies the **ES256** signature, and validates the signing certificate's **X.509 chain to a
  STI-PA trust anchor** (`Passport::verify_with_chain`). It does **not** fetch the `x5u`
  certificate (async I/O + TTL cache is the application's job) or run the TN-Authorization-List ↔
  `orig` check.
- **New (this workstream):** `sip-identity` gains PASSporT **signing** behind a `sign` feature
  (siphon-rs PR #123) — `sign(params, key, rng)` builds and ES256-signs a SHAKEN PASSporT and emits
  the `Identity` header value. It round-trips through the existing verifier. This makes outbound
  path (a) below concrete.
- **DSIP side:** the gateway already maps a verified attestation into a `tel` claim
  (`dsip-gateway::tel_claim`, §G§5) whose `verified`/`attestation` fields the callee's client
  renders as the §18.1 basis (G3). A PASSporT whose `orig` ≠ the SIP `From` is discarded.

## 2. Inbound: PSTN → DSIP (verification)

**Available today, end to end.** The gateway:

1. reads the `Identity` header off the INVITE, parses the PASSporT (`IdentityHeader::parse`);
2. fetches the `x5u` certificate (application layer: HTTPS GET + cache; a small addition, not in
   `sip-identity` by design);
3. `verify_with_chain` against the STI-PA anchors → an attestation level (A/B/C) or a failure;
4. checks `orig.tn` against the SIP `From` and `iat` freshness (RFC 8224 replay window);
5. builds the `tel` claim: `attestation` = A/B/C, `verified` = the chain + signature + orig-match
   all passed.

The DSIP callee then sees, per §18.1: *"Gateway attested by gw.example · STIR attestation A
(verified)"* — or *"… (unverified)"* / *"· no attestation"* when the header is absent, the chain
fails, or `orig` mismatches. This is the strong half: DSIP inherits the PSTN's own caller
authentication and renders it honestly, without a badge.

**Gaps to close for production inbound** (all application-layer, none blocking the design):
- `x5u` fetch + cache with the STI-PA CRL/allow-list.
- TN-Authorization-List check (does the cert actually cover `orig.tn`?).
- RCD (Rich Call Data, RFC 8946/9449) and `jcard`/`crn` claims → additional display claims
  (caller name, logo) carried as further `identity.claims` entries, each rendered as a claim
  (§18.2), never as verified truth unless the issuer is trusted for that data.

## 3. Outbound: DSIP → PSTN (assertion) — three paths

This is where operator status decides everything.

### (a) The operator is an authorized service provider

It holds an SPC (Service Provider Code) token from the STI-PA and an STI certificate whose `x5u` is
publicly reachable. It can sign a SHAKEN PASSporT — `attest: "A"` for numbers it owns and has
authenticated the DSIP caller's right to use, `B`/`C` otherwise — and put it on the outbound
INVITE. **`sip-identity`'s new `sign` makes this a few lines.** The crossing is *not* downgraded on
the identity axis (it may still be on SRTP if the trunk is plain RTP).

The hard part is not the signing; it is **entitlement**: mapping a DSIP identity to a number the
operator is authorized to assert. A DSIP identity is not a phone number. The operator must either
(i) own a number range and assign numbers to DSIP identities (the "DSIP identity has a PSTN DID"
model), or (ii) hold a delegate certificate for the caller's number (path c). Attestation `A`
requires (i) with authentication; without it the gateway asserts `B` at best.

### (b) The operator is not a service provider

Most DSIP deployments. It has no SPC token, no STI certificate. It can present `From` /
`P-Asserted-Identity` and RCD-like display data, but **cannot sign a PASSporT** — and MUST NOT
present a self-signed one as attestation (stated in the `sign` module docs and §G§2). Every such
crossing is `gateway.downgraded` with `identity-not-assertable`; the DSIP caller's rich identity
does not survive into the PSTN. This is the honest default, and it is why §6.3 exists.

### (c) Delegate certificates (RFC 9060) — the DSIP-shaped path

A carrier that owns a number range delegates a **TN range** to the operator via a delegate
certificate. The operator then signs PASSporTs for numbers in that range under its delegate cert,
chaining to the carrier's authority. This is the most interesting path for DSIP because **the DID
document could publish the delegate certificate**: a `did:web` identity that owns a PSTN number
could carry, in its DID document, the delegate cert authorizing that number — turning "does this
DSIP identity own this number?" into a DID-resolution question the gateway already knows how to
answer (§8.1 authority order). This unifies DSIP's identity model with STIR's: the same document
that proves the signaling key proves the number entitlement.

`sip-identity`'s `sign` covers the cryptographic step for (a) and (c) identically (both sign a
PASSporT with a P-256 key); the difference is which certificate the `x5u` points at and what it
chains to. Building the delegate-cert-in-DID-document model is a design study, not a v1 feature,
but it is the recommended direction and is filed as a forward item.

## 4. CNAM

CNAM (calling name) is a US database lookup, not a signed assertion. A gateway MAY populate the
`tel` claim's `cnam` field from a CNAM dip, but it is unverified display data (§18.2): rendered as
"caller name (unverified)", never as part of the attestation basis. RCD's signed `nam`/`jcard`
(path 2 above) is the verifiable alternative and is preferred where available.

## 5. Recommendations

1. **Ship inbound now.** Add the `x5u` fetch/cache + TN-Auth-List check at the application layer;
   the verification core and the claim rendering are done. This is the high-value half — DSIP
   callees get honest, rendered STIR attestation for PSTN callers.
2. **Assert outbound only when entitled.** Wire `sip-identity`'s `sign` behind an operator-config
   flag that is off by default; emit `gateway.downgraded identity-not-assertable` whenever it is
   off. Never self-sign.
3. **Pursue (c).** A design note on publishing delegate certificates in DID documents is the
   distinctive contribution: it is where DSIP's decentralized identity and STIR's number
   entitlement meet. Draft it as a v0.8+ study.
4. **RCD over CNAM.** Prefer signed RCD claims; render CNAM as unverified.

## 6. Status of the prototype

siphon-rs PR #123 adds `sip-identity` PASSporT signing (feature `sign`), round-tripped through the
existing verifier. It is the concrete artifact behind path (a)/(c). The gateway does not yet call
it (that is an operator-gated outbound step, deliberately not enabled by default); the findings
above are the plan for when it does.
