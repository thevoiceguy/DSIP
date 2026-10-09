# Number-to-DID attestation — design study

**Status:** design study, 2026-10-08. **Adopted 2026-10-08** as the draft Number Attestation Profile (`v0.11/dsip-number-attestation-profile-v0.11-draft.md`, spec-gap 110); stage 1 (§10) is done. The text below is kept as the design record;
the profile and spec-gap 110 record where stage 1 departed from it (certificate time). It answers G4
recommendation 3 (`gateway-stir-findings.md` §5, "Pursue (c)") and G§11 path (c).

**The one-sentence version.** The holder of a number's STIR authority signs a short-lived statement, "this number
is used by this DID". The DID document says the same thing back. Clients verify both offline against the STIR
certificate roots the PSTN already uses. The number stays an alias, and the DID stays the identity.

## 1. The two questions

A phone number is used in DSIP in two directions, and they need different things:

| | question | who asks | today |
|---|---|---|---|
| **Entitlement** (DID → number) | "Is this DSIP caller entitled to show +1 555 123 4567?" | a DSIP callee; a gateway asserting STIR outbound | not answerable: G§11 path (b), `gateway.downgraded identity-not-assertable` |
| **Discovery** (number → DID) | "I dialled +1 555 123 4567: which DSIP identity is that?" | a DSIP caller; a gateway receiving a PSTN call | gateway configuration only |

Both rest on one artifact, the **binding** (§3). Discovery adds a way to find it (§6).

## 2. Principles (inherited, not new)

1. **The number is an alias (§8.2), the DID is the identity.** A binding answers "which DID uses this number". It
   never makes the carrier the identity's authority. The DID document remains authoritative for endpoints, keys and
   delegations (§8.1 step 4).
2. **No new PKI.** The number's authority is whoever holds a STIR certificate (RFC 8226) whose TNAuthList covers it:
   a carrier, a CPaaS provider, or an enterprise holding a delegate certificate (RFC 9060). DSIP trusts the same
   STI-CA list the PSTN does (SHAKEN governance), and adds no trust registry of its own.
3. **Two-way, or nothing.** The number's authority says "N → DID", and the DID document says "DID → N". Either side
   alone proves nothing:
   - a carrier cannot attach a number to an identity that never claimed it;
   - an identity cannot claim a number its carrier never assigned.
4. **Verify offline, transport anywhere.** A binding is a signed object, so it can travel in an invite, a DID
   document, a DHT hint or a transparency log. Transport confers no authority (§8.1 step 6).
5. **Explain the basis (§18.1).** Clients render "number attested by *Carrier* for this identity", never a generic
   badge.

## 3. The binding

A JWS in compact serialization, signed `ES256` by the key of a STIR certificate whose TNAuthList covers `tn`. That
is the same key type and the same chain that already sign SHAKEN PASSporTs, so a carrier's STIR signer can issue
bindings with no new key material.

```
protected: { "alg": "ES256", "typ": "dsip-tn-binding+jwt", "x5u": "https://cr.carrier.example/sti.pem" }
payload:   { "tn": "+15551234567",
             "did": "did:web:alice.example",
             "iat": 1791430000,
             "exp": 1791516400,
             "jti": "01J9…",                                   // a ULID
             "status": "https://status.carrier.example/tn/01J9…" }  // optional (§18.3)
```

- **`tn`** is E.164, digits only after `+`. A binding names one number. Ranges stay in certificates; bindings stay
  per number, so revocation is per number.
- **`exp − iat` ≤ 7 days** (proposed; spec-gap draft B). Porting a number out is the main way a binding becomes
  wrong, and short expiry bounds that window without depending on a status service. A carrier renews automatically
  while the subscriber keeps the number.
- **Signature over bytes** (§10.2): the compact JWS is carried as is and verified on its bytes, never re-serialized.
- **The certificate rule** is RFC 8226's. The chain must lead to a trusted STI-CA, the leaf's TNAuthList must cover
  `tn` (by number, by range, or by SPC with an authority lookup), and the certificate must be valid at `iat`.

**Back-reference.** The DID document lists the number:

```json
"alsoKnownAs": ["tel:+15551234567"],
"service": [{ "id": "#tn", "type": "DSIPNumberBinding", "serviceEndpoint": "https://alice.example/tn-bindings" }]
```

`alsoKnownAs` is the "DID → N" half. The service endpoint serves the current bindings, so anyone holding the DID can
fetch the proof of the number. For `did:key` subjects, which have no document to edit, the subject's own Pkarr
packet (DHT Hints §9) carries a `_tn` TXT record with the number, signed by the identity key.

### Verification (the `check` a vector suite would pin)

Given a binding, a DID, a time and a trust list, the checks run in this order and the first failure is reported:

1. Parse: compact JWS, `typ` is exact, `alg` is `ES256` → `malformed`
2. Fetch or take `x5u`; chain to a trusted STI-CA → `untrusted-certificate`
3. The signature verifies over the JWS signing input → `signature`
4. TNAuthList covers `tn` → `not-authorized-for-tn`
5. `iat ≤ now < exp`, `exp − iat ≤ 7 d`, the certificate valid at `iat` → `expired` | `lifetime-too-long`
6. `did` equals the DID being checked → `did-mismatch`
7. The DID document's `alsoKnownAs` (or the `_tn` record) contains `tel:` + `tn` → `not-claimed-by-did`
8. Status, when the relying party's policy requires it (§18.3) → `revoked`

Steps 1–6 are offline given the certificate chain. Step 7 is a normal DID resolution. Step 8 is optional, and is
where a bank or a regulated tier would differ from a consumer client.

## 4. Entitlement: a DSIP caller showing a number

The caller adds the binding to the invite's existing `identity.claims[]`. This is the `tel` claim type that G§5
registered, with one new field:

```json
{ "type": "tel", "number": "+15551234567", "binding": "<compact JWS>" }
```

- A `tel` claim **with `binding`** is the caller's own number, verified by §3 against the envelope's signing
  identity. A `tel` claim **with `verifier`** is G§5's gateway claim for a PSTN caller. Clients render the two
  differently:
  - *"+1 555 123 4567 · number attested by Carrier Example for this identity"*
  - *"+1 555 123 4567 · PSTN caller, gateway attested by gw.example · STIR attestation A"*
- A claim whose binding fails is dropped, and the number is not shown as attested. Like any unverified claim
  (§18.2), the number may still be shown as "(unverified)".
- **Trust tier (§19.1).** A verified binding is evidence of a number held under a real subscriber relationship.
  Proposed: it may count as Tier 3 (domain-bound) for first-contact policy, as a business's `did:web` does. Whether
  it should is a policy choice (spec-gap draft D).

**Toward the PSTN (a gateway asserting outbound).** A gateway carrying a DSIP caller to the PSTN sees a verified
binding for the `From` number, signed by the number's own authority. Whether that lets the gateway sign a SHAKEN
PASSporT with `attest: A` is a SHAKEN governance question, not a DSIP one: A requires the signing provider to know
the customer and the customer's right to the number (spec-gap draft A). The conservative path needs no new
governance. The number's carrier issues the gateway operator an RFC 9060 delegate certificate for the subscriber's
numbers (G§11 path c), and the binding is how the gateway confirms, per call, that this DSIP identity is the one the
number belongs to.

## 5. Why this beats a SIM swap

A number moved to a new DID, legitimately by a port or a new subscriber, or illegitimately by a carrier-level
hijack, does not inherit the old identity. Contacts who stored the DID see a **different identity** behind a familiar
number, and the client says so, the way a messenger warns about a changed safety number:

> *+1 555 123 4567 now belongs to a different identity (number attested by Carrier B since 3 Oct). Your contact
> "Alice" is did:web:alice.example.*

Today a SIM swap silently inherits everything the number unlocks. Here the attacker gains the number's routing, not
the person's identity.

## 6. Discovery: number → DID

There is no global, portability-aware directory that a caller can query (user ENUM, RFC 6116, was never deployed
publicly), and the number-portability database is a paid carrier resource. Three ways in, in order of preference:

1. **Published by the subject, carried as a hint.** The subject publishes its binding on the hints tier, keyed by
   the number: an overlay record or a Pkarr packet whose key is derived from `tn`. The DHT stays a hints tier: the
   reader verifies the binding (§3) and then resolves the DID, so a forged or stale record costs a failed lookup,
   never a misroute. This needs no carrier cooperation beyond issuing the binding.
2. **Served by the number's authority, logged.** A carrier serves bindings for the numbers it holds at
   `https://<carrier>/.well-known/dsip/tn/<E.164>`, and enters them in an Alias Transparency log (T§): the alias is
   `tel:+15551234567` and the value is the DID. The log makes a carrier's answers auditable, so it cannot show a
   different DID to one caller. The caller still has to know the carrier, so this route suits enterprises and
   carriers who route their own customers.
3. **Presented in a call.** The caller's binding (§4) teaches the callee the number-to-DID mapping for future calls.

**Privacy is the hard part.** The number space is small: about 10¹⁰ numbers for NANP. Any lookup keyed by the
number, even hashed, can be enumerated: try every number, learn every DSIP user and their DID. That makes a ready
target list for spam, whatever `first contact` (§19.4) then refuses. Proposed defaults (spec-gap draft C):

- **Discoverability is opt-in.** Without it, a binding is only presented (route 3) and served from the DID document
  to someone who already holds the DID, and is never published keyed by the number.
- Published routes are rate-limited by the server, and the T§ log blinds its labels (VRF) so the log itself cannot
  be enumerated. Neither stops a patient enumerator of route 1. That is a stated limitation, not a solved one.
- Discoverable or not, an unsolicited call still faces first contact. Being findable is not being reachable.

## 7. Porting and conflicts

- **A clean port.** The losing carrier stops renewing, and revokes where it runs a status service. The gaining carrier
  issues a new binding. The subject updates `alsoKnownAs`, or the new subscriber adds the number to their own.
- **Two valid bindings for one number** (the port window: both carriers' certificates still cover it, both bindings
  unexpired). The binding whose DID currently lists the number in `alsoKnownAs` wins; the two-way rule decides
  almost every case. If both DIDs list it, which happens with a hijack or a careless old subscriber, the newer `iat`
  wins and the client shows the identity-change warning (§5). Proposed; spec-gap draft B.
- **Revocation without a status service** is expiry. That is the reason for the 7-day cap.

## 8. Who issues bindings, and why they would

| issuer | holds | motive |
|---|---|---|
| Carrier (mobile/fixed) | SPC-level STIR cert | anti-spoofing; branded calling it already sells; SIM-swap reduction is a fraud-loss saving |
| CPaaS (Twilio, Telnyx, Bandwidth) | SP STIR cert for the numbers they rent | a per-number API product; their customers are businesses that want verified outbound identity |
| Enterprise | RFC 9060 delegate cert for its range | its own staff numbers bound to its own `did:web`, with no carrier in the loop after delegation |

The binding API is small: given a number the customer holds, and a DID that lists it, sign §3 and renew it every few
days. A CPaaS provider is the realistic first issuer, because its customers already authenticate numbers through it.

## 9. What changes where (if adopted)

- **New draft profile, Number Attestation (`N§`):** §3 (binding and its checks), §4 (claim and rendering), §6 (the
  discovery routes and the opt-in), §7 (conflict rule).
- **Core:** §8.2 lists `tel:` aliases and the binding as their alias method; §18.1 gets the rendering line; §24 gets
  the `DSIPNumberBinding` service type and the `binding` field of the `tel` claim; A.8 notes it.
- **Gateway Profile:** G§11 path (c) points here; G§3.2 may route an inbound PSTN call by a discovered binding
  instead of static configuration.
- **Alias Transparency:** T§3 normalization for `tel:` labels (E.164, digits only).
- **Vectors:** `tn-binding/`. A test STIR PKI is generated by the vector generator (a root, an SPC certificate, a
  delegate certificate, and certificates that are out of range, expired or wrongly signed), so verdicts are
  offline and deterministic. Each §3 step gets accepting and refusing cases, and the order of the checks is pinned.
  Three-way parity as always.

## 10. Stages

1. **Vectors and a verifier.** A generated test PKI, the §3 checks in Python, Rust and TypeScript, three-way parity.
   No carrier is needed.
2. **DSIP-to-DSIP.** `dsip call` presents a binding, and the callee verifies and renders it. The demo also shows a
   binding for a number the certificate does not cover being refused, and the identity-change warning (§5).
3. **Discovery.** Route 1 on `dsip-node` (a number-keyed hint, opt-in), and route 2 as a T§ log entry.
4. **Gateway.** Inbound routing by binding; outbound assertion under a delegate certificate (needs `sip-identity`
   PASSporT signing, siphon-rs PR #123).
5. **Pilot** (needs a partner). One CPaaS provider issues real bindings for a handful of numbers. This is the stage
   that turns a design into a carrier conversation.

## 11. Spec-gap drafts (to file if the design is adopted)

**A. G§11 / SHAKEN — may a gateway attest `A` on a carrier's binding?** The binding is the number authority's own
statement that this DSIP identity uses the number, and the DSIP invite proves the caller holds that identity.
Choices:
- (a) yes, `A`, the binding standing in for the subscriber relationship;
- (b) `B`, the gateway knowing the customer but not owning the number;
- (c) only under an RFC 9060 delegate certificate for the number.

Proposed: (c) normative and (a) raised with the SHAKEN governance bodies. **Decided (stage 4, 2026-10-09): (c)**,
and (a) is not raised: a binding becomes the basis for an RFC 9447 authority token, so a gateway obtains a
short-lived delegate certificate by ACME (RFC 9448) instead. Spec-gap 110, item A.

**B. N§3 / N§7 — binding lifetime and conflicts.** Choices for the maximum lifetime: 24 h, 7 d or 30 d. Shorter
bounds the port-out window; longer survives an issuer outage. Proposed: 7 d. For two valid bindings, the two-way
rule decides first, and the newer `iat` decides when both DIDs claim the number, with the identity-change warning.

**C. N§6 — discoverability default.** Number-keyed lookups can be enumerated in a 10¹⁰ space. Choices: opt-in,
opt-out, or never publish keyed by number. Proposed: opt-in. Stated as a limitation that is instrumented and not
solved, like Sybil resistance (§3.2).

**D. §19.1 — the tier of a verified number.** Choices: Tier 1 (a number proves little), Tier 3 (like a domain), or
deployment policy. Proposed: deployment policy, with Tier 3 as the example, because numbers are cheap to rent in
bulk and that is exactly how robocallers work.

## 12. Open questions for the user

1. Is a carrier or CPaaS pilot (stage 5) realistic, and through whom? Twilio is already on the testbed's SIP path.
2. Should bindings also cover **short codes and toll-free numbers**? They have their own registries and STIR
   treatment.
3. Should this wait for the RCD work to stabilise (signed caller name and logo)? A binding could carry RCD-style
   `nam`, which would merge §18.2 brand claims with number attestation.
