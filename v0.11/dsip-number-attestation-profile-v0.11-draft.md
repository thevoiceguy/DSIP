# Draft: DSIP Number Attestation Profile (`tn-binding/0.1`)

**Status:** DRAFT, companion profile to DSIP v0.11. Cite as `N§n`. Adopted 2026-10-08 from the design study
`impl/docs/number-attestation-design.md` (spec-gap 110). Vectored so far (`impl/vectors/tn-binding/`):
- stage 1: N§3, the binding and its checks;
- stage 2: N§4, the claim and its rendering, and N§5, the identity-change warning;
- stage 3: N§6 route 1, on a `dsip-node`, and N§7, choosing between bindings.

The exact text of the rendered lines is the vector suite's. Later stages will vector the rest.

A phone number is an alias (§8.2), and a DID is an identity. This profile lets the holder of a number's STIR
authority sign a short-lived statement, the **binding**: "this number is used by this DID". The DID document says
the same thing back. A client verifies both offline, against the STIR certificate roots the PSTN already uses.

The profile does not make a carrier an identity's authority. The DID document stays authoritative for endpoints,
keys and delegations (§8.1). A binding answers one question: which DID uses this number.

## N§1 Scope

The profile defines:

- the **binding**, a signed object, and the order of the checks that verify it (N§3);
- a `tel` identity claim that carries a binding, and how a client renders it (N§4);
- the warning a client shows when a number moves to another identity (N§5);
- how a caller finds the DID behind a number (N§6);
- what happens when a number is ported, and when two bindings conflict (N§7).

**Numbers in scope.** Only E.164 numbers: a `+`, then 2 to 15 digits, the first not `0`. Short codes are not E.164
and are out of scope. Toll-free numbers that are written in E.164 pass the syntax checks. Their issuers and their
STIR treatment are an open question (spec-gap 110, item E).

## N§2 Principles

1. **The number is an alias and the DID is the identity** (§8.2). A binding never moves authority over an identity
   to the carrier.
2. **No new PKI.** A number's authority is whoever holds a STIR certificate (RFC 8226) whose TNAuthList covers the
   number. That can be a carrier, a CPaaS provider, or an enterprise with a delegate certificate (RFC 9060). A
   relying party trusts the STI-CA list the PSTN trusts (SHAKEN governance) and keeps no trust registry of its own.
3. **Both directions, or nothing.** The number's authority says "number → DID". The DID document says "DID → number".
   Neither half proves anything alone:
   - a carrier cannot attach a number to an identity that never claimed it;
   - an identity cannot claim a number its carrier never assigned.
4. **Verify offline; carry anywhere.** A binding is a signed object. It may travel in an invite, a DID document, a
   DHT hint or a transparency log. Where it travelled confers no authority (§8.1).
5. **Explain the basis** (§18.1). A client names who attested the number, and never shows a generic badge.

## N§3 The binding

### N§3.1 Format

A binding is a JWS (RFC 7515) in compact serialization: three base64url segments joined by `.`.

**Protected header.** A JSON object:

| member | value |
|---|---|
| `alg` | exactly `ES256` (ECDSA P-256 with SHA-256, the PASSporT algorithm) |
| `typ` | exactly `dsip-tn-binding+jwt` |
| `x5u` | an `https://` URL serving the signing certificate chain in PEM, leaf first (as for PASSporT, RFC 8225 §5) |

A header with a `crit` member is malformed: this profile defines no critical header parameters. Other header
members are ignored.

**Payload.** A JSON object:

| member | value |
|---|---|
| `tn` | the number: `+`, then 2–15 digits, the first not `0` |
| `did` | the DID that uses the number; a string that starts `did:` |
| `iat` | when it was issued: integer Unix seconds, ≥ 0 |
| `exp` | when it expires: integer Unix seconds, greater than `iat` |
| `jti` | a ULID, unique per issuer |
| `status` | optional: an `https://` URL where the issuer reports whether the binding is revoked (§18.3) |

Other payload members are ignored.

- **One number per binding.** Ranges stay in certificates, and bindings stay per number, so an issuer revokes one
  number at a time.
- **Lifetime.** `exp − iat` is at most **604,800 seconds (7 days)**. Porting a number out is the main way a binding
  becomes wrong. A short expiry bounds that window without relying on a status service, and an issuer renews
  automatically while the subscriber keeps the number.
- **Signature over bytes** (§10.2). A verifier checks the signature over the bytes it received, and decodes the
  segments only after that. Nothing is re-serialized.
- **JSON** in both segments is UTF-8 I-JSON (RFC 7493). Integers have no fraction or exponent (§10.3).

### N§3.2 The certificate

The rules are RFC 8226's, used as SHAKEN uses them:

- **Path.** The chain at `x5u` leads to a certificate on the relying party's STI-CA trust list. Every certificate
  on the path is valid at the time of verification.
- **Algorithms.** Every certificate on the path is signed with ECDSA P-256 and SHA-256, and holds a P-256 key.
- **Coverage.** The leaf certificate has a TNAuthList (RFC 8226 §9), and the TNAuthList covers `tn`. It can cover the
  number in three ways:
  - **`one`**: the entry is the number;
  - **`range`**: the number falls in the range;
  - **`spc`**: the relying party's lookup assigns the number to that Service Provider Code (for SHAKEN, the number
    portability data).
- **Nested coverage.** Any other certificate on the path that has a TNAuthList must cover `tn` too. A delegate
  certificate (RFC 9060) therefore cannot attest a number its issuer could not.

### N§3.3 The back-reference

The DID document claims the number:

```json
"alsoKnownAs": ["tel:+15551234567"],
"service": [{ "id": "#tn", "type": "DSIPNumberBinding", "serviceEndpoint": "https://alice.example/tn-bindings" }]
```

- **`alsoKnownAs`** holds the string `tel:` followed by `tn`, exactly. This is the "DID → number" half.
- **The `DSIPNumberBinding` service**, which is optional, serves the current bindings as a JSON array of compact
  JWS strings. Anyone holding the DID can fetch the proof of its numbers there.
- **A `did:key` subject** has no document to edit. It claims a number with a `_tn` TXT record holding `tn` in its own
  Pkarr packet (DHT Hints Profile §9), which its identity key signs. This route is not vectored yet.

### N§3.4 Verification

A relying party verifies a binding against four things:

- the DID it is checking;
- that DID's resolved document;
- its clock;
- its policy: the trust list, the SPC lookup, and whether to require a status check.

The checks run in this order. **The first one that fails gives the reason.**

1. **`malformed`.** The binding is not a well-formed N§3.1 object:
   - not three base64url segments;
   - the header or payload is not an I-JSON object;
   - the signature segment is empty;
   - any member in the N§3.1 tables is missing or has the wrong value or type;
   - `crit` is present.
2. **`untrusted-certificate`.** Any of:
   - the chain cannot be fetched from `x5u`;
   - a certificate does not parse;
   - the path does not reach the trust list;
   - a certificate on the path is not valid now;
   - a certificate breaks the N§3.2 algorithm rules;
   - an issuing certificate is not a CA;
   - a path length constraint is exceeded;
   - a certificate has a critical extension other than basicConstraints, keyUsage and TNAuthList;
   - a TNAuthList is not well-formed.
3. **`signature`.** The leaf key does not verify the signature over the JWS signing input (the ASCII bytes of the
   header segment, `.`, and the payload segment).
4. **`not-authorized-for-tn`.** The leaf has no TNAuthList, or a TNAuthList on the path does not cover `tn`.
5. **Time**, checked in this order:
   - **`lifetime-too-long`**: `exp − iat` is more than 604,800 seconds.
   - **`not-yet-valid`**: `iat` is more than 300 seconds ahead of the clock (the §12.9 tolerance).
   - **`expired`**: the clock has reached `exp`.
6. **`did-mismatch`.** `did` is not the DID being checked, compared exactly.
7. **`not-claimed-by-did`.** The DID's document does not list `tel:` + `tn` in `alsoKnownAs`.
8. **Status**, only when the relying party's policy requires it (§18.3):
   - **`status-unavailable`**: the binding has no `status` URL, or no answer came from it, or the answer is
     neither "good" nor "revoked" (a required check fails closed);
   - **`revoked`**: the issuer reports the binding revoked.

Steps 1–6 need only the certificate chain. Step 7 is ordinary DID resolution. Step 8 is where policies differ: a
bank or a regulated tier may require it, and a consumer client usually does not.

A verified binding gives the relying party the number, the DID, the binding's expiry, and **who attested it**. That
is the leaf certificate subject's first organization name, or its first common name when it has no organization.

## N§4 Entitlement: a DSIP caller showing a number

A caller adds the binding to the invite's existing `identity.claims[]`, as a `tel` claim (G§5) with a `binding`
member:

```json
{ "type": "tel", "number": "+15551234567", "binding": "<compact JWS>" }
```

- **The claim is checked against the envelope.** A receiver verifies the binding (N§3.4) against the DID of the
  envelope's signing identity, and `number` must equal the binding's `tn`.
- **A failed claim is dropped.** The number is not shown as attested. Like any unverified claim (§18.2), it may
  still be shown marked "(unverified)".
- **Rendering** (§18.1). A `tel` claim with a `binding` is the caller's own number. A `tel` claim with a `verifier`
  is G§5's gateway claim for a PSTN caller. Clients render them differently:
  - *"+15551234567 · number attested by Carrier Example for this identity"*
  - *"PSTN caller +15551234567"*, with the basis *"Gateway attested by gw.example · STIR attestation A (verified)"*

  A claim with a string `verifier` is a gateway claim, even when it also carries a `binding`. A binding claim
  never changes the identity's own basis line.
- **Trust tier** (§19.1). How much a verified binding counts for first contact is deployment policy (spec-gap 110,
  item D). Treating it like a domain-bound identity (Tier 3) is a reasonable choice for a business. Numbers are
  cheap to rent in bulk, which is how robocallers work, so a consumer client may give it less.
- **Toward the PSTN.** A gateway that carries a DSIP caller to the PSTN may assert the `From` number only under a
  STIR certificate that covers it. Normally that is an RFC 9060 delegate certificate, which the number's carrier
  issues to the gateway operator (G§11, path c). The binding tells the gateway, per call, that this DSIP identity is
  the one the number belongs to. Whether a binding alone lets a gateway attest `A` is a question for SHAKEN
  governance, not for DSIP (spec-gap 110, item A). N§4.1 says what the gateway does.

### N§4.1 Gateways

A DSIP↔PSTN gateway (Gateway Profile 1.0, `G§`) is a relying party on both sides of a crossing. This section adds
to G§3, G§5 and G§7 what a bound number changes; the conformance suite pins the rules (`tn-binding/assert-*`,
`passport-*`).

**Naming the destination.** A DSIP caller that wants a PSTN number dials the gateway: the invite's `to` is the
gateway's DID, and its `destination` member is the number as a tel URI, `tel:` + E.164. A callee that is not a
gateway ignores `destination`. A client that was asked for `tel:+…` first looks the number up (N§6); only a number no
binding resolves is a PSTN number (spec-gap 111).

**Outbound: a bound number toward the PSTN.** The gateway checks the invite's `tel` claims as any receiver does
(N§4, against the envelope's signing identity). The first attested claim gives the number.

1. **With no attested claim** the gateway presents its own identity on the SIP leg and crosses with
   `gateway.downgraded` `identity-not-assertable` (G§7). It never presents a number a caller did not prove.
2. **With an attested claim** the SIP `From` is the number: the caller proved to the gateway that it is the
   number's. The gateway signs a SHAKEN PASSporT (RFC 8225, RFC 8588) for the call **only** when its own STIR
   certificate (G§11 path c: normally an RFC 9060 delegate certificate) chains to the gateway's trust list, every
   TNAuthList on that path covers the number (N§3.2), and the signing key is the leaf's. The PASSporT carries
   `attest: A`, `orig.tn` the caller's number, `dest.tn` the dialled one, `iat` the gateway's clock and an `origid`
   the gateway makes per call (RFC 8588 §4); it travels as the `Identity` header, `<token>;info=<x5u>;alg=ES256;ppt=shaken`
   (RFC 8224 §4).
3. **Otherwise** the number is presented unsigned (G§11 path b) and the crossing is downgraded
   `identity-not-assertable`. The level is `A` or nothing: a gateway that cannot vouch for the number under its
   certificate does not attest `B` on the strength of a binding (spec-gap 110, item A).

**Inbound: a PSTN caller's PASSporT.** The gateway verifies an inbound INVITE's `Identity` header before it renders
the G§5 claim (RFC 8224 §6.2): the header reads, `alg` and `ppt` are ones it implements (an unsupported header is
ignored, RFC 8224 §6.2.3), the PASSporT reads, `orig` is the `From` (a mismatch discards the PASSporT whole, G§5),
`dest` holds the dialled number, `iat` is within 60 s, the `x5u` is the `info` URI, the chain reaches the trust
list, the signature holds, and, for `attest` `A` only, every TNAuthList on the path covers `orig`. A PASSporT that
reads but fails a later step keeps its level with `verified: false`. Numbers are compared canonically (RFC 8224
§8.3): without the `+` and visual separators.

## N§5 A number that moves to another identity

A client that holds a contact's DID and number, and then verifies a binding of that number to a **different** DID,
**MUST** say so. It renders the new identity as new, never as the stored contact:

> *+15551234567 now belongs to a different identity (number attested by Carrier B since 2026-10-03). Your contact
> "Alice" is did:web:alice.example.*

A client says this only when no stored contact listing the number has the attested DID.

A legitimate port or a carrier-level hijack moves the number's routing. It never moves the person's identity.

## N§6 Discovery: number → DID

There are three ways for a caller to find the DID behind a number, in order of preference:

1. **A binding the subject publishes on a hints node.**
   - A `dsip-node` holds bindings by number:
     - `PUT /dsip/v1/tn/<tn>` stores one;
     - `GET /dsip/v1/tn/<tn>` answers `{"bindings": [...]}`.
   - Before it stores a binding, a node checks steps 1–5 of N§3.4: everything that needs no DID resolution. It
     holds at most four live bindings per number, one per DID, keeping the newest (the vector README pins the
     rules).
   - A reader verifies every returned binding in full, each against its own DID's document, and chooses by N§7.
     A forged or stale binding costs a failed lookup, never a misroute.
   - The node is a hints tier (§8.1): it can withhold a binding, but never forge one.
   - In this draft nodes do not replicate bindings to each other. A publisher puts its binding on several nodes,
     as it would on several Pkarr relays, and renews it with each new binding.
2. **A binding the number's authority serves**, at `https://<authority>/.well-known/dsip/tn/<tn>`, and enters in an
   Alias Transparency log (T§) under the label `tel:` + `tn`. The log makes the authority's answers auditable.
3. **A binding presented in a call** (N§4). The callee learns the number-to-DID mapping for future calls.

### N§6.1 A gateway routing a PSTN call to a bound number

An inbound PSTN call names a number, and the gateway must find the DSIP identity to invite (G§3.2's "resolved DSIP
target"). The operator's own table decides first: it is the operator's statement about its own trunk, and a binding
never overrides it. When the table names nothing, the gateway resolves the number by route 1 (a lookup on the hints
nodes it is configured with), verifies every returned binding in full against its own DID's document, and chooses
by N§7. When neither yields an identity, the gateway refuses the INVITE `identity.unknown` (404, Q.850 cause 1;
G§4.2). The G§5 `tel` claim on the DSIP invite is the same either way; only the target changed. The suite pins the
rule (`tn-binding/route-*`).

**Discoverability is opt-in** (spec-gap 110, item C). Without it, a binding is only presented (route 3), or served to
someone who already holds the DID (N§3.3). It is never published under a key derived from the number.

The number space is small: about 10¹⁰ numbers for NANP. Any lookup keyed by the number, even hashed, can be
enumerated. Servers rate-limit published routes, and the transparency log blinds its labels. Neither stops a patient
enumerator of route 1. That limitation is stated and instrumented, not solved, as with Sybil resistance (§3.2).
Being findable is not being reachable: an unsolicited call still faces first contact (§19.4).

## N§7 Porting and conflicts

- **A clean port.** The losing issuer stops renewing, and revokes the binding if it runs a status service. The
  gaining issuer binds the number again, for the same DID or for a new subscriber's DID.
- **Two verified bindings for one number.** While a port is in progress, both carriers' certificates may still cover
  the number, and both bindings may be unexpired:
  - **One DID claims the number.** The binding whose DID lists it in `alsoKnownAs` wins. Step 7 of N§3.4 already
    decides almost every case.
  - **Both DIDs claim it.** This happens after a hijack, or when the old subscriber never removed it. The binding
    with the newer `iat` wins; on a tie, the smaller binding text wins. The client names the other identities that
    still hold verified bindings for the number. When a stored contact is involved, it also shows the N§5 warning
    (spec-gap 110, item B).
- **Revocation without a status service** is expiry. That is why the lifetime cap exists.

## N§8 Who issues bindings (informative)

| issuer | holds | motive |
|---|---|---|
| Carrier (mobile or fixed) | an SPC-level STIR certificate | anti-spoofing; the branded calling it already sells; fewer SIM-swap fraud losses |
| CPaaS provider | an SP STIR certificate for the numbers it rents | a per-number API for business customers |
| Enterprise | an RFC 9060 delegate certificate for its range | its staff numbers bound to its own `did:web` |

## N§9 Registries

- **Media type** of a binding's `typ`: `dsip-tn-binding+jwt`.
- **DID service type** (§24): `DSIPNumberBinding`.
- **`tel` claim member** (G§5, §24): `binding`, a compact JWS (N§4).
- **Invite member** (§24, the invite schema): `destination`, a tel URI naming the PSTN number asked of a gateway
  (N§4.1).
- **Verification reasons** (local, never sent on the wire):
  - `malformed`
  - `untrusted-certificate`
  - `signature`
  - `not-authorized-for-tn`
  - `lifetime-too-long`
  - `not-yet-valid`
  - `expired`
  - `did-mismatch`
  - `not-claimed-by-did`
  - `status-unavailable`
  - `revoked`
- **Gateway reasons** (local; N§4.1, the conformance suite's `passport` and `assert` checks):
  - a PASSporT: `no-identity-header`, `malformed`, `unsupported`, `orig-mismatch`, `dest-mismatch`, `stale`,
    `x5u-mismatch`, then `untrusted-certificate`, `signature`, `not-authorized-for-tn` as above;
  - an assertion: `no-binding`, `bad-destination`, `no-certificate`, `key-mismatch`, and `untrusted-certificate`,
    `not-authorized-for-tn` as above. A dropped claim's reason is reported as the N§4 check gave it.

## N§10 Security and privacy considerations

- **Number authorities can lie, within limits.** A carrier can bind a number it controls to any DID that claims the
  number. It cannot bind a number to a DID that never claimed it, and it cannot make a DID it does not control call
  anyone.
- **A port or a hijack** moves a number's routing to another DID. It never moves an existing identity, and N§5
  makes the change visible.
- **Enumeration** is the cost of discovery (N§6), so discoverability is opt-in.
- **A gateway signs within its certificate.** A gateway that signs PASSporTs (N§4.1) can assert only the numbers
  its STIR certificate covers, and only for a caller who proved the number with a binding. A compromised gateway
  key is a compromised delegate certificate, no more: the carrier that issued it revokes it.
- **Trust lists** are the relying party's choice. A deployment outside SHAKEN's reach (another country's STIR
  ecosystem, or an enterprise's own CA for internal numbers) configures its own list, and a binding means exactly
  what that list's certificates mean.
