# Outline: DSIP Presence Profile (`presence/0.1`)

**Status:** superseded by the draft `v0.17/dsip-presence-profile-v0.17-draft.md` (2026-10-22), which pins P§3–P§5 and P§8 with vectors; kept for its history. Spec-gaps 134–137 decided 2026-10-19 as drafted here. Candidate companion profile for v0.17, cite as `P§n` once
adopted. It collects spec-gaps 134–137 (`impl/docs/spec-gaps.md`). Nothing here is implemented or pinned. Per rule 1,
each section turns into vectors before any code, and the section's vector plan says which. v0.16 is final, so the
draft itself goes into `v0.17/` when that version is assembled.

The core stays as it is: presence is optional (§9.1), private by default (§9.2), carried by `subscribe`/`notify`
(§9.3), and never published to the DHT (§8.5). This profile fills in what §9 leaves open. That covers how a device's
signed record reaches its authority, how several devices make one identity's presence, which states exist, and what
each subscriber is shown.

## P§1 Scope

This profile defines:

- the **`publish`** of a device's signed presence record to its authority (P§3);
- **per-device records** and the rule that combines them into an identity's presence (P§4);
- the **`dsip-presence-state`** registry and its fallback (P§5);
- **audiences**: what detail a subscriber is shown, chosen by the authority from the records it holds (P§6);
- **time-boxed shares** of presence (P§7);
- the profile's **timers** (P§8).

Out of scope: presence bridged to SIP SIMPLE, XMPP or carrier presence; calendar or meeting integration; presence
encrypted to subscribers (an open question, P§10); enterprise policy distribution (a deployment pattern, P§10).

## P§2 Principles

1. **Reachability never depends on presence** (spec-gap 137). No relay, mailbox or other service may require presence
   publication as a condition of delivery. Delivery decisions use bindings (§13.2), never presence records.
2. **No presence oracle.** A response to a party not authorized for the target's presence MUST NOT vary with the
   target's presence state. This extends §9.3's anti-enumeration rule beyond `subscribe`.
3. **The authority carries presence and never authors it** when a subject-signed record exists (P§3). What it asserts
   by itself (§9.3) is labelled as such, and only used when no valid record exists.
4. **Signed by the device that knows.** Each record is signed by the device it describes. Nothing signs for another
   device, and the identity key stays offline (§7.3).

## P§3 Publishing (spec-gap 134)

- A new message, `publish`, sent by a device over its binding to its authority (§13.2). Its payload is one §9.4
  record (P§4 form). The authority answers `accepted` or `error`:
  - `presence.signer-mismatch`: the record's `device` is not the envelope signer;
  - `presence.not-delegated`: the signer's delegation lacks the capability (see open question: `dsip.signaling`, or a
    new `dsip.presence`);
  - `policy.subscription-lifetime`, or a new token, when `expires_at` exceeds the P§8 cap.
- The authority keeps the latest record per `(subject, device)` until its `expires_at`. A newer `seq` replaces it, and
  a lower or equal `seq` is refused (`presence.stale`).
- When a record changes, every authorized subscription to the subject gets a `notify` whose `body` is the record set
  (P§6 decides which records each subscriber sees).
- An expired record is dropped. With no valid record left for a device, the authority falls back to §9.3 assertion
  for that device, and the body says which kind of presence it is.
- A device that unbinds keeps its record until the P§8 grace timer runs out, so a phone changing networks doesn't
  flicker `offline`.

**Vector plan.** `state/presence-publish-accepted`, `-replaces-by-seq`, `-stale-seq-refused`,
`-signer-mismatch`, `-expiry-falls-back-to-assertion`, `-unbind-grace`, `-rebind-within-grace`;
`semantic/publish-lifetime-over-cap`.

## P§4 Several devices, one identity (spec-gap 135)

- The §9.4 record gains `device`, the DID of the device it describes, which MUST equal the signer. `seq` is ordered per
  `(subject, device)`.
- A `notify` body for presence carries the current record of every device the subscriber may see. The subscriber's
  client computes the identity's state from them; the authority doesn't.
- **Combining rule** (deterministic, so every subscriber agrees): the identity takes the highest-ranked state among its
  valid records. Starting order: `dnd` > `busy` > `available` > `away` > `offline`. An unknown state ranks as its P§5
  fallback, and `offline` applies only if every device is `offline` or has no valid record.
- A v0.16 record without `device` counts as one unnamed device.

**Vector plan.** A new `presence-aggregate` vector kind: inputs are record sets, the output is the combined state.
`presence/aggregate-busy-beats-idle`, `-dnd-wins`, `-all-offline`, `-expired-ignored`, `-unknown-state-fallback`,
`-legacy-record-no-device`; `semantic/presence-seq-per-device` (two devices whose `seq` counters interleave, neither
dropped).

## P§5 States (spec-gap 136)

- Registry `dsip-presence-state`, shape `[a-z][a-z0-9-]*`, initial values `available`, `busy`, `away`, `dnd`,
  `offline`. It's open: implementations MUST NOT reject an unknown token.
- Fallback: an unknown state is shown as `available` (and ranked as `available` in P§4), with the token displayed
  raw. A newer state must never make a reachable person look unreachable.
- "Invisible" is client behaviour, not a state: an invisible device publishes `offline`, or nothing. P§2.2 is what
  keeps it from leaking.
- Optional fields, shown only at `detailed` (P§6): `activity` (registry `dsip-presence-activity`, initially
  `in-call`, `in-meeting`, `presenting`) and `note` (free text, length cap TBD).

**Vector plan.** `payload/presence-state-unknown-accepted`, `payload/presence-note-over-cap`,
`trust/presence-unknown-state-rendered`.

## P§6 Audiences and detail

- Three detail levels: `basic` (available or unavailable), `standard` (P§5 states), `detailed` (plus `activity` and
  `note`).
- A device may publish one record per audience it shares with, each signed, with the record's `audience` naming it.
  The authority sends each subscriber only the records for that subscriber's audience, as its policy decides from the
  verified identity, `claims` and `capability` (§9.3, unchanged). The authority never edits a record, so a reduced
  view is a separately signed record, never a redacted one.
- A subscriber in no audience gets the uniform `policy.blocked` (§9.3); a device with no record for an audience
  falls back to assertion for that audience, or the profile says it shows nothing (open question).
- The authority sees every audience's records in plaintext. That is accepted (it already sees the bindings), and it is
  why encryption is P§10.

**Vector plan.** `state/presence-audience-selects-record`, `-no-record-for-audience`,
`-blocked-subscriber-uniform`.

## P§7 Time-boxed shares

- A share is a `capability` token (§9.3) the subject's authority issues for one subscriber DID and an audience, with
  an expiry. When the token expires, the subscription ends with a `terminated` notify, reason `policy.terminated`;
  revoking it early does the same.
- Issuing a share is out of band, as for `contact_token` (§19.4): a link, a QR code, or a grant.
- Revocation stops future notifies only. What was already shown can't be recalled, and the profile says so.

**Vector plan.** `state/presence-share-expires`, `-share-revoked`, `-renewal-past-share-expiry-refused`.

## P§8 Timers

| Timer | Default | Bounds | Meaning |
|---|---|---|---|
| Record lifetime | 300 s | 60–3,600 s | A record's `expires_at` minus `issued_at`. Devices refresh before expiry. |
| T-Presence-Grace | 60 s | 0–300 s | After a device unbinds, how long the authority keeps its record before treating the device as `offline`. |
| Publish rate | — | ≥ 5 s between publishes per device | Refused with `policy.rate-limited` beyond it. Keeps presence from being a traffic channel. |

The numbers are placeholders to be argued over before vectors pin them (§9.5's trade-off: short is fresh, long is
cheap).

## P§9 Security and privacy considerations

- Calls, deposits and subscription answers must not leak presence by their reason or timing (P§2.2).
- The authority is trusted with presence plaintext, and not trusted to forge it: a subscriber checks each record's
  signature and delegation (§7.4).
- A record names a device. Showing the per-device breakdown to subscribers reveals how many devices someone has and
  which one is active. Clients SHOULD show the combined state only; the profile could let a device omit `device`
  (open question, at the cost of P§4).
- Presence history is metadata. Authorities SHOULD keep no record past its expiry.

## P§10 Open questions

1. **Capability:** is publishing presence under `dsip.signaling`, or does it need a new `dsip.presence` delegation
   capability (registry `dsip-delegation-capability`)?
2. **Encryption to subscribers.** One route: an MLS group per audience, with presence sealed under its exporter, as
   Messaging Profile activity is (M§11). It reuses existing key distribution and removal; the cost is a group per
   audience, and every share is a membership change. Defer until P§3–P§6 are pinned.
3. **Enterprise policy.** A deployment pattern, not protocol: an organisation runs the `did:web` authority for its
   identities and applies policy there (§9.3 already makes authorization the authority's decision). A signed policy
   document for managed endpoints only matters if endpoints must comply, and a modified client ignores it. Write it
   up as guidance with the operational vs social presence distinction.
4. **A device with no record for an audience:** fall back to assertion, or show nothing?
5. **Messaging:** should a member's presence also travel in its groups (M§11 activity)? That would give a second path
   with its own audiences.

## P§11 Sequence

1. ~~The user decides spec-gaps 134–137.~~ Decided 2026-10-19, as drafted.
2. ~~Write the draft from this outline; write vectors (P§3, P§4 and P§5 first), with Python verdicts.~~ Done 2026-10-22: `presence` is the §9.4 record sent itself (not `publish`, which §22 owns), under `dsip.signaling`, reason category `presence`, timers as drafted.
3. Implement in Rust (`dsip-broadcast`'s authority already holds subscriptions) and in `impl-ts`, until three-way
   parity holds; then fuzz the combining rule (`fuzz.py`).
4. Browser client: publish, show the combined state, settings for audiences and shares.
5. The draft goes into `v0.17/` at assembly.
