# DSIP Presence Profile (`presence/0.1`)

**Status:** DRAFT, companion profile to DSIP v0.17. Cite as `P§n`. It collects spec-gaps 134–137, decided 2026-10-19,
and the choices made 2026-10-22 on the outline (`impl/docs/presence-profile-outline.md`): a device sends its signed
`presence` record itself (no new message), under `dsip.signaling`, with the timers of P§8 and the reason category
`presence` (P§9). P§3–P§5 and P§8 are pinned by vectors; P§6 and P§7 are not yet.

The core stays as it is: presence is optional (§9.1), private by default (§9.2), carried by `subscribe`/`notify`
(§9.3), and never published to the DHT (§8.5). This profile fills in what §9 leaves open: how a device's signed record
reaches its authority, how several devices make one identity's presence, which states exist, and what each subscriber
is shown.

## P§1 Scope

This profile defines:

- how a device **publishes** its signed presence record to its authority (P§3);
- **per-device records** and the rule that combines them into an identity's presence (P§4);
- the **`dsip-presence-state`** registry and its fallback (P§5);
- **audiences**: what detail a subscriber is shown (P§6, not yet pinned);
- **time-boxed shares** of presence (P§7, not yet pinned);
- the profile's **timers** (P§8) and **reason tokens** (P§9).

Out of scope: presence bridged to SIP SIMPLE, XMPP or carrier presence; calendar or meeting integration; presence
encrypted to subscribers (P§11); enterprise policy distribution (a deployment pattern, P§11).

## P§2 Principles

1. **Reachability never depends on presence** (spec-gap 137). No relay, mailbox or other service may require presence
   publication as a condition of delivery or reachability. Delivery decisions use bindings (§13.2), never presence
   records. A callee's own client declining a call is not covered by this rule.
2. **No presence oracle.** A response to a party not authorized for the target's presence MUST NOT vary with the
   target's presence state. This extends §9.3's anti-enumeration rule beyond `subscribe`.
3. **The authority carries presence and never authors it** when a subject-signed record exists (P§3). What it asserts
   by itself (§9.3) is labelled as such, and is used only for a device that holds no valid record.
4. **Signed by the device that knows.** Each record is signed by the device it describes. Nothing signs for another
   device, and the identity key stays offline (§7.3).

## P§3 Publishing (spec-gap 134)

A device publishes by sending its §9.4 `presence` record, signed by itself, to its **authority**: the relay it binds to
(§13.2), which answers `subscribe` for its identity (§9.3). `to` is the authority's DID. Publishing needs no capability
beyond `dsip.signaling`, which every envelope's delegation already carries (§7.4): a device that may bind can already
make the authority assert it `available`, so a record reveals nothing a binding does not.

```json
{
  "dsip": {"core": "1.0", "min_core": "1.0", "profiles": ["interactive-media/1.0"], "extensions": [], "critical": []},
  "type": "presence",
  "id": "01K742SG0000000000PRES0001",
  "from": "did:key:z6MkAlicePhone",
  "to": "did:key:z6MkAliceRelay",
  "subject": "did:web:alice.example",
  "device": "did:key:z6MkAlicePhone",
  "state": "busy",
  "seq": 58,
  "issued_at": 1760000000,
  "expires_at": 1760000300
}
```

**Validity at any receiver** (§12.9). A record is kept and forwarded for its whole lifetime, so like a reachability
hint (spec-gap 96) its age is bounded by `expires_at`, not by the 300 s replay window: a `presence` envelope whose
`expires_at − issued_at` exceeds 3,600 s is invalid (`presence-validity`), an `issued_at` more than 300 s in the future
is invalid (`replay-window`), and one past its `expires_at` is expired. The record's `seq` (below), not its id, decides
whether a re-observed record replaces another.

**Payload rule.** When `device` is present it MUST equal `from`, the signing device (`presence-signer-mismatch`,
reason `presence.signer-mismatch`). A record without `device` is a v0.16-form record (P§4).

**At the authority.** A record comes over the device's binding: traffic from a device that has not bound never reaches
these checks (`transport.hello-required`, §13.2), so the identity in rule 1 is always known. A record that passed the
envelope pipeline is refused with `error` (`to` the publishing device,
`in_reply_to` the record's id), checked in this order, the first that applies:

1. `presence.signer-mismatch`: the record names no `device`, or its `subject` is not the identity the signing device
   is delegated by (§7.4), as the authority learned it when the device bound (§13.2).
2. `presence.lifetime`: `expires_at − issued_at` is below 60 s or above 3,600 s (P§8).
3. `presence.stale`: the authority holds a record for the same `(subject, device)` whose `seq` is equal or greater.
4. `policy.rate-limited`: the authority accepted a record from this device less than 5 s earlier (P§8), whether or not
   that record is still held; the `error` carries `retry_after`, the whole seconds left.

Otherwise the record is accepted. The authority does not acknowledge it (as for `publish`, §22.1): it keeps it as the
device's current record, replacing any earlier one, and every active presence subscription to the subject gets a
`notify` (§9.3) carrying the new body.

**The body.** A presence `notify` body is `{"event": "presence", "state": S}`, as in §9.3, where `S` is the authority's
assertion about the subject's devices that hold **no** record: `available` when any of them is bound to it, else
`offline`. When the authority holds any record for the subject, the body also has `records`: each record it holds,
ordered by `device`. A record in a body is the signed envelope (§9.3 RECOMMENDS the signed form, and P§2.3 requires
it); a subscriber verifies each independently of the authority. A body without `records` is the v0.16 body.

**Expiry.** A record past its `expires_at` is dropped, and the authority forgets its `seq`. With no record left for a
device, that device counts in the assertion again. When the clock passes several records' expiry at once, each
subscription gets one `notify` for its subject, subjects in order.

**Unbinding.** A device that unbinds keeps its record until T-Presence-Grace (P§8) has passed since the unbind, so a
phone changing networks does not flicker `offline`. The grace runs from the first unbind: a further unbind while it
runs changes nothing, and a record accepted from the device meanwhile keeps the grace running. A device that binds
again within the grace keeps its record as if it had never left. When the grace runs out, the record is dropped as at
expiry. A grace of 0 drops it at the unbind.

**Notifying.** A subscription gets a `notify` when an event changes its body: an accepted record, a record dropped, or
a binding change of a device that holds no record. A binding change that leaves the body as it was sends nothing.

## P§4 Several devices, one identity (spec-gap 135)

- The §9.4 record carries `device`, the DID of the device it describes, which MUST equal the signer (P§3). `seq` is
  ordered per `(subject, device)`: one device's counter never makes another's record stale.
- A presence `notify` body carries the current record of every device the subscriber may see. The subscriber's client
  computes the identity's presence from them; the authority does not.
- **Combining rule**, deterministic so every subscriber agrees. The candidates are the state of every record that is
  still valid (`expires_at` after now), plus `available` when the body's assertion is `available`. With no candidate,
  the identity is `offline`. Otherwise it takes the highest-ranked candidate: `dnd` > `busy` > `available` > `away` >
  `offline`, an unknown state ranking as `available` (P§5). Among candidates of equal rank, a record comes before the
  assertion (the device's own signed word before the authority's claim); then a registered state before an unknown
  one; then unknown ones in code-point order.
- The result names the effective state (a registered value), the token that won (shown raw when unknown, P§5), and
  whether it came from a record, from the assertion, or from nothing. A client MUST render a state that came from the
  assertion as the authority's claim (§9.3).
- A v0.16-form record, without `device`, counts as one unnamed device's record.

## P§5 States (spec-gap 136)

- Registry `dsip-presence-state`, shape `[a-z][a-z0-9-]*`, at most 64 characters; initial values `available`, `busy`,
  `away`, `dnd`, `offline`. It is open: implementations MUST NOT reject an unknown token.
- Fallback: an unknown state is shown as `available` (and ranked as `available` in P§4), with the token displayed raw.
  A newer state must never make a reachable person look unreachable.
- "Invisible" is client behaviour, not a state: an invisible device publishes `offline`, or nothing. P§2.2 is what
  keeps it from leaking.

## P§6 Audiences and detail (not yet pinned)

- Three detail levels: `basic` (available or unavailable), `standard` (P§5 states), `detailed` (plus `activity`,
  registry `dsip-presence-activity` with `in-call`, `in-meeting`, `presenting`, and a free-text `note`).
- A device may publish one record per audience it shares with, each signed, with the record's `audience` naming it.
  The authority sends each subscriber only the records for that subscriber's audience, as its policy decides from the
  verified identity, `claims` and `capability` (§9.3). The authority never edits a record, so a reduced view is a
  separately signed record, never a redacted one.
- A subscriber in no audience gets the uniform `policy.blocked` (§9.3).
- The authority sees every audience's records in plaintext. That is accepted (it already sees the bindings), and it is
  why encryption is P§11.

## P§7 Time-boxed shares (not yet pinned)

- A share is a `capability` token (§9.3) the subject's authority issues for one subscriber DID and an audience, with
  an expiry. When the token expires, the subscription ends with a `terminated` notify, reason `policy.terminated`;
  revoking it early does the same.
- Issuing a share is out of band, as for `contact_token` (§19.4): a link, a QR code, or a grant.
- Revocation stops future notifies only. What was already shown cannot be recalled.

## P§8 Timers

| Timer | Default | Bounds | Meaning |
|---|---|---|---|
| Record lifetime | 300 s | 60–3,600 s | A record's `expires_at` minus `issued_at`. Devices publish again before expiry. |
| T-Presence-Grace | 60 s | 0–300 s | After a device unbinds, how long the authority keeps its record. |
| Publish interval | — | ≥ 5 s per device | Between two accepted records of one device; sooner is refused `policy.rate-limited`. Keeps presence from being a traffic channel. |

The grace is the authority's choice within its bounds; the lifetime bounds and the publish interval are checked as P§3
says.

## P§9 Reason tokens

The profile registers the category `presence` in the core reason registry (§15). Its default fallback for an unknown
condition: the record is refused; the device does not send the same record again, and publishes a corrected one.

| Token | Meaning | Carried on |
|---|---|---|
| `presence.signer-mismatch` | The record's `device` is missing or is not the signer, or its `subject` is not the signer's identity | `error` |
| `presence.lifetime` | The record's lifetime is outside P§8's bounds | `error` |
| `presence.stale` | The authority holds a record of the same device with an equal or greater `seq` | `error` |

`policy.rate-limited` (§15) covers the publish interval.

## P§10 Security and privacy considerations

- Calls, deposits and subscription answers must not leak presence by their reason or timing (P§2.2).
- The authority is trusted with presence plaintext, and not trusted to forge it: a subscriber checks each record's
  signature and delegation (§7.4).
- A record names a device. Showing the per-device breakdown to subscribers reveals how many devices someone has and
  which one is active. Clients SHOULD show the combined state only.
- Presence history is metadata. Authorities SHOULD keep no record past its expiry; P§3 has them forget it.

## P§11 Open questions

1. **Encryption to subscribers.** One route: an MLS group per audience, with presence sealed under its exporter, as
   Messaging Profile activity is (M§11). It reuses existing key distribution and removal; the cost is a group per
   audience, and every share is a membership change. Deferred until P§6 is pinned.
2. **Enterprise policy.** A deployment pattern, not protocol: an organisation runs the `did:web` authority for its
   identities and applies policy there (§9.3 already makes authorization the authority's decision).
3. **A device with no record for an audience** (P§6): fall back to assertion, or show nothing?
4. **Messaging:** should a member's presence also travel in its groups (M§11 activity)? That would give a second path
   with its own audiences.
