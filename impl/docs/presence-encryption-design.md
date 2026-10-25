# Presence encrypted to subscribers — design note (P§11 question 1)

Status: **decided.** 2026-10-23 (user: "encryption now with (b) and D2–D6 as drafted"); **D7 decided (a)** 2026-10-24.
The wire detail that D7 (a) settles, and three findings it turned up, are §9; the work is staged in §10.
Spec-gaps: 152 = D1 with D3, 153 = D2, 154 = D4, 155 = D5, 156 = D6, 157 = D7 (151 went to the invite-admission
finding of spec-gap 150's work). They are written into `spec-gaps.md` with the implementation, after #243 merges.

## 1. What problem this solves, and what it does not

Today the authority (the subject's relay) reads every presence record in plaintext. It cannot forge one (each is
signed by its device, P§2.4), but it learns each device's state, every audience's state, and from the grants it is
shown, who is in which audience (P§6, last paragraph).

Encryption can hide:

- **the state** of each record (`busy`, `dnd`, …) and its token;
- **which audience** a record is for, and so the shape of the subject's audiences, if the audience label is replaced
  by an opaque tag (D2).

Encryption cannot hide, because the authority needs it or sees it anyway:

- **bindings**: whether a device is connected, and the authority's own assertion (`available` / `offline`, §9.3),
  which already says most of what a casual observer wants;
- **timing and count**: when a device publishes, how often, how many audiences it publishes for (one record each);
  a state change is a new record, so its timing says "something changed";
- **who watches whom**: the subscriptions and the grants presented in them.

So the gain is real but narrow: an honest-but-curious relay operator learns that Alice's phone is connected and
changed state at 14:02, not that it went `dnd`, nor that her `family` audience sees `busy`. Sections 4 and D5 deal
with what timing still leaks.

There are two adversaries, and they are handled differently:

- **The authority.** Encryption is the only defence; this note is about it.
- **A former subscriber** (a share that ended, a grant revoked). The authority already stops delivering to it at once
  (P§7). A former subscriber who still holds a key reads nothing more unless the authority also hands it records,
  i.e. unless the two collude. Key rotation on removal (D3) defends against that collusion and nothing else. This
  matters because rotation is the expensive part of every option.

## 2. What stays the same

- The record stays a signed §9.4 `presence` envelope from the device. The authority still runs P§3's checks: signer,
  lifetime, `seq` staleness, publish interval. They read only outer fields (`subject`, `device`, `seq`, `issued_at`,
  `expires_at`, the audience tag), so none of them needs the state.
- The authority still routes records to subscriptions by audience (P§6) and still makes its own assertion for
  devices holding no record the subscription sees.
- Combining (P§4) is already the subscriber's job, so it moves nowhere: the subscriber decrypts, then combines.
- Reachability never depends on presence (P§2.1), and no response varies with a state the authority now cannot read
  (P§2.2 gets easier, not harder).

## 3. The record

A sealed record replaces `state` with `sealed`, as a sealed introduction replaces `purpose` (§19.4):

```json
{
  "type": "presence", "subject": "did:web:alice.example", "device": "did:key:z6MkAlicePhone",
  "audience": "k:01K7…",                       // D2: an opaque key id, not "family"
  "seq": 59, "issued_at": 1760000000, "expires_at": 1760000300,
  "sealed": "<base64url nonce ‖ ciphertext ‖ tag>"
}
```

- Plaintext: `{"state": "busy"}`, padded to a fixed length (D5), encrypted with AES-256-GCM under the audience key
  (M§11.1's construction), AAD binding `subject`, `device`, `audience`, `seq` and `expires_at`, so the authority
  cannot move a ciphertext to another record.
- The envelope signature covers `sealed`, so a subscriber still verifies the device's word before decrypting it.
- `state` and `sealed` MUST NOT both be present. A subscriber that cannot decrypt (no key, an old key) treats the
  record as absent for combining: it neither shows `offline` nor guesses. Whether the assertion then counts that
  device is D4.

## 4. Key distribution — the main decision (D1)

Every option keys per audience, with "no audience" (every grantee) as one more audience. They differ in how the key
reaches the grantee and what removal costs.

### (a) MLS group per audience (the route P§11 names)

The subject's devices and each grantee's devices are members of one MLS group per audience; the key is
`MLS-Exporter("dsip presence", group_id, 32)` per epoch, exactly as messaging activity (M§11.1).

- For: removal is a Remove commit and gives a fresh epoch at once (real post-removal secrecy, which also defeats the
  collusion case); key distribution, multi-device and device revocation are already solved in `dsip-mls`.
- Against: presence starts to require the Messaging Profile's infrastructure: a hub to order commits, mailboxes for
  welcomes, key packages for every grantee device. A grantee with no messaging cannot see presence at all. Every grant
  is an Add commit and every share's end is a Remove that some member device must be online to commit at
  `valid_until`. A group per audience per subject is many groups for little traffic.

### (b) The audience key sealed into the grant

The grant that admits a subscriber (P§6 rule 2) carries the current audience key, HPKE-sealed to the grantee
identity's X25519 `keyAgreement` key (§19.4's sealed construction; every device acting for an identity holds that
key, §10.4 rule 3). The grantee's devices read it from the grant they already hold.

- For: no new message, no new infrastructure, works for anyone who can hold a grant; the key arrives with the
  permission, so "admitted but cannot read" never happens.
- Against: rotating the key means giving every remaining grantee a new grant, which needs a grant without a fresh
  introduction: **spec-gap 150 (b)** is a prerequisite. Rotation is O(grantees in that audience) signed grants.
  A device added to the grantee identity later can open the key (it holds the identity's key agreement key), which is
  what we want.

### (c) A separate key message

A `presence-key` object, HPKE-sealed to each grantee identity, sent on its own (through the grantee's relay or
mailbox) whenever the audience key is created or rotated.

- For: rotation does not touch grants; works with spec-gap 150 decided either way.
- Against: a new message type, its own delivery and retry, and a window where a subscriber is admitted but holds no
  key (or an old one). It is (b) with the coupling removed and the ordering problem added.

**Draft choice: (b),** with rotation per D3. It keeps presence free of the messaging stack, and it ties the key to
the one object that already means "may see this audience". Its cost is spec-gap 150 (b), which is wanted for share
controls anyway. (a) is the right answer if presence later moves into messaging conversations (P§11 question 3,
spec-gap 148); this note does not propose that.

## 5. The other decisions

**D2 — the audience on the wire.** (i) Keep the label (`family`): the authority learns the audience structure but no
states. (ii) An opaque tag per audience key (`k:` + the key's ULID), carried in both the record and the grant's
`presence_audience`; a new key is a new tag, so the authority sees an audience "change" at each rotation but never its
name. Draft: **(ii)**; a label is a statement about the subject's relationships, and the tag costs nothing. P§6's
token shape (`[a-z][a-z0-9-]*`) admits `k-01k7…` if the colon is dropped.

**D3 — rotation.** (i) Never: an audience key lives until the subject resets it by hand; ended shares are protected by
the authority's delivery control only. (ii) On removal: when a grant in the audience is revoked or reaches
`valid_until`, the next record for that audience uses a new key, and the remaining grantees get it (with (b): new
grants). (iii) On a schedule (for example daily) and on removal. Draft: **(ii)**. It is the only one that defends
against the collusion case, and removal is rare next to publishing. Under (b), a removal in a large audience is a
burst of grants: worth a bound (rotation at most once per T-Presence-Rotate, batching removals).

**D4 — a device whose records the subscriber cannot read.** (i) It counts as holding no record: the authority's
assertion covers it, as today. (ii) It counts as unknown: excluded from combining, shown as "presence hidden". Draft:
**(i)** for the authority's computation (it cannot tell either way, and the rule must stay the one in P§6), and the
client MAY say "presence not readable" when it holds a sealed record it cannot open.

**D5 — timing and size.** (i) Nothing: accept that change timing leaks. (ii) Pad the plaintext to a fixed size and
SHOULD refresh on a fixed cadence (every record re-sent at a steady interval whether or not the state changed), so a
change is not distinguishable from a refresh. Draft: **(ii)**, padding MUST and steady refresh SHOULD; P§8's publish
interval already bounds the cost (one record per device and audience per refresh).

**D6 — versioning.** Sealed records are `presence/0.2`. A subject may publish both forms during migration only by
audience (one audience sealed, another plain); a subscriber that lists only `presence/0.1` is given plain audiences
only. Draft: a subject's client chooses per audience; no record is ever published in both forms.

## 6. What it costs to build (if (b) and the drafts are chosen)

1. Spec-gap 150 decided (b) and implemented: a grant that follows a grant.
2. Spec text: P§3 sealed record, P§6 opaque audience tags, a new P§ for keys and rotation, P§8 rotation bound; core
   §19.4: a grant MAY carry a sealed `presence_key`. Schema: `sealed` on `presence`, `presence_key` on `grant`.
3. Vectors before code: sealing and AAD binding (table), the authority's checks on a sealed record (it must not need
   the state), rotation on revoke and on `valid_until`, a subscriber with an old key, D4's assertion rule.
4. Three implementations: the authority changes little (routing by tag); the work is in the endpoint (key state,
   rotation, re-granting) and the two clients.
5. Demos and web tests; the WAN presence check gains a sealed audience.

Roughly the size of the audiences work (#237 + #240–#242), plus spec-gap 150.

## 7. Questions for you

1. Pursue this now, or leave P§11 question 1 open for presence 0.1 and finish v0.17 first?
2. D1: (a) MLS, (b) key in the grant, or (c) separate key message? Draft (b).
3. D2–D6 as drafted?

Answered 2026-10-23: now; D1 (b); D2–D6 as drafted.

## 8. The construction, and D7 (decided (a), 2026-10-24)

Working the decisions into wire detail:

- **Keys.** One 32-byte key per audience per epoch, plus one for "no audience" (the main record, which every grantee
  sees). A record names its key with `kid`; it keeps `audience` (the D2 tag) for routing, and the main record has none,
  so P§6's routing is unchanged.
- **The record.** `sealed` replaces `state`; plaintext `{"state": S}` UTF-8, right-padded with spaces to 128 bytes
  (D5; a state is at most 64 characters). AES-256-GCM, random 12-byte nonce, AAD = `subject` ‖ `device` ‖ `audience`
  (or empty) ‖ `kid` ‖ `seq` ‖ `expires_at`. `sealed` = base64url `nonce ‖ ct ‖ tag`, as M§11.1. Profile
  `presence/0.2` (D6).
- **The grant.** `presence_keys`: the keys this grantee needs (no-audience, and its audience's), HPKE-sealed to the
  grantee identity's key agreement key (§10.4) and bound to the grant's `id`, `from` and `to`, as a sealed purpose is
  (§19.4). Every device of the grantee can open it.
- **Rotation (D3).** When a grant ends (revoked, or past `valid_until`), the next record for each key it held uses a
  new epoch, and every remaining grantee holding that key gets a grant that follows theirs (spec-gap 150) carrying the
  new keys. A pure rotation changes nothing the grantee may do, so it needs no revocation at the authority: the old grant
  admits what the new one does until it expires, and nobody is cut off mid-watch. Note the cost: ending any share
  rotates the no-audience key, so **every** grantee gets a new grant. T-Presence-Rotate bounds how often (removals in
  one window are batched).
- **Subscribers.** Keep the keys of the current and the previous epoch (records under the old one live until their own
  `expires_at`). A record whose `kid` they hold no key for counts as unreadable (D4).
- **Authority.** Checks and routing as today. A subscription whose `subscribe` does not list `presence/0.2` is not
  given sealed records, and its assertion counts their devices as holding none (D6).

**D7 — how the subject's own devices share the keys.** Every device of the subject publishes, so all of them need the
same key for each audience and epoch, and must agree on the current epoch. The note did not cover this. Choices:

- **(a) Derive, and read the epoch off the authority.** `key = HKDF(identity's X25519 key agreement secret, "dsip
  presence" ‖ kid)`, `kid` = the audience tag ‖ "." ‖ the epoch number. Every device of an identity holds that secret
  (§10.4) and a grantee never does, so no key is sent between the subject's devices. The epoch number is in the clear in
  `kid`: a device publishes at the highest epoch it has seen for that audience, in its own records (it watches its own
  identity, P§6 rule 1) or in a grant-revocation it sent. Cost: the authority sees how many rotations each audience has
  had; a device that has not caught up publishes one record under the old epoch (still unreadable to the removed
  grantee unless the authority colludes).
- **(b) Random keys, distributed to siblings.** The device that rotates sends the new key to its own identity's other
  devices, sealed to the identity's key agreement key, through the authority or the mailbox. Needs a new message and
  its delivery and retry; a sibling offline at rotation publishes under the old key until it catches up.
- **(c) One publishing device.** Only one device publishes sealed records; the others publish plain or nothing.
  Simplest, and it loses P§4's per-device records for sealed audiences.

**Draft: (a).** It needs no new message and no coordination beyond what P§6 rule 1 already allows, and a device always
derives the key it needs; the only coordination is the epoch number, which can lag harmlessly.

## 9. The construction as specified (P§12), and what D7 (a) changed

D7 (a) means nothing is sent between the subject's own devices, so everything they must agree on is derived from the
identity's X25519 key agreement secret `s` (§10.4: every device acting for the identity holds it, a grantee never does)
or read off records they already see. Working that through changed three things from §5 and §8:

1. **The audience tag is derived, not a key's ULID** (refines D2 (ii)). Siblings must use the same tag for an audience
   or their records land in different audiences. `tag(L) = "k-" ‖ base32 (lower case, unpadded) of the first 10 bytes
   of HKDF-SHA256(s, info "dsip presence audience v1" ‖ 0x00 ‖ subject ‖ 0x00 ‖ L)`, 18 characters, a valid P§6
   token. The label `L` never leaves the subject's devices; the tag stays the same across rotations (the epoch, in
   `kid`, is what changes), so the authority sees "audience k-… rotated 3 times", as D7 (a) already accepted.
2. **The record field is `sealed_state`, not `sealed`.** A `presence` record is addressed to the authority, and an
   addressee implementing `sealed-body/1.0` refuses any payload carrying `sealed` without that extension in
   `dsip.critical` (§10.4). A record named `sealed` would be refused by exactly the authorities that implement the
   most privacy. The record carries `kid` and `sealed_state` in place of `state`.
3. **Rotation crosses devices by observation** (refines D3 (ii) for several devices). A device knows only the grants it
   issued. So the device that ends a grant rotates; every other device of the subject sees the higher epoch in its own
   identity's records (P§6 rule 1) and re-grants the live grants *it* issued. A sibling that is offline re-grants when
   it returns, and until then its grantees cannot read the new epoch: they see the authority's assertion (D4).

Keys: `kid` = scope ‖ "." ‖ epoch, the scope `main` (records with no audience) or the tag; `key = HKDF-SHA256(s,
info "dsip presence key v1" ‖ 0x00 ‖ subject ‖ 0x00 ‖ kid, 32)`. Record: plaintext `{"state": S}` padded with spaces
to 128 bytes, AES-256-GCM, AAD `"dsip presence v1" ‖ 0x00 ‖ subject ‖ 0x00 ‖ device ‖ 0x00 ‖ audience ‖ 0x00 ‖ kid ‖
0x00 ‖ u64be(seq) ‖ u64be(expires_at)`. Grant: `presence_keys` = `{alg, enc, ct}`, HPKE as a sealed purpose, info
`dsip presence keys v1`, AAD `id ‖ 0x00 ‖ from ‖ 0x00 ‖ to`, plaintext `{"keys": [{kid, key}]}` padded to a multiple of
256 bytes. All of it is P§12.

**A further finding, for stage E2 (spec-gap 159, drafted in `spec-gaps.md`).** A rotation grant follows the old one
without revoking it (so nobody is cut off mid-watch), which leaves the old grant admitting at the authority. When the
share later ends, revoking only the newest grant leaves a subscription the old one admitted running. Draft (a): ending
a share revokes every grant of its chain that is still before its `valid_until` (rotation keeps `valid_until`, so the
chain is the grants that followed one another by rotation). (b) Rotation grants do revoke their predecessor, and the
grantee re-subscribes at once with the new grant, a short gap in its notifies. (c) The authority treats a grant whose
`session` names a grant as standing in for it: revoking either ends what both admitted. Draft: (a), it changes nothing
at the authority.

## 10. Stages

- **E1 — wire, keys, authority** (#248, merged): spec-gaps 152–157 in `spec-gaps.md`; P§12 and core §19.4 text; schemas
  (`kid`, `sealed_state`, `presence_keys`); vectors for derivation, sealing and opening a record, opening a grant's
  keys, the subscriber's view with unreadable records (D4), the payload rules, and the authority's routing by profile
  (D6); Python, Rust and impl-ts.
- **E2 — the endpoint**, in two parts:
  - **E2a — the trace machine** (#249, merged): key state per scope and epoch, keys put in a grant, rotation on revocation,
    on a following grant and on `valid_until` with T-Presence-Rotate, re-granting on a sibling's higher epoch with
    rotation chains, the grantee keeping two epochs; spec-gaps 159, 160 and 161 decided; state vectors
    (`state/presence-keys-*`) and a fuzz target (`presence-keys`) on Python, Rust (`dsip-session`) and impl-ts.
  - **E2b — Core** (#250, merged; spec-gap 162 decided): the wire behind the traces in `dsip-endpoint`: `presence_keys` sealed with HPKE in the grants Core
    signs and opened from the ones it receives, key bytes kept per grantor, records sealed at the current epoch
    (`Publisher`) and opened in the watch (`Watch` with the held keys), the own watch fed back as sibling records, the
    `revoke` emission sent as `grant-revocation`s, and the key state persisted with the contacts.
- **E3 — clients and the testbed**, in three parts:
  - **E3a — the agent and the CLI** (this PR): `AgentConfig.presence`; the agent gives Core its relay as the authority,
    so revocations of a share and its chain go from Core; `dsip answer --seal-presence` (keys in grants, audience labels
    sent as tags), `dsip presence publish --sealed` (records sealed, the device's own watch adopting a sibling's epoch),
    `dsip presence watch` listing `presence/0.2` and opening records with the keys held; `demos/presence-sealed-demo.sh`.
  - **E3b — the browser**: Settings audiences sealed, badges, a "presence not readable" note; the wasm host on
    `set_authority`, `sign_presence`, `own_record` and `Watch::view`; a web test.
  - **E3c — the testbed**: the relay and web redeployed and a sealed WAN presence check.
