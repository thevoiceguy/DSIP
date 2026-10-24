# Presence encrypted to subscribers — design note (P§11 question 1)

Status: **draft for decision** (2026-10-23). Docs only: nothing here is spec text, a vector or code. Each decision
below becomes a spec-gap once chosen, and the text lands in the Presence Profile after that, vectors first.

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

Decided items become spec-gaps 151 onward (D1 with D3, D2, D4, D5, D6), recorded in `spec-gaps.md` as each one is.
