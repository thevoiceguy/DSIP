# DSIP Messaging Profile 1.0 — Unified Messaging, Mailboxes, and Voicemail

**Status:** DRAFT, companion profile to DSIP (staged for v0.8). Design text, **not yet implemented**.
Unlike the Gateway Profile and the WebRTC Media Binding, this document is written *before* the
reference implementation: per the project's vectors-first rule, a `messaging/` vector category
pins it next, and where the vectors and this text disagree the disagreement is resolved
explicitly (vector bug or text bug), never papered over. Spec-gaps 31–47
(`impl/docs/spec-gaps.md`) record every choice this draft makes that core does not already
settle.
**Profile identifier:** `messaging/1.0`. **Conformance pieces:** `DSIP Messaging Profile 1.0`
(clients) and `DSIP Mailbox 1.0` (mailbox and hub services) — M§18.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are RFC 2119 / RFC 8174.
Core sections are cited `§n`; this profile's own sections are cited `M§n`; the WebRTC Media
Binding is `B§n`. MLS is RFC 9420; HPKE is RFC 9180.

---

## M§1 Scope and principles

DSIP Core v1.0 establishes trusted *real-time* sessions and defers messaging to a profile (§3.2,
§6.1). This is that profile. It lets the same DSIP identity that places calls also send and
receive **asynchronous** communication — text, voice and video messages, voicemail, images,
files, contacts, locations, reactions, receipts, and conversation activity — with end-to-end
encryption, multiple devices, groups, and durable history.

Principles:

1. **One identity, one mailbox, one conversation model, any media.** Text, voicemail and files
   are not separate systems; they are *content objects* of different kinds carried by one
   mechanism (M§8). Media type (`kind`) and user intent (`purpose`) are separate axes.
2. **The mailbox is untrusted storage.** A mailbox stores ciphertext it cannot read, cannot
   impersonate its owner, and is never an identity authority (§8.1). Identity stays with the
   DID and its delegated devices (§7.3, §7.4).
3. **Always deposit; push is the fast path.** Every durable object is deposited into mailboxes;
   a recipient device that is online receives it within the same round trip as a live push from
   its own mailbox. There is no "try realtime, then fall back" race (M§9).
4. **Durable versus ephemeral.** Content, receipts, and history are durable. Activity
   ("typing…") is ephemeral and is never stored (M§11).
5. **Reuse before invent** (§6.1, §6.2). Group and multi-device encryption is MLS; first-contact
   sealing is HPKE; authentication of devices is the core delegation model; first contact is the
   core `introduction`/`grant` exchange; transport is `ws/1.0`.
6. **Honest about limits** (§5.6). Metadata exposure, non-repudiation, the history/forward-secrecy
   trade, and what a hub can withhold are stated in M§15, not implied away.

**Out of scope for 1.0** (M§19): SMS/MMS/RCS gateways, sealed-sender metadata protection, group
administration roles, message edits and retractions, disappearing messages, multi-hub groups,
chunked/streamed blobs, and any post-quantum ciphersuite beyond a reservation.

## M§2 Architecture

### M§2.1 Roles

| role | what it is | trust |
|---|---|---|
| **client device** | a device delegated by an identity with capability `dsip.messaging` (M§6.2) | holds MLS state and plaintext |
| **mailbox** | a `service`-class DSIP identity (§7.1, a `did:web`) that stores deposits for the identities it serves, pushes them to their bound devices, serves their KeyPackages and blobs | ciphertext and routing metadata only |
| **hub** | the mailbox that orders one MLS group's handshake messages and fans every group message out to the members' mailboxes (M§6.5) | ciphertext, group roster (device DIDs), timing |

A hub is a role a mailbox plays for a group, not a separate kind of server. A mailbox MAY be
co-located with a DSIP relay (§13) and MAY share its service identity; if it does, one `ws/1.0`
connection carries both call signaling and mailbox traffic.

### M§2.2 Groups are the unit of encryption

Every conversation is an MLS group whose members are **devices** (leaves), grouped by the
**identity** that delegated them:

- A **direct conversation** is a group of exactly two identities with all their messaging devices.
  Alice (phone, laptop) and Bob (phone, desktop, tablet) is a five-leaf group.
- A **group conversation** is a group of any number of identities.
- Each identity also has one **personal group** containing only its own devices, hubbed at its
  own primary mailbox. It carries the archive key (M§12), read state when read receipts are off
  (M§10), call history, and other own-device synchronization.

"Bob has four devices" is therefore not a special case anywhere in this profile: it is four
leaves.

### M§2.3 Flow at a glance

```
 Alice phone                Alice mailbox          hub (= Alice mailbox       Bob mailbox          Bob devices
     │                           │                  for this conversation)         │                    │
     │── deposit (MLS app) ─────►│── (local hub) ──►│                              │                    │
     │                           │                  │── deposit (seq 42) ─────────►│── items (push) ───►│ phone (bound)
     │◄── accepted (seq 42) ─────│◄─────────────────│                              │   stored for ─────►│ desktop (later sync)
     │                           │◄── deposit (seq 42, own copy for Alice laptop)  │                    │
```

## M§3 Core hooks this profile requires

The profile is additive except for the following core items, each filed as a spec-gap:

| # | core section | hook |
|---|---|---|
| 31 | §12.9, §13.3, §19.4 | The 300 s replay window rejects any held envelope delivered more than 300 s after signing — including v0.7 introductions (7-day validity). Independent of messaging; this profile avoids it by construction (M§5.1). |
| 32 | §3.2, §6.1, §12.1, §24.4 | Name `messaging/1.0` and its message types; add the two conformance pieces. |
| 33 | §6.2, §20.7 | End-to-end encryption for asynchronous traffic: MLS for conversations, HPKE for sealed introductions; state non-repudiation. |
| 34 | (new) | MLS requires an ordering authority for commits; this profile's choice is the per-group hub. |
| 35 | (new) | New-device history versus forward secrecy: the archive key (SYNC mode, default). |
| 36 | §19.4 | Grant scope `dsip.message`; `sealed` introductions; authorization of group adds; voicemail from `dsip.invite` grantees. |
| 37 | §8.1, §13.2, DHT Hints Profile | DID service type `DSIPMailbox`; hint `service` discriminator; multiple mailboxes. |
| 38 | §15.1 | New reason category `mailbox`. |
| 39 | §7.4, §24.2 | Delegation capability `dsip.messaging`; no delegation-capability registry exists today. |
| 40 | §13.2 | Object size constant `MAX_MLS_BYTES` and HTTPS blob carriage for anything larger. |
| 41 | §12, §14 | Voicemail is caller-recorded; trigger conditions; no new core field. |
| 42 | §12.6, §20.6 | Duplicate direct conversations and successor groups: lower ULID wins; hub-hosting asymmetry tripwire. |
| 43 | (new) | Ephemeral activity is keyed by the MLS exporter, not the secret tree. |
| 44 | (new) | "Durably processed" (M§5.4): MLS state and delivery state commit together; redelivered MLS items collapse by `seq` (M§8.5). |
| 45 | (new) | Mailbox-to-hub forwarding: only an owner device's deposit, only to the group's registered hub; the hub takes identity from the header delegation. |
| 46 | §19.4 | A hub-forwarded welcome's adder is proven only by `origin`; refusal tokens for a bad `origin`. |
| 47 | (new) | A device's own items fanned back to it are recognised by the `accepted` seq (or their bytes), never decrypted. |

## M§4 The mailbox service

### M§4.1 Identity

A mailbox is a DSIP identity of class `service` (§7.1), a `did:web` of its operator (§7.2), with a
per-instance device key delegated by that identity (§7.4) — the same pattern as a gateway (G§2).
Every envelope a mailbox sends (`accepted`, `items`, `key-packages`, fan-out `deposit`, `error`)
is signed by that key.

### M§4.2 Discovery (§8.1)

An identity advertises its mailbox in its **DID document** as a service entry. This is the
authoritative source:

```json
{
  "id": "did:web:example.com:users:bob#dsip-mailbox",
  "type": "DSIPMailbox",
  "serviceEndpoint": {
    "uri": "wss://mbx.example.net/dsip",
    "bindings": ["ws/1.0"],
    "mailbox": "did:web:mbx.example.net",
    "priority": 0,
    "profiles": ["messaging/1.0"],
    "accepts": ["text", "audio", "video", "image", "file", "contact", "location"],
    "voicemail": { "max_duration_s": 180 }
  }
}
```

- `uri` MUST be `wss` (§13.2). `mailbox` is the mailbox service DID; a client MUST verify that the
  mailbox's `hello` (§13.2) is signed under that DID before depositing.
- `accepts` lists content kinds (M§8.2) the owner's clients render; it is a hint to senders, not a
  mailbox-enforced rule (the mailbox cannot see kinds).
- `voicemail` present means the owner accepts voicemail (M§13); absent means it does not.
- **Usable entries.** An entry is usable when it satisfies the service shape (`mailbox-service`
  schema: `wss` URI, `bindings`, and the `mailbox` DID) **and** advertises `messaging/1.0` in
  `profiles`. Anything else is skipped: a mailbox that does not say it speaks the profile, or whose
  DID is missing, cannot be used.
- **Multiple mailboxes.** An identity MAY list several `DSIPMailbox` entries with integer `priority`
  (lower first; absent is 0, and entries of equal priority keep document order). Senders and hubs
  deposit to the lowest-priority usable entry that accepts the connection; that entry is the
  identity's **primary** mailbox for the deposit. The owner's devices
  MUST sync **every** listed mailbox and deduplicate (M§8.5), and
  MUST deposit archive items (M§12) to every listed mailbox, so each is a complete replica of
  history. Migrating providers is: add the new entry, let devices replicate archive into it,
  remove the old entry.
- **`did:key` identities** have no document. They MAY advertise a mailbox in a DHT reachability
  hint (DHT Hints Profile) whose `endpoints[]` item carries `"service": "DSIPMailbox"` plus the
  fields above. Hint-sourced mailboxes are hints (§8.1 rule 6): a client MUST present them as
  such and MUST NOT replace the mailbox of an established conversation on a hint alone.
- **Hints never override a document.** Hints are consulted only for an identity whose document lists
  no `DSIPMailbox` entry. When a document lists entries and none is usable, the identity has no
  mailbox: a client MUST NOT fall back to a hint, because a hint signed by one device would then
  override the authoritative source (§8.1, M§15.4).

### M§4.3 Binding and capabilities

A device, a hub, or another mailbox reaches a mailbox over `ws/1.0` with a verified `hello`
(§13.2); the mailbox MUST verify the device delegation, including capability `dsip.messaging`
(M§6.2), before serving any mailbox operation for that identity. A revoked or expired delegation
therefore ends a device's access at its next binding with no additional mechanism.

The mailbox's `hello` `capabilities` object carries a `mailbox` member:

```json
"mailbox": {
  "profiles": ["messaging/1.0"],
  "modes": ["sync", "queue"],
  "hub": true,
  "ciphersuites": [1, 3],
  "max_mls_bytes": 24576,
  "blob_endpoint": "https://mbx.example.net/blobs",
  "max_blob_bytes": 104857600,
  "mls_retention_s": 2592000,
  "max_retention_s": 31536000,
  "quota_bytes": 10737418240
}
```

Values are informative (§13.2 capability rule); enforcement is server-side.

### M§4.4 Modes and retention

The owner selects a mode with `mailbox-config` (M§5.7):

- **`sync` (default).** Content is retained as archive items (M§12) for the owner's retention
  period, bounded by the operator's `max_retention_s`. A device added later reconstructs history.
- **`queue`.** No archive items are accepted. An item is deleted once every **registered device**
  has acknowledged it (M§5.4) or `mls_retention_s` passes, whichever is first. A device added later
  receives no history.

A *registered device* is one that has completed a verified `hello` for the owner within
`mls_retention_s`. In both modes, MLS items (handshake, application, welcome) are retained until
every registered device has acknowledged them or `mls_retention_s` passes (RECOMMENDED 2,592,000 s,
30 days); a device offline longer than that re-joins its groups by external commit (M§6.8).

Retention and quota never affect DID ownership (principle 2); `mailbox.quota-exceeded` refuses new
deposits, it never deletes an identity.

## M§5 Messages

### M§5.1 Common rules and the two-layer model

All messages below are DSIP-JOSE envelopes (§10.2) obeying §10.3 and the full envelope pipeline,
including the 300 s replay window and ULID/`issued_at` consistency (§12.9, §20.6). Their `dsip`
block lists `messaging/1.0` in `profiles`. `expires_at − issued_at` MUST NOT exceed 60 s for every
type in this section (they are delivery envelopes, not records).

The profile separates **carriage** from **content**:

- **Carriage** is the envelope. It is authenticated per hop and is fresh on every hop: a mailbox
  never re-delivers an old envelope; it delivers stored *bytes* inside a new `items` envelope it
  signs now. The replay window therefore never sees a stored envelope (this is how the profile
  avoids spec-gap 31).
- **Content** is the MLS message inside (`mls`), authenticated end to end by the sender's MLS leaf
  signature (M§6) and deduplicated by content id for as long as it is retained (M§8.5), not for
  300 s.

`from` on client-originated messages is the **device DID**, like `hello`; the device's delegation
rides in the protected header `delegations` array (§7.4) whenever the receiver may not hold it.

**Size constant.** `MAX_MLS_BYTES` = **24,576**. A receiver MUST refuse an `mls`, `welcome`,
`group_info`, `sealed`, or `archive` value whose decoded length exceeds it
(`mailbox.object-too-large`). The decoded length is computed from the base64url text as
⌊length × 3 / 4⌋, so decoders that differ on non-canonical trailing bits cannot disagree about the
limit (the alphabet itself is a schema check).
Double base64url expansion (value inside payload) keeps every envelope carrying one such value,
plus a header delegation, under the 65,536-byte `ws/1.0` cap (§13.2). Anything larger is a blob
(M§8.4).

**Refusals** of profile messages that break these rules, in the order a receiver checks them:
schema, then lifetime (over 60 s; over 10 s for `ephemeral`), then for a deposit the class
(unregistered → `mailbox.unsupported-class`), the class field table below, and the size constant.
Schemas: `v0.8/dsip-messaging-schemas-draft/` (generated; normative for shape).

### M§5.2 `deposit`

Places one item into a mailbox or submits it to a hub.

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "deposit",
  "id": "01M3250V00JYBWAX8APKJPP0PK",
  "from": "did:key:z6MkAlicePhone",
  "to": "did:web:mbx.alice.example",
  "group": "MDFNMzI1MFRSM1dROFpLNU4yRDlYSEc2QkE",
  "class": "application",
  "mls": "<base64url MLSMessage (PrivateMessage)>",
  "blobs": [{ "uri": "https://mbx.alice.example/blobs/9f86d0…", "sha256": "9f86d0…", "size": 482220 }],
  "issued_at": 1790000000,
  "expires_at": 1790000030
}
```

Fields:

- `to` — the hub (for group traffic) or the target mailbox (for hub fan-out and welcomes). A device
  normally sends every deposit to its **own primary mailbox**, which forwards it unchanged to `to`
  when `to` names another service (mailbox-to-hub forwarding over `ws/1.0`, hello as service
  identity). Forwarding keeps device IP addresses away from foreign hubs and bounds a device's
  connections to one. A device MAY connect to a hub directly.
  **Forwarding rules** (spec-gap 45). A mailbox forwards only a deposit from a device of its owner,
  and only to the hub registered for the deposit's `group` (M§6.6), reached at the `hub.uri` of the
  `welcome` that registered it. It refuses a deposit from another identity's device with
  `policy.blocked`, and one for an unregistered group or addressed to any service other than that
  group's hub with `mailbox.unknown-group`. It stores nothing and relays the hub's `accepted` or
  `error` back to the device. Because a forwarded deposit arrives on the mailbox's connection, the
  device MUST carry its delegation in the header (M§5.1), and the hub MUST take the depositor's
  identity from that delegation (capability `dsip.messaging`), never from the connection.
- `recipient` — present only on deposits addressed to a mailbox: the served identity the item is
  for.
- `group` — base64url MLS `group_id`; MUST equal the group id inside `mls`.
- `class` — one of (registry `dsip-deposit-class`; a receiver MUST refuse an unknown class with
  `mailbox.unsupported-class` — class is structural, not presentational):

  | class | carries | stored? |
  |---|---|---|
  | `handshake` | an MLS PublicMessage proposal or commit; a commit MAY carry `welcome`, `group_info`, `ratchet_tree_blob`, `grants` | yes |
  | `application` | an MLS PrivateMessage | yes |
  | `welcome` | an MLS Welcome, hub → new member's mailbox | yes |
  | `group-info` | the latest signed GroupInfo for external joins | latest per group only |
  | `ephemeral` | sealed activity (M§11) in `sealed`, no `mls` | **never** |
  | `archive` | an archive record (M§12) in `archive`, with `akid`, `ref_group`, `ref_seq` | yes (`sync` mode) |

- `seq` — present on hub fan-out deposits: the hub's order for this group (M§6.5).
- `blobs` — the ciphertext manifest of blobs the content references (M§8.4): URI, SHA-256 of the
  ciphertext (lowercase hex), ciphertext size. Keys are **never** here.
- `hub` — on `welcome`: `{ "did": …, "uri": … }` of the group's hub, so the new member's mailbox
  can register the group (M§6.6).
- `grants` — on a commit that adds identities, and on the resulting `welcome`: the compact
  serialized `grant` envelopes (§19.4) authorizing the adder to add each new identity (M§14.2).
- `origin` — on hub-forwarded `welcome`: the adder device's original signed `handshake` deposit
  (compact), so the new member's mailbox can verify who added it (M§14.2).
- `successor_of` — on `welcome` for a successor group (M§7.5): the predecessor group id.

### M§5.3 `accepted`

The signed acknowledgement that a hub or mailbox has taken responsibility for a deposit (or blob).
It is the **accepted receipt** of M§10.1 and is the service's claim, not the recipient's.

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "accepted",
  "id": "01M3250VZ83Q0ERDRMH2PK6QCT",
  "from": "did:web:mbx.alice.example",
  "to": "did:key:z6MkAlicePhone",
  "in_reply_to": "01M3250V00JYBWAX8APKJPP0PK",
  "group": "MDFNMzI1MFRSM1dROFpLNU4yRDlYSEc2QkE",
  "seq": 42,
  "issued_at": 1790000001,
  "expires_at": 1790000031
}
```

- `in_reply_to` MUST equal the deposit's `id` (the anti-splicing pattern of §13.2).
- `seq` is present when a hub accepted a `handshake` or `application` deposit.
- `duplicate: true` marks an idempotent re-acceptance (M§9.3, M§12.2).
- `ephemeral` deposits get no `accepted`; they get an `error` only on refusal.
- Refusal is a signed `error` with a reason (M§16); a mailbox MUST NOT silently drop a
  non-ephemeral deposit (§13.2).

### M§5.4 `sync` and `items`

An owner's device reads its mailbox with `sync`:

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "sync",
  "id": "01M34TVDM0MKWKEVZPQZ2VVQDX",
  "from": "did:key:z6MkBobDesktop",
  "to": "did:web:mbx.bob.example",
  "since": "c:000000000000a41f",
  "ack_through": "c:000000000000a41f",
  "limit": 200,
  "live": true,
  "issued_at": 1790090000,
  "expires_at": 1790090030
}
```

- `since` — an opaque cursor (≤ 64 characters) from a prior `items`; `null` reads from the oldest
  retained item. An unknown or expired cursor is refused with `mailbox.cursor-invalid`; the device
  re-syncs from `null`.
- `ack_through` — this device has durably processed every item up to and including this cursor
  (M§4.4 deletion input). Acknowledgement is per device. *Durably processed* (spec-gap 44) means
  the MLS state change an item caused, the device's ack position and its per-group `seq` positions
  (M§8.5) are committed together: a device MUST NOT acknowledge an item whose MLS state change could
  still be lost, and SHOULD commit each item's MLS state and delivery state atomically, so that a
  crash rolls both back and the item is simply redelivered. A duplicate item advances the ack
  position like any other.
- `live: true` — while this connection stays bound, push new items as unsolicited `items`.

The mailbox answers with one or more `items`:

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "items",
  "id": "01M34TVEK8MP8DMJ3E4BTQDGCN",
  "from": "did:web:mbx.bob.example",
  "to": "did:key:z6MkBobDesktop",
  "in_reply_to": "01M34TVDM0MKWKEVZPQZ2VVQDX",
  "items": [
    {
      "cursor": "c:000000000000a420",
      "stored_at": 1790000002,
      "class": "application",
      "source": "did:web:mbx.alice.example",
      "group": "MDFNMzI1MFRSM1dROFpLNU4yRDlYSEc2QkE",
      "seq": 42,
      "mls": "<base64url>",
      "blobs": [{ "uri": "https://mbx.bob.example/blobs/9f86d0…", "sha256": "9f86d0…", "size": 482220 }]
    }
  ],
  "next": null,
  "issued_at": 1790090001,
  "expires_at": 1790090031
}
```

- Items are in cursor order; cursors increase monotonically per mailbox.
- `next` is the cursor to pass as `since` for more, `null` when caught up.
- A mailbox MUST paginate so every `items` envelope fits the transport cap; `MAX_MLS_BYTES`
  guarantees any single item fits.
- A pushed `items` (live) has no `in_reply_to`.
- When the mailbox has replicated a blob (M§8.4), it rewrites `blobs[].uri` to its own copy; the
  `sha256` never changes.

### M§5.5 `key-packages` and `key-package-fetch`

The mailbox is its owners' MLS KeyPackage directory.

**Upload** — an owner device sends `key-packages` to its own mailbox:

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "key-packages",
  "id": "01M3250WYGNJK7F3T0CHH49HY0",
  "from": "did:key:z6MkBobPhone",
  "to": "did:web:mbx.bob.example",
  "subject": "did:web:example.com:users:bob",
  "key_packages": ["<base64url KeyPackage>", "<base64url KeyPackage>"],
  "last_resort": "<base64url KeyPackage>",
  "issued_at": 1790000002,
  "expires_at": 1790000032
}
```

The mailbox MUST verify that each KeyPackage's leaf credential names the uploading device and
satisfies M§6.2, and answers `accepted`. It keeps at most a bounded number per device
(RECOMMENDED 100) and exactly one `last_resort` per device (the newest replaces the older). A
`key-packages` message MUST carry at least one KeyPackage, and an upload from a device that is not a
registered device of the owner is refused `policy.blocked`.

**Fetch** — any identity's device asks for a target's KeyPackages:

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "key-package-fetch",
  "id": "01M3250XXRDZ2NRTN8X0861MHF",
  "from": "did:key:z6MkCarolPhone",
  "to": "did:web:mbx.bob.example",
  "target": "did:web:example.com:users:bob",
  "grant": "<compact grant envelope from Bob to Carol>",
  "issued_at": 1790000003,
  "expires_at": 1790000033
}
```

- Authorization is M§14.2. Unauthorized requests are refused `policy.first-contact-required`; a
  target the mailbox does not serve is refused `transport.unknown-recipient` (the §13.2 relay
  rule, deliberately the same as session traffic — M§15.5).
- The response is `key-packages` with `in_reply_to` set, `subject` = target, and **one** KeyPackage
  per currently delegated messaging device of the target, each removed from the directory as it is
  served (single use). A device with none left contributes its `last_resort`, which is not removed.
  A device with neither is omitted; if no device can be served, the mailbox refuses
  `mailbox.no-key-packages`.
- A mailbox MUST rate-limit fetches per requesting identity per target (directory draining is a
  denial-of-service against first contact); a grant-bearing fetch MAY get a higher limit.

### M§5.6 `blob-put`

The only message type carried over HTTPS instead of `ws/1.0`. It authorizes one blob upload
(M§8.4) and is sent as `Authorization: DSIP <compact envelope>` on
`PUT {blob_endpoint}/{sha256}`, whose body is the ciphertext.

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "blob-put",
  "id": "01M3250ZW8M3FKBFNTBB326WY9",
  "from": "did:key:z6MkAlicePhone",
  "to": "did:web:mbx.alice.example",
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "size": 482220,
  "issued_at": 1790000005,
  "expires_at": 1790000065
}
```

The mailbox MUST verify the envelope (the device must be delegated by an identity it serves),
MUST verify that the body's SHA-256 and length match, and answers `201` with a signed `accepted`
envelope (`in_reply_to` = the `blob-put` id) as the JSON body. HTTPS uses TLS 1.3 with Web PKI
validation as in §13.2.

### M§5.7 `mailbox-config`

An owner device configures its own mailbox:

```json
{
  "dsip": { "core": "1.0", "min_core": "1.0", "profiles": ["messaging/1.0"], "extensions": [], "critical": [] },
  "type": "mailbox-config",
  "id": "01M32514RGC6EF1RE73ZBM8ZWB",
  "from": "did:key:z6MkBobPhone",
  "to": "did:web:mbx.bob.example",
  "subject": "did:web:example.com:users:bob",
  "mode": "sync",
  "retention_s": 31536000,
  "admit": "grant",
  "groups": [
    { "group": "MDFNMzI1MFRSM1dROFpLNU4yRDlYSEc2QkE", "hub": "did:web:mbx.alice.example", "state": "joined" }
  ],
  "revoked_grants": ["01M3252NK00MMY0046JK6MBG79"],
  "issued_at": 1790000010,
  "expires_at": 1790000040
}
```

- Every field except the envelope fields and `subject` is optional; present fields replace the
  stored value (for `groups`, per group entry).
- `admit` ∈ {`grant`, `open`} (default `grant`): whether first contact requires a grant (M§14.2).
  `open` suits businesses and public services.
- `groups[].state` ∈ {`joined`, `left`}: confirms a pending registration (M§6.6) or ends one.
- `revoked_grants` lists grant ids the owner has revoked; the mailbox MUST refuse authorization by
  them from then on (§19.4 "revocation is local policy at the granting side" — this is its
  propagation to the mailbox).
- The mailbox answers `accepted`.

## M§6 Encryption: the MLS profile

### M§6.1 Ciphersuites

- `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001, RFC 9420's mandatory-to-implement suite)
  MUST be implemented.
- `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003) SHOULD be implemented.
- All suites use Ed25519 signatures, matching the core crypto floor (§10.2). A device whose only
  DSIP key is ES256 cannot hold a messaging leaf in 1.0 (M§6.2).
- A hybrid post-quantum suite (an IETF-assigned X25519 + ML-KEM suite) is **reserved**. Groups
  SHOULD move to it by commit once it is assigned and implemented; this is registry work, not a
  protocol change.

A group's suite is fixed at creation. Creators pick the most preferred suite supported by every
initial KeyPackage.

### M§6.2 Credentials: the DSIP authentication service

MLS delegates "who is this leaf?" to an application-defined authentication service. In DSIP that
service is the core delegation model (§7.4) plus DID resolution (§8.1):

- The leaf credential is a `basic` credential whose `identity` is the UTF-8 **device DID**.
- The LeafNode carries exactly one extension `dsip_delegation` (type `0xF0D1`, private use until
  registered; M§17) whose data is the compact DeviceDelegation envelope (§7.4) for that device: the
  ASCII bytes `protected.payload.signature`. Its `capabilities` MUST include `dsip.messaging`
  (spec-gap 39). Leaf capabilities list both DSIP extension types and the basic credential, and every
  group's `RequiredCapabilities` requires them, so a client that cannot carry them cannot join.
- Authentication checks, in order: credential type `basic`; identity is a UTF-8 DID; exactly one
  `dsip_delegation`; the delegation is a valid compact envelope naming this device and signed by its
  subject; it carries `dsip.messaging`; it is live; the leaf signature key is the device's key.
- The leaf `signature_key` MUST be the device's Ed25519 public key — the key the device DID
  resolves to, or the key the delegation names. One device key thus signs both DSIP envelopes and
  MLS leaf operations; MLS's labelled signatures (`SignWithLabel`) provide the domain separation.
- **Validation.** Every member, and the hub, MUST validate a credential when it enters the group
  (Add, external commit, Update with a new LeafNode) and MUST treat content from a leaf whose
  delegation no longer verifies (expired, subject key rotated with reason `compromised` or `lost`,
  §7.5) as unauthenticated: not rendered, not archived.
- **Renewal.** A device MUST commit an Update carrying a renewed delegation before its current one
  expires. Delegation lifetimes (§7.4 example: 7 days) therefore also bound leaf-key age, which
  helps post-compromise security.
- The **identity** a leaf belongs to is the delegation's `subject`. All identity-level rules in this
  profile (membership, receipts, deduplication) use that value.

### M§6.3 GroupContext extension

Every group carries the required GroupContext extension `dsip_conversation` (private-use until
registered), UTF-8 JSON:

```json
{ "conversation": "01M3250V00JYBWAX8APKJPP0PK", "kind": "direct",
  "hub": { "did": "did:web:mbx.alice.example", "uri": "wss://mbx.alice.example/dsip" },
  "successor_of": null }
```

- `conversation` is a ULID that is stable for the life of the conversation, across successor groups
  (M§7.5). The MLS `group_id` is a separate, per-group value: the UTF-8 bytes of a fresh ULID
  generated at group creation. The `group` field of every message is its base64url encoding.
- `kind` ∈ {`personal`, `direct`, `group`} (registry `dsip-conversation-kind`; an unknown kind is
  handled as `group`).
- `hub` names the ordering authority. Because it is inside the GroupContext, every member agrees on
  it cryptographically; changing it takes a GroupContextExtensions commit (M§7.4).

### M§6.4 Wire forms

- Proposals and commits MUST be sent as **PublicMessage** so the hub can validate them (M§6.5). This
  exposes the roster (device DIDs) to the hub, which already needs it for fan-out (M§15).
- Application messages MUST be sent as **PrivateMessage**.
- Welcomes MUST NOT inline the `ratchet_tree` extension when that would exceed `MAX_MLS_BYTES`; the
  committer then uploads the serialized tree as a blob and names it in `ratchet_tree_blob`
  (`{uri, sha256, size}`, unencrypted: the tree is public group state).

### M§6.5 Ordering: the hub (spec-gap 34)

MLS requires every member to apply the same commit for each epoch; two members committing in the
same epoch fork the group, and forks cannot be merged. DSIP resolves this with one ordering
authority per group, the **hub** named in `dsip_conversation`.

The hub MUST:

1. **Authenticate depositors.** Accept a `handshake` or `application` deposit only from a device
   whose identity currently has at least one leaf in the group, or (for a `handshake` external
   commit) from a joiner authorized by M§6.8; refuse others with `policy.blocked`. A hub orders
   `handshake` and `application` deposits and forwards `ephemeral` ones. It also accepts a
   `group-info` deposit from a member: that one is stored as the group's latest GroupInfo and
   forwarded to the members' mailboxes **without a `seq`**, since it is state, not conversation.
   Any other class is refused `mailbox.unsupported-class`.
2. **Order commits.** Track the group's epoch and public tree from the commits it accepts. For the
   current epoch *e*, accept the **first** commit that validates (framing signature by a current
   member leaf, M§7.3 authorization, credentials per M§6.2); assign it the next `seq`; advance to
   *e + 1*. Refuse any later commit for *e* (which now arrives at epoch *e + 1*) with
   `mailbox.commit-conflict`, a commit that fails validation or M§7.3 with `policy.blocked`, and any
   handshake message for another epoch with `mailbox.stale-epoch`. A standalone proposal for the
   current epoch is sequenced and fanned out without advancing the epoch.
3. **Bound staleness.** Accept application messages for epoch *e* or *e − 1*; refuse older ones with
   `mailbox.stale-epoch`. Discard pending standalone proposals when the epoch advances.
4. **Sequence.** Assign every accepted `handshake` and `application` item a `seq`: a per-group
   integer starting at 1, incremented by one per item. Answer the depositor with `accepted` carrying
   `seq`.
5. **Fan out in order.** Deposit each item, with its `seq`, to the primary mailbox of every member
   identity (including the sender's own identity, which is how a user's other devices see sent
   messages), and for a commit that removes identities, to those identities too. Deliver to each
   mailbox in `seq` order, retrying an unacknowledged deposit before sending later ones. A commit
   that adds identities also sends a `welcome` to each added identity; a commit that is an external
   join sends none, since the joiner joined by its own commit.
6. **Keep only what ordering needs.** The hub retains the epoch, the public tree, the latest
   GroupInfo, and its retry queue. It is not a history store. A group's creator publishes the first
   GroupInfo before its first commit: that is what bootstraps the hub's public view, and every
   committer republishes it afterwards so the hub and the members' mailboxes hold a current one for
   external joins (M§6.8).

A committing member MUST NOT apply its own commit until it holds the hub's `accepted`. On
`mailbox.commit-conflict` it syncs, processes the winning commit, and re-proposes if still needed.

**A device's own items** (spec-gap 47). Rule 5 fans every item back to its sender's identity, and MLS
does not let a device decrypt its own messages. The sending device MUST treat the `seq` in the hub's
`accepted` as processed (M§8.5), so the copy is a duplicate when it arrives. A copy can arrive before
the `accepted` (they travel different connections when the deposit was forwarded); a device
recognises it by its MLS bytes and MUST NOT process it.

A device that sees a `seq` gap for a group MUST NOT process a **handshake** item beyond the gap, or
any item after a held one, until the gap fills. Application items beyond a gap with no held
handshake before them are processed (within an epoch they remain decryptable). If the gap does not
fill within `gap_timeout` (RECOMMENDED 300 s) of the first item being held, the device re-joins by
external commit (M§6.8) and treats every seq up to the highest it has seen as passed; a missing item
arriving later is a duplicate.

**What the hub cannot do** (MLS guarantees, not policy): read content, forge content, add or remove
members, or change the hub without a member's signed commit. **What it can do:** withhold or delay
fan-out, see the roster and traffic timing, and refuse service (M§15.3).

### M§6.6 Group registration at member mailboxes

A mailbox accepts hub fan-out only for groups registered for its owner:

- Accepting a valid `welcome` deposit (authorized per M§14.2) registers `(group, hub)` as
  **pending**. A pending group admits hub deposits up to a bounded size (RECOMMENDED 1 MiB, 500
  items); beyond it the mailbox refuses `mailbox.quota-exceeded`. A hub deposit is admitted only
  from the hub registered for the group.
- An owner device confirms with `mailbox-config` `groups[].state: joined`, or ends it with `left`.
  An unconfirmed pending group is dropped, with its items, after `pending_group_ttl`
  (RECOMMENDED 604,800 s).
- A hub deposit for an unregistered group is refused `mailbox.unknown-group`. The hub MAY retry that
  member later; it MUST NOT stall other members' fan-out because of it.

### M§6.7 KeyPackages and adding devices

- Each messaging device keeps KeyPackages uploaded (M§5.5), each with the MLS lifetime extension set
  no later than its delegation's `expires_at`.
- **A new device of an existing member identity** is added by any existing device of the **same**
  identity (Add + Welcome), first to the personal group, then to that identity's conversation
  groups. A device MAY defer adding itself to rarely used conversations until they are next active.

### M§6.8 External joins

A device MAY join by external commit, using the latest `group-info` item from its own mailbox, when:

- its identity already has a leaf in the group (a device returning after `mls_retention_s`, or a new
  device with no surviving sibling online), and the external commit Removes that identity's stale
  leaves it replaces; or
- the group is the identity's own personal group.

The hub MUST refuse any other external commit (`policy.blocked`). Every member MUST verify the same
condition and MUST render the join ("Bob's new tablet joined") like any roster change (M§7.3).

### M§6.9 HPKE: sealed introductions

HPKE is used for exactly one thing in 1.0: sealing the free-text part of a first-contact
`introduction` to the recipient (M§14.1). Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
AES-128-GCM, mode `base` — the same primitives as MLS suite 0x0001, so no new code path. The
recipient key is the X25519 `keyAgreement` key in the recipient identity's DID document; for
`did:key` it is the X25519 key derived from the Ed25519 key as the `did:key` method defines.

### M§6.10 Non-repudiation (stated)

DSIP envelopes are signed, and MLS leaf signatures authenticate every message. A recipient can
prove to a third party that a given device of a given identity sent a given message. This profile
does **not** offer Signal-style deniability, and clients MUST NOT describe messages as deniable.
This is consistent with DSIP's identity-first design (§5.2); a deniable-messaging extension would
need a different authentication construction and is not reserved.

## M§7 Conversations and groups

### M§7.1 The personal group

Each identity's first messaging device creates its personal group (`kind: personal`), hubbed at
the identity's primary mailbox, and generates the first archive key (M§12). Every later device of
the identity joins it before any other group.

### M§7.2 Direct conversations

A direct conversation is created by the first identity to send: it fetches the peer's KeyPackages
(M§5.5), creates a group with `kind: direct` whose hub is its **own** primary mailbox, adds its own
other devices and the peer's devices in one commit, and deposits the commit with `welcome`,
`group_info`, and `grants`.

**Duplicate direct conversations** (spec-gap 42). If both identities create a direct conversation
concurrently, two exist for one identity pair. Each client MUST converge on the one with the
**lower `conversation` ULID**: it renders both histories as one thread, sends new content only to
the winner, and leaves the loser once its own pending content is re-sent. As in §20.6, the ULID
timestamp is sender-chosen, so a party can backdate to win. The only asymmetry is which identity's
mailbox hosts the hub (metadata visibility, M§15.1). Receivers MUST apply the §20.6 ULID/`issued_at`
consistency check to the creating deposit; a conversation that fails it cannot win. Any future feature
that attaches privilege to hosting MUST re-evaluate this rule (the §20.6 tripwire).

### M§7.3 Group conversations and membership

A group conversation (`kind: group`) is created like a direct one, with any number of identities.
In 1.0:

- Any member identity MAY add another identity, subject to M§14.2 authorization (the adder holds
  a `dsip.message` grant from the added identity, or that identity's mailbox admits `open`).
- Any member identity MAY remove another identity, and any identity MAY leave (commit removing all
  its own leaves).
- Adding or removing **devices** of an identity is reserved to that identity's own devices, except
  that any member MAY remove a leaf whose delegation no longer verifies (M§6.2).
- Every roster change MUST be rendered to members, attributed to the committing identity.
- Administrative roles (who may add or remove whom) are reserved (`group-admin/1.0`, M§19).

The hub enforces the device-ownership rule and the credential rule on the public commit. Members
MUST enforce all of M§7.3 themselves: the hub check is defense in depth, not the authority.

There is no protocol limit on group size. A hub MAY cap leaves and advertise it; it refuses excess
adds with `policy.blocked` and a `detail`.

### M§7.4 Changing the hub

While the hub is alive, any member MAY move the group to another hub by a GroupContextExtensions
commit that changes `dsip_conversation.hub`. The old hub orders and fans out that commit, then
refuses further deposits for the group with `mailbox.unknown-group`. Members then deposit to the new
hub, which initializes its state from the latest `group-info`.

### M§7.5 Successor groups (the hub is gone)

If a hub is permanently unreachable, no commit can be ordered. Any member MAY create a **successor
group**: same `conversation` ULID, new `group_id`, `successor_of` set to the dead group's id, its
own primary mailbox as hub, the dead group's last known roster (by identity) added.

- Member mailboxes accept the resulting `welcome` without a grant if `successor_of` names a group
  registered for their owner (M§6.6).
- Receiving clients MUST verify that the successor's creator was a member of the predecessor and
  that every added identity was in the predecessor's last roster (a successor may omit members, never
  add them). Otherwise they MUST treat it as a new conversation subject to normal first contact (M§14).
- If several successors appear, clients converge on the one with the lowest `group_id`, compared as
  the decoded ULID, not as its base64url text, whose sort order differs (same rule as M§7.2). A
  `group_id` that does not decode to a ULID cannot win.

## M§8 Content

### M§8.1 Content objects

The plaintext of every MLS application message is one UTF-8 JSON object obeying §10.3 (integers
only, no floats). Its `object` member discriminates:

| `object` | purpose | M§ |
|---|---|---|
| `content` | a message: text, media, file, reaction, voicemail, … | M§8 |
| `receipt` | delivered / read / played | M§10 |
| `archive-key` | a new archive key, personal group only | M§12 |
| `call-event` | call history, personal group only | M§13.3 |

An unknown `object` MUST be ignored (not rendered, not an error).

A `content` object:

```json
{
  "object": "content",
  "id": "01M3250V00JYBWAX8APKJPP0PK",
  "conversation": "01M3250V00JYBWAX8APKJPP0PK",
  "sender": "did:web:example.com:users:alice",
  "sent_at": 1790000000,
  "kind": "text",
  "purpose": "message",
  "content_type": "text/plain",
  "text": "Dinner at 7?",
  "reply_to": null
}
```

- `id` is a ULID; its timestamp MUST be within 300 s of `sent_at` (§20.6 consistency, applied to
  content).
- `sender` MUST equal the identity of the MLS sender leaf (M§6.2); a mismatch makes the object
  unauthenticated.
- `conversation` MUST equal the group's `dsip_conversation.conversation`.
- `reply_to` names another content `id` in the same conversation.

### M§8.2 Kind and purpose

**`kind`** is the media type axis (registry `dsip-content-kind`):

| kind | body |
|---|---|
| `text` | `text` (string), `content_type` `text/plain` (MUST support) or `text/markdown` (MAY; render as plain when unsupported) |
| `audio` | `blob` (M§8.4), `duration_ms`; `audio/ogg; codecs=opus` MUST be supported |
| `video` | `blob`, `duration_ms`; `video/webm` SHOULD be supported |
| `image` | `blob`, optional `width`, `height`, `thumbnail` (inline base64url ≤ 8,192 bytes) |
| `file` | `blob`, `name` |
| `contact` | `did`, optional `display_name`, `contact_token` (§19.4) |
| `location` | `lat_e7`, `lon_e7` (integer degrees × 10⁷, per §10.3), optional `accuracy_m` |

An unknown kind that carries a `blob` MUST be offered as a file. Otherwise it MUST be rendered as
an "unsupported message" placeholder, never silently dropped.

**`purpose`** is the user-intent axis (registry `dsip-content-purpose`):

| purpose | meaning |
|---|---|
| `message` | ordinary message (default) |
| `voice-message` / `video-message` | recorded message sent deliberately |
| `voicemail` | recorded after an unanswered call (M§13); carries `session` |
| `attachment` | a file or media item accompanying a conversation |
| `reaction` | `kind: text`, `reply_to` = target; `text` is one emoji grapheme cluster (≤ 32 bytes), empty string removes the sender's reaction |
| `callback-request` | a request to be called back; optional `text` |

An unknown purpose MUST be handled as `message`. `edit` and `retract` are reserved (M§19).

### M§8.3 Content and the size limit

A content object whose MLS application message would exceed `MAX_MLS_BYTES` MUST move its
payload into a blob. Long text is sent as `kind: file`, `content_type: text/plain`.

### M§8.4 Blobs

Large payloads are encrypted client-side and stored as opaque blobs:

1. The sender generates a fresh 32-byte key and encrypts the payload with AES-256-GCM, with no AAD.
   The stored ciphertext is `nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)`. The key is single use.
2. The sender uploads the ciphertext to its own primary mailbox (`blob-put`, M§5.6).
3. The content object carries the key:
   `"blob": { "uri": …, "sha256": …, "size": …, "key": "<base64url 32 bytes>", "alg": "A256GCM", "content_type": "audio/ogg; codecs=opus" }`.
4. The deposit's `blobs` manifest carries `uri`, `sha256`, and `size`, but **not** the key.
5. Blob `GET {blob_endpoint}/{sha256}` is a **capability URL**: anyone holding the 256-bit hash may
   fetch the ciphertext, which is useless without the key.
6. A member mailbox whose owner is in `sync` mode SHOULD replicate every manifest blob on receipt,
   verifying `sha256`, and rewrite `uri` in `items` (M§5.4). Devices then fetch only from their own
   mailbox (M§15.1), falling back to the original `uri`.
7. A device MUST verify `sha256` and `size` before decrypting and MUST discard a mismatch.
8. The source mailbox retains a blob at least `blob_retention_s` (RECOMMENDED 2,592,000 s).

### M§8.5 Deduplication and ordering

- **Deduplication key:** (`conversation`, `sender` identity, `id`). A client MUST retain seen keys
  for as long as it retains the conversation's history, not for the 300 s envelope window.
  Duplicates arise legitimately (multiple mailboxes, retries, archive plus MLS copies) and MUST be
  collapsed silently.
- **Redelivered MLS items** (spec-gap 44). A sequenced (`handshake`, `application`) item the device
  already processed cannot be decrypted again, because MLS deletes the secret it used, so the key
  above is unavailable for it. A device MUST keep, durably and per group, the hub `seq` values it has
  processed (the contiguous position of M§6.5 and any seq processed beyond a gap) and MUST treat a
  redelivered item with such a seq as a duplicate without decrypting it — after a restart, a
  `mailbox.cursor-invalid` re-sync from `null`, or a second mailbox. A `welcome` for a group the
  device has joined is likewise a duplicate; unsequenced `group-info` is state and is simply applied
  again.
- **Display order** is hub `seq` order within a group. For a conversation spanning successor groups
  it is predecessor items first. `sent_at` MAY be displayed but MUST NOT reorder history, so a
  backdated `sent_at` cannot insert content into the past.

## M§9 Delivery model

### M§9.1 Always deposit; push is the fast path

A sender never delivers content directly to recipient devices. It deposits once to the hub (via
its own mailbox). The hub fans out to every member identity's mailbox, and each mailbox pushes to
that identity's bound devices (`sync live`) as soon as it stores the item.

- **Recipient online:** a device receives the item within the same fan-out, typically well under a
  second. This is the realtime experience.
- **Recipient offline:** the item waits in the mailbox and arrives on the device's next `sync`.
- **Some devices online:** the online ones receive it now; the rest on their next sync. There is no
  "delivered to one device, lost to the others" state.

This removes the race of "send realtime, fall back to the mailbox after a timeout": the sender's
obligation ends at the hub's `accepted`, so a phone that backgrounds the app right after sending
loses nothing.

### M§9.2 Sender states

| state | meaning | shown as |
|---|---|---|
| pending | not yet `accepted` by the hub; the client retries | clock |
| accepted | hub `accepted` held (M§10.1) | sent |
| delivered | a `delivered` receipt from the recipient identity (M§10.2) | delivered |
| read / played | per M§10.3, M§10.4, only if the recipient discloses them | read / played |

### M§9.3 Retries and idempotence

A sender that has not received `accepted` MUST re-deposit the **same** MLS message bytes, never a
re-encryption, in a fresh envelope. A hub that has already sequenced those bytes for the group
answers `accepted` with the original `seq` and `duplicate: true`, and does not fan out again. Hubs
MUST remember the digests of sequenced items for at least `mls_retention_s`.

### M§9.4 Hub unavailable

If the hub cannot be reached, the client keeps content pending and retries with the §13.2 backoff.
The client MUST NOT deposit application traffic directly into members' mailboxes (that would bypass
ordering). A hub unreachable past a client-chosen threshold (RECOMMENDED 24 h) is the successor-group
trigger of M§7.5.

### M§9.5 Relationship to relay store-and-forward

Mailbox traffic MUST NOT rely on relay store-and-forward (§13.3), which is best-effort, silently
expiring, and bounded to envelope lifetimes. Deposits are made to the mailbox service, which is
durable and acknowledges. Call signaling continues to use §13.3 unchanged.

## M§10 Receipts

### M§10.1 Accepted

`accepted` (M§5.3) is signed by the hub. It means the hub has sequenced the item. It is **not**
evidence that any recipient mailbox or device has it. Clients MUST render it as the service's claim
("sent"), never as delivery. This follows §9.3's authority-asserted-presence rule.

### M§10.2 Delivered

A `receipt` object is an MLS application message to the conversation group:

```json
{ "object": "receipt", "id": "01M34TVFJGJ1EX44HJV9S9P09W", "conversation": "01M3250V00JYBWAX8APKJPP0PK",
  "sender": "did:web:example.com:users:bob", "sent_at": 1790090002,
  "kind": "delivered", "targets": ["01M3250V00JYBWAX8APKJPP0PK"] }
```

- `delivered` means some device of the recipient identity has decrypted and stored the target.
- It is **identity-level**. A device MUST NOT send `delivered` for a target for which it has already
  seen a `delivered` from any device of its own identity. Its sibling devices are group members and
  see those receipts. A device decides after processing a whole sync batch (a live push is a batch of
  one), so a sibling's receipt later in the same batch suppresses its own; it then sends one receipt
  covering every remaining new item from other identities. Concurrent duplicates still occur, so
  receivers MUST collapse receipts by (identity, `kind`, target) and take the timestamp of the lowest
  `seq`. A receipt from the identity that sent the target content is ignored.
- `targets` holds at most 256 ids; more targets are split across receipts.
- In group conversations with more than 32 member identities, clients SHOULD NOT send `delivered`.

### M§10.3 Read: a per-conversation watermark

- `kind: read` carries `through` (a content id) instead of `targets`. It means the identity has read
  every content item in the conversation up to and including the `seq` of `through`.
- A watermark is monotone: receivers ignore one that does not advance past the identity's current
  watermark, and one whose `through` names content they do not hold.
- Because it is identity-level and monotone, reading on the phone and then on the desktop yields
  one deterministic state, satisfying multi-device reconciliation without per-device read receipts.
- Clients SHOULD send at most one read watermark per conversation per 5 s. A read inside the interval
  is not sent; when the interval passes, the client sends its latest watermark once. A local read at
  or below the identity's current watermark (including one a sibling device set) sends nothing.

### M§10.4 Played

`kind: played` with `targets` applies to `audio` and `video` content, including voicemail; receivers
ignore it for other kinds. It is identity-level, sent at most once per target, and collapsed like
`delivered`.

### M§10.5 Privacy

- `read` and `played` receipts disclose behavior, so a client MUST NOT send them to other identities
  without the user's explicit opt-in. This follows §9.2's private-by-default posture. `delivered`
  MAY default on.
- Opt-in MAY be scoped per conversation or per contact.
- No sender can require a receipt. Senders MUST NOT interpret the absence of a receipt as anything,
  as with silence in §19.4.
- When read receipts are off, the client still sends its `read` watermark, but **only to its
  personal group**, so the identity's own devices stay in sync without disclosure.

## M§11 Ephemeral activity

"Alice is typing…", "recording audio…", "recording video…", "uploading…".

### M§11.1 Keying (spec-gap 43)

Activity is **not** sent through the MLS secret tree. Frequent refreshes would consume ratchet
generations, and a long-offline member would eventually exceed its maximum forward distance.
Instead, per epoch:

```
activity_key = MLS-Exporter("dsip activity", group_id, 32)
```

The sender builds an `activity` object, signs it as a compact DSIP-JOSE envelope with its device
key (the exporter key is shared by the whole group, so the signature is what attributes it), and
encrypts it with AES-256-GCM under `activity_key`: random 12-byte nonce, AAD = `group_id` ‖ epoch
(8-byte big-endian). The result goes in the deposit's `sealed` field as base64url
`nonce ‖ ciphertext ‖ tag`, with `class: ephemeral`.

```json
{ "object": "activity", "conversation": "01M3250V00JYBWAX8APKJPP0PK",
  "sender": "did:web:example.com:users:alice", "activity": "typing", "state": "active" }
```

- `activity` uses registry `dsip-activity` (`typing`, `recording-audio`, `recording-video`,
  `uploading`). An unknown value is rendered as a generic "active…".
- `state` ∈ {`active`, `stopped`}.

### M§11.2 Lifetime

- The carrying deposit's `expires_at − issued_at` MUST NOT exceed 10 s.
- A sender refreshes at most every 5 s while the activity continues (an `active` for the same activity
  within 5 s of the last one sent is not sent) and MAY send `stopped`, which is always sent and resets
  the interval.
- A receiver MUST clear the indicator when no refresh arrives before the last one's `expires_at`.
- Hubs and mailboxes MUST NOT store `ephemeral` deposits: they push to currently bound devices and
  otherwise drop them, and they MUST drop them at `expires_at`. An offline user never receives stale
  activity. A hub forwards activity to the member identities **other than the sender's** (the
  sender's own devices have no use for it), assigns no `seq`, and sends no `accepted`.
- Activity is subject to the same opt-in rule as `read` receipts (M§10.5).
- Activity is lower-assurance by design: it is authenticated by device signature and confidential
  to the group for the epoch, but not forward-secret within an epoch. It never carries content.

## M§12 History and multiple devices

### M§12.1 The archive key (spec-gap 35)

MLS forward secrecy means a device added today cannot decrypt yesterday's MLS messages. In `sync`
mode, history survives through an identity-level **archive key**:

- The first device creates a random 32-byte archive key with id `akid` (a ULID) and sends it as an
  `archive-key` object to the personal group: `{"object": "archive-key", "akid": …, "key": …,
  "created_at": …}`.
- The newest `akid` is current. Devices keep all prior keys, which are needed to read older archive.

### M§12.2 Archiving

After a device decrypts and stores an application item carrying `content`, or a `receipt` that
changes rendering, it builds an **archive record**:

```json
{ "object": "archive-record", "conversation": "…", "group": "MDFNMzI1MFRSM1dROFpLNU4yRDlYSEc2QkE", "seq": 42,
  "sender": "did:web:example.com:users:alice", "sender_device": "did:key:z6MkAlicePhone",
  "received_at": 1790000002, "payload": { "object": "content", "…": "…" } }
```

The device encrypts it with AES-256-GCM under the current archive key: random nonce, AAD =
`group_id` ‖ `seq` (8-byte big-endian). It then deposits it with `class: archive`, `akid`,
`ref_group`, and `ref_seq` to each of its identity's mailboxes.

- A mailbox keeps the **first** archive item per (`ref_group`, `ref_seq`) and answers later ones
  `accepted` with `duplicate: true`. Every device may try; exactly one record is kept.
- Once an MLS item has been archived and acknowledged by every registered device, the mailbox MAY
  delete the MLS item before `mls_retention_s`.
- `queue`-mode mailboxes refuse `archive` deposits with `mailbox.unsupported-class`.

### M§12.3 Adding a device

1. The identity delegates the device (§7.4) with `dsip.messaging`.
2. The device binds to its mailboxes and uploads KeyPackages.
3. An existing device of the identity adds it to the personal group. A new member cannot decrypt
   application messages from epochs before it joined, so the adder MUST re-send every live
   `archive-key` object in the first epoch after its commit.
4. The existing device adds it to conversation groups (M§6.7).
5. The new device syncs from `null`. It decrypts archive records for history and MLS items from its
   join epoch onward.

If no existing device is available, the new device joins the personal group and its conversation
groups by external commit (M§6.8). It then has archive keys only if the identity's recovery
arrangement preserved them (§7.6: an escrowed or backed-up archive key is deployment guidance).
Otherwise, earlier history is unrecoverable, and the client MUST say so.

### M§12.4 Removing a device

When a device is lost, revoked, or its delegation lapses:

- Any remaining device of the identity MUST commit its removal from the personal group and every
  conversation group. Other members MAY remove it once its delegation fails (M§6.2).
- A remaining device MUST create a new archive key and send it to the personal group, which no
  longer contains the removed device. New archive records are unreadable to it.
- Records archived before removal stay readable by anything that exfiltrated them and their key.
  Re-encrypting old archive under the new key is OPTIONAL (costly, and it cannot recall copies
  already taken).
- The mailbox stops serving the device at its next `hello`, because its delegation no longer
  verifies (M§4.3).

### M§12.5 What is lost, stated

Messages sent to an identity during a window in which it has **no** device in a group — for example
after its last device is destroyed and before a replacement joins — were encrypted to leaves that no
longer exist. They cannot be recovered by any party. Clients MUST NOT imply otherwise.

## M§13 Voicemail

### M§13.1 Model (spec-gap 41)

Voicemail is caller-recorded asynchronous media, not a service that answers the call:

- The **caller's** client records the message locally and sends it as an `audio` (or `video`)
  content object with `purpose: voicemail`, encrypted end to end like any other content.
- The mailbox never receives plaintext audio.
- Core is unchanged: no early media (§4) and no new `reject` field.

A deployment MAY still answer calls with a voicemail *service* (`answered_by: service`, §14.3).
Such a service holds plaintext by construction, is outside this profile's end-to-end guarantee, and
clients MUST render its recordings as the service's.

### M§13.2 When a caller may offer voicemail

After an attempt ends, a caller client MAY offer to record a voicemail if **all** of the following
hold:

1. The callee's `DSIPMailbox` entry carries `voicemail` (M§4.2).
2. The caller can send to the callee: an existing direct conversation, or authorization to create
   one (M§14.2).
3. The attempt ended with one of:
   - `reject` `user.no-answer`, `user.declined`, `endpoint.busy`, or `endpoint.unavailable`
   - the caller's own `cancel` `session.timeout` (T-Establish or T-Ring expiry, §12.9)

It MUST NOT offer voicemail after `user.blocked`, any `policy.*`, `identity.*`, or `media.*` reason,
`session.answered-elsewhere`, or any other registered token not listed above (e.g.
`endpoint.capability`). An **unregistered** rejection token falls back by category (§15.1): an
`endpoint.*` condition offers (endpoint state prevented the call, like busy or unavailable); an
unregistered condition in any other category does not, because it may be block-like.

- Recording MUST stop at `voicemail.max_duration_s`.
- The object carries `session` (the invite `id`) and `duration_ms`.
- `audio/ogg; codecs=opus` MUST be supported.
- A greeting, if the callee publishes one, is an optional unencrypted `voicemail.greeting`
  `{uri, sha256, size}` in the service entry. It is public by the owner's choice.

### M§13.3 Call history across devices

A callee device that alerted and was not answered sends a `call-event` object to its personal group:

```json
{ "object": "call-event", "session": "…", "peer": "did:web:…", "direction": "inbound", "outcome": "missed", "at": 1790000000 }
```

This way every device of the identity shows one missed call. Devices MUST NOT send `call-event` for
legs cancelled with `session.answered-elsewhere` (§12.7). Clients interleave call events, voicemail,
and content into one conversation timeline by peer identity.

## M§14 First contact and abuse

### M§14.1 Message requests are introductions

A stranger who wants to message reuses §19.4 unchanged in structure:

- The stranger sends an `introduction`. It remains ≤ 4,096 bytes, rate-limited, never ringing, and
  shown on the requests surface.
- The recipient answers with a `grant` whose `scope` includes **`dsip.message`** (new
  `dsip-grant-scope` value), or rejects, or stays silent.

**Sealed introductions** (spec-gap 36). An introduction MAY replace its plaintext `purpose` with
`sealed`:

```json
"sealed": { "alg": "hpke-base-x25519-sha256-aes128gcm", "enc": "<base64url>", "ct": "<base64url>" }
```

- The plaintext is `{"purpose": "…"}`. `purpose` is still ≤ 280 characters.
- HPKE `info` is `"dsip sealed introduction v1"`.
- AAD is the UTF-8 of `id` ‖ 0x00 ‖ `from` ‖ 0x00 ‖ `to`, so a sealed body cannot be spliced into
  another introduction.
- `purpose` and `sealed` MUST NOT both be present.
- Sealing hides the request text from relays, but it also defeats relay-side content screening.
  Relay rate limits (§19.4) still apply. A recipient client MAY discard sealed introductions from
  identities below a chosen trust tier (§19.1).

### M§14.2 Authorization at the mailbox

A mailbox authorizes a `key-package-fetch`, or a `welcome` deposit that creates a new group
membership for its owner, when **any** of the following holds:

1. The owner's `admit` is `open`.
2. The requester, or for a `welcome` the adder identity proven by `origin`, presents a live grant
   from the owner whose `to` is that identity and whose `scope` includes `dsip.message` or
   `dsip.invite`. The grant must have `valid_until` in the future and an id not listed in
   `revoked_grants`.
3. The requester is the owner itself: a device of the same identity.
4. For a `welcome`, `successor_of` names a group registered for the owner (M§7.5).

For a hub-forwarded `welcome`, the mailbox MUST verify:

- `origin`: the adder device's signed deposit, with a valid delegation, and `issued_at` within 300 s
  of the hub deposit's `issued_at`
- that the grant's `to` equals the adder's identity

(spec-gap 46) `origin` is verified as a credential (its own replay window does not apply; the 300 s
bound above replaces it). It MUST be a `handshake` deposit for the same `group`, and the adder is the
identity its header delegation proves; nothing else in the welcome or on the hub's connection names
the adder. A hub-forwarded `welcome` whose `origin` is absent, unverifiable, for another group, or
outside the 300 s bound is refused with `policy.blocked`; one whose proven adder holds no
authorization is refused with `policy.first-contact-required`, as for any other welcome.

A grantee holding only `dsip.invite` may create a conversation so that it can leave voicemail. The
recipient's client MUST restrict that conversation's rendered content to `purpose` `voicemail` and
`callback-request` until a `dsip.message` grant exists, and MUST hold other content in the requests
surface.

### M§14.3 Abuse controls

The §19.2 hooks apply to messaging as follows:

- Mailboxes MUST rate-limit deposits and fetches per sending identity.
- Hubs MUST rate-limit per member identity.
- Quota is `mailbox.quota-exceeded` with `retry_after` where meaningful.
- Blocking an identity locally ends rendering, and the client SHOULD revoke that identity's grants
  (M§5.7) and leave shared direct conversations.
- Because every sender is a persistent cryptographic identity (§5.2), reputation and blocklists
  attach to something that cannot be spoofed like a telephone number. Minting new identities is
  still cheap; see §19 on Sybil resistance.

## M§15 Security and privacy considerations

### M§15.1 Metadata

End-to-end encryption hides content, not metadata. What each party learns:

| party | learns |
|---|---|
| relay / network observer (§20.7) | connection timing and sizes; TLS hides the rest |
| sender's mailbox | its owner's deposits: target hub DIDs, group ids, times, sizes; blob sizes |
| hub | the group roster (device DIDs → identities), per-member traffic timing and sizes, commit history |
| recipient's mailbox | hub DIDs and group ids its owner belongs to, item times and sizes, blob hashes and sizes |
| other members | everything a member sees, including roster changes |

Blob replication (M§8.4) keeps recipient devices' IP addresses away from the sender's mailbox.
Mailbox-to-hub forwarding (M§5.2) keeps sender devices' IP addresses away from foreign hubs.
Sealed-sender carriage, which would hide the sender identity from hubs and mailboxes, is not in
1.0. It conflicts with per-identity rate limiting (§19.4, M§14.3) and is reserved (M§19).

### M§15.2 The history trade (M§12)

`sync` mode deliberately trades forward secrecy of **stored history** for recoverability. An
attacker who later obtains a current archive key, by compromising any device of the identity or the
recovery arrangement, reads all archive records under that key held by any mailbox. `queue` mode
keeps MLS forward secrecy end to end and has no history. Clients MUST explain the difference when
the user chooses.

### M§15.3 Hub powers

A hub can withhold, delay, or refuse fan-out for a group it hosts. It cannot forge, read, or
reorder undetectably, because members see `seq` gaps (M§6.5). Remedies are a hub change (M§7.4) or
a successor group (M§7.5). Direct-conversation creators host the hub by default, which puts that
power with a participant's own provider rather than a third party.

### M§15.4 Mailbox redirection

An attacker who can change an identity's advertised mailbox receives deposits destined for it. Such
an attacker holds the identity key (DID document), a device key (hints), or the domain (`did:web`,
§8.4). It gains ciphertext and metadata, not content, since content is encrypted to group leaves,
not to the mailbox. It can, however, deny delivery. Clients MUST NOT move an established
conversation's traffic on a hint alone (M§4.2). Key-transparency deployments (§7.7) SHOULD log
`DSIPMailbox` changes.

### M§15.5 Existence disclosure

For deposits and KeyPackage fetches, mailboxes follow the §13.2 relay rule:

- `transport.unknown-recipient` for identities they do not serve
- `policy.first-contact-required` for unauthorized requests

This discloses that an identity uses a given mailbox, as relays already disclose for session
traffic. Introductions remain the anti-enumerated channel (§19.4). A client that must not reveal
whether a target exists sends an introduction first.

### M§15.6 Downgrade

`messaging/1.0` appears in the signed `dsip` block, and the group's ciphersuite is fixed in the
GroupContext. A hub or mailbox cannot strip encryption, because there is no plaintext carriage to
downgrade to. A client MUST NOT render any content that did not arrive as an authenticated MLS
application message or an archive record under a known `akid`.

## M§16 Reason tokens

Category **`mailbox`** (new in §15.1, spec-gap 38). Fallback for an unknown `mailbox.*` condition:
re-sync, retry once, then surface the failure.

| token | meaning | valid on |
|---|---|---|
| `mailbox.commit-conflict` | A commit for this epoch was already accepted; sync and re-propose | error |
| `mailbox.stale-epoch` | Application or handshake traffic for an epoch older than the hub accepts | error |
| `mailbox.unknown-group` | The hub does not host this group, or the mailbox has no registration for it | error |
| `mailbox.cursor-invalid` | The `sync` cursor is unknown or expired; re-sync from `null` | error |
| `mailbox.object-too-large` | A value exceeds `MAX_MLS_BYTES`, or a blob exceeds `max_blob_bytes` | error |
| `mailbox.quota-exceeded` | The owner's quota is exhausted; `retry_after` MAY be present | error |
| `mailbox.no-key-packages` | No KeyPackage or last resort is available for any device of the target | error |
| `mailbox.unsupported-class` | Unknown deposit `class`, or one the receiver (hub, or the owner's mode) refuses | error |
| `mailbox.unsupported-mode` | `mailbox-config.mode` is not a registered mode; nothing is changed | error |

Existing tokens used unchanged: `policy.first-contact-required`, `policy.blocked`,
`policy.rate-limited`, `transport.unknown-recipient`, `transport.envelope-too-large`.

## M§17 Registry entries requested

- `dsip-profile`: `messaging/1.0`.
- Message types (profile, not the §12.1 session set): `deposit`, `accepted`, `sync`, `items`,
  `key-packages`, `key-package-fetch`, `blob-put`, `mailbox-config`.
- `dsip-grant-scope`: `dsip.message`.
- Delegation capability `dsip.messaging`, in a **new** delegation-capability registry (§7.4 values
  are unregistered today; spec-gap 39).
- DID service type `DSIPMailbox`; DHT hint `endpoints[].service`.
- `dsip-reason`: category `mailbox` and the M§16 tokens.
- New registries:
  - `dsip-deposit-class`: `handshake`, `application`, `welcome`, `group-info`, `ephemeral`,
    `archive`
  - `dsip-content-kind`: `text`, `audio`, `video`, `image`, `file`, `contact`, `location`
  - `dsip-content-purpose`: `message`, `voice-message`, `video-message`, `voicemail`,
    `attachment`, `reaction`, `callback-request`; reserved `edit`, `retract`
  - `dsip-receipt-kind`: `delivered`, `read`, `played`
  - `dsip-activity`: `typing`, `recording-audio`, `recording-video`, `uploading`
  - `dsip-mailbox-mode`: `sync`, `queue`
  - `dsip-conversation-kind`: `personal`, `direct`, `group`
- MLS (IANA "MLS Extension Types"): `dsip_delegation` (LeafNode), `dsip_conversation`
  (GroupContext). Until registered they use the private-use codepoints `0xF0D1` and `0xF0D2`.

Registry-governed values are shape-validated in schemas and membership-checked with the fallbacks
stated above; none is a closed enum (CLAUDE.md engineering rule).

## M§18 Conformance

**DSIP Messaging Profile 1.0 (client).** A conformant client MUST:

- implement M§5 client messages, M§6 (suite 0x0001, credentials, wire forms, commit discipline,
  external-join rules), and M§7
- implement M§8 content with the MUST-supported kinds and media types, M§9, and M§10 including the
  privacy rules
- implement M§11 and M§12 (both modes), and M§14 with sealed-introduction receipt

**DSIP Mailbox 1.0 (service).** A conformant mailbox MUST:

- implement M§4, M§5 service messages, and the hub rules of M§6.5–M§6.8
- implement M§7.4, the M§8.4 blob endpoint, M§9.3 idempotence, the M§11.2 non-storage rule, the
  M§12.2 archive rules, M§14.2 authorization, and M§16

**Vectors.** Conformance is pinned by a `messaging/` category, written before code. Tranche 1
(101 vectors, 2026-09-15, Rust/Python parity) covers message and object rules, hub traces and
mailbox traces; tranche 2 (46 vectors) covers the voicemail offer, conversation and successor
convergence, client receipt/watermark/activity traces, and seq-gap handling; tranche 3 (38 vectors)
covers the MLS layer: extension wire encoding, the leaf authentication service, `dsip_conversation`
bytes, and the AES-256-GCM formats for blobs, activity and archive. The reference implementation also
runs the profile end to end on OpenMLS (`impl/crates/dsip-mls`, `tests/e2e.rs`): DSIP device keys as
MLS signers, a hub validating real commits from public group state, a mailbox, a text message, a
voicemail blob, activity and archive sealing, and a commit conflict — and over the wire
(`impl/crates/dsip-mailbox`, `impl/demos/messaging-demo.sh`): two identities, each with its own
mailbox service, a hub federating fan-out to the peer mailbox, discovery through published DID
documents, first contact by grant, and MLS-encrypted text delivered live, after the recipient's
device disconnects, after its process is killed and restarted, and after a crash between processing
an item and committing it. A `resume-trace` group (10 vectors) pins the device's durable delivery state
across restarts and its own fanned-back items (spec-gaps 44, 47). A group conversation runs over the wire
too (`impl/demos/group-demo.sh`): three identities with three mailboxes, members' deposits forwarded to
the hub (spec-gap 45, `messaging/mailbox-forward-*`), welcomes proven by `origin` (spec-gap 46,
`messaging/mailbox-welcome-hub-forwarded-*`), an add while a member's device process is dead and a
removal while the removed member is disconnected. The full plan:

- payload shapes for every message type and content object
- mailbox and hub state traces: sequencing, commit conflict, stale epoch, idempotent re-deposit,
  pending group registration and expiry, ephemeral non-storage, queue-mode deletion, archive
  first-wins, KeyPackage single use and last resort, M§14.2 authorization and grant revocation
- client traces: receipt collapse, watermark monotonicity, duplicate-direct-conversation
  convergence, successor-group acceptance, voicemail offer conditions
- encoding vectors for `dsip_delegation` and `dsip_conversation`

MLS itself is tested with the IETF MLS interoperability test vectors, not re-specified here.

## M§19 Deferred and reserved

- **SMS/MMS/RCS gateway profile.** It builds on the Gateway Profile's identity and downgrade rules
  (G§2, G§7) and the `tel` claim (spec-gap 25). An RCS bridge is natural because RCS Universal
  Profile 3.0 also uses MLS.
- **Sealed sender** (`sealed-sender/1.0`, reserved).
- **Group administration roles** (`group-admin/1.0`, reserved).
- **`edit` and `retract`** purposes (reserved), and disappearing messages.
- **Multi-hub or leaderless ordering.** Rejected for 1.0: MLS forks cannot be merged (spec-gap 34).
- **Chunked and streamed blobs** for large video.
- **Hybrid post-quantum ciphersuite** (reserved, M§6.1).
- **Carriage over `quic/1.0`** (§13.4) when that binding lands. Nothing here is WebSocket-specific
  except the size arithmetic of `MAX_MLS_BYTES`.

---

## Appendix M-A: Example flows (informative)

### A.1 First contact, then a first message

1. Carol sends Bob a sealed `introduction`. Bob's relay holds it (§19.4). It appears in Bob's
   requests surface.
2. Bob grants `scope: ["dsip.invite", "dsip.message"]`.
3. Carol's phone sends `key-package-fetch` to Bob's mailbox with the grant and receives one
   KeyPackage for each of Bob's three devices.
4. Carol's phone creates a `direct` group hubbed at Carol's mailbox and deposits one commit to it.
   The commit adds Carol's laptop and Bob's three devices and carries `welcome`, `group_info`, and
   the grant.
5. The hub accepts (seq 1). It deposits a `welcome` (with `origin` and the grant) to Bob's mailbox,
   which verifies M§14.2 and registers the group as pending. It also deposits one to Carol's
   mailbox for her laptop.
6. Carol's phone deposits "Hi Bob, it's Carol from the meetup" (seq 2).
7. Bob's phone is bound, so its mailbox pushes both items. The phone joins, confirms the group
   (`mailbox-config`), decrypts, and archives. Bob's desktop gets the same items on its next sync
   and skips archiving (the record already exists).

### A.2 Voicemail to an offline callee

1. Alice's `invite` to Bob gets no `progress`, because Bob's devices are all offline.
2. T-Establish expires, and Alice's client sends `cancel` `session.timeout`.
3. Bob's `DSIPMailbox` advertises `voicemail`, and a direct conversation exists, so Alice's client
   offers to record.
4. Alice records 28 s of Opus. The client encrypts it into a blob, runs `blob-put` to Alice's
   mailbox, and deposits `kind: audio, purpose: voicemail, session: <invite id>, duration_ms:
   28400`.
5. Bob's mailbox replicates the blob.
6. The next morning Bob's phone syncs, shows "Voicemail from Alice, 0:28", and sends `delivered`.
   When he plays it, `played` is sent only if Bob opted in.

### A.3 A new tablet with full history

1. Bob delegates the tablet with `dsip.messaging`.
2. The tablet binds and uploads KeyPackages.
3. Bob's phone adds it to the personal group and re-sends the archive keys, then adds it to Bob's
   conversation groups.
4. The tablet syncs from `null`. Archive records give it every conversation back to the retention
   horizon, and MLS items give it everything from its join onward.
