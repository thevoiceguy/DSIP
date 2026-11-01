# Outline: DSIP Wake Profile (`wake/0.1`)

**Status:** superseded by the draft `v1.0/dsip-wake-profile-v1.0-draft.md` (2026-10-31; spec-gaps 169–175 decided "all (a)"), kept for its history. Outline, 2026-10-31, for stage A1 of dsip-rs's `docs/dsip-app-plan.md`. Candidate companion profile to
DSIP 1.0, cite as `W§n` once adopted. It collects spec-gaps 169–175 (`impl/docs/spec-gaps.md`), each with the
editor's draft answer, for the owner to decide. Nothing here is implemented or pinned. Per rule 1, each section turns
into vectors before any code, and the section's vector plan says which. Once decided, the draft goes to
`v1.0/dsip-wake-profile-v1.0-draft.md`; it adds message types and a capability member, which §11.4 allows in 1.x
(spec-gap 163 (a)).

The core already says what this profile fills in. §13.3: reaching a device that is asleep "is the responsibility of
the relay store-and-forward layer", platform push is centralized, and "the push payload need carry nothing but a wake
signal". The relay's `hello` example advertises `push_wake: ["apns", "fcm"]` (§13.2), informative and undefined.
Nothing says how a device asks to be woken, who may wake it, or what a wake carries. iOS and Android end a
background app's sockets, so without this a phone rings only while its app is open.

## W§1 Scope

This profile defines:

- the **push gateway**, a `service` identity (§7.1) that holds an app publisher's APNs key and FCM account and
  forwards wakes to them (W§2);
- how a device **enrols** a platform push token with a gateway and gets an opaque **handle** (W§3);
- how a device **registers** to be woken with each **waker**: its relay for calls, its mailbox for messages (W§4);
- when a waker **wakes** a device, and what the wake carries (W§5, W§6);
- the profile's timers (W§7), reason tokens (W§8), and its privacy considerations (W§9).

Out of scope: Web Push (RFC 8030) for browsers, which needs no gateway and is a later section; notifications shown to
the person (a wake is not a notification: the woken app decides what to show); presence (reachability never depends
on it, P§2); how the app reports a call to CallKit or Telecom (the app plan, stage A5).

## W§2 Roles and the flow

- **Device**: one app install, a delegated device (§7.4). It holds a platform token (a PushKit VoIP token on iOS, an
  FCM registration token on Android).
- **Push gateway**: a `did:web` service identity run by the app's publisher, whose DID document names a
  `DSIPWake` service endpoint (an `https` URI). Only the publisher holds the credentials APNs and FCM require, so a
  relay run by anyone else cannot push to the official app directly (app plan decision 6).
- **Waker**: a relay (§13.6) or a mailbox (M§4) that serves the device's identity and holds traffic for it.

```
device ──wake-enrol (platform token)──────────────────────────► gateway
device ◄─────────────────────────────── accepted (handle) ────── gateway
device ──wake-register (registration: waker, gateway, handle)──► relay / mailbox
           … device sleeps; an invite arrives and is held (§13.3) …
relay ───wake (registration, kind, sealed hint)─────────────────► gateway ──► APNs / FCM ──► device
device ──hello (§13.2) ─────────────────────────────────────────► relay: the held invite is flushed as usual
```

A wake never carries the traffic. The device binds and receives it through DSIP, signed end to end, as it would
had it been awake.

## W§3 Enrolment at the gateway (spec-gaps 173, 175)

- A device sends the gateway `wake-enrol` (HTTPS, spec-gap 173): `provider` (`apns` or `fcm`, registry
  `dsip-wake-provider`), `app` (the APNs topic or the FCM project), `token` (the platform token), `environment`
  (`production` or `sandbox`, APNs only), and `key`: a **wake key**, an Ed25519 public key the device made for this
  enrolment (spec-gap 175). The envelope is signed by the wake key itself, `from` its `did:key`, so the gateway never
  learns the device's DID.
- The gateway answers `accepted` with `handle`: an opaque string, at most 512 bytes, that it alone can read (draft: an
  AEAD of provider, app, token and wake key under the gateway's own key, so the gateway keeps no table). A new
  platform token means a new enrolment and a new handle.
- The gateway MAY refuse an app it does not push for: `wake.unsupported-app`.

**Vector plan.** `payload/wake-enrol-*` (shape, provider shape and registry fallback, token length bound),
`semantic/wake-enrol-signer-is-key` (the `from` must be the `did:key` of `key`).

## W§4 Registration with a waker (spec-gaps 169, 170, 174)

- The device makes a **registration**, a compact signed record (the delegation's form, §7.4) signed by its wake key:
  `waker` (the relay's or mailbox's DID), `gateway` (the gateway's DID), `handle`, `issued_at`, `not_after`. It is the
  waker's permission to ask that gateway to wake that handle, and nobody else's (spec-gap 169).
- The device sends it to the waker over its binding in a new message, `wake-register` (spec-gap 170), also carrying
  `seal_key` (an X25519 public key for W§6's sealed hint) and `kinds` (which of W§5's kinds it wants; default all the
  waker sends). The waker answers `accepted`, or refuses:
  - `wake.waker-mismatch`: the registration's `waker` is not this waker;
  - `wake.registration-invalid`: bad signature, `not_after` before `issued_at`, or past the W§7 cap;
  - `wake.gateway-unknown`: the waker will not use that gateway (its own policy; it MAY allow any).
- The waker keeps one registration per device (§7.4 device DID, the `wake-register` signer): a new one replaces it.
  A `wake-register` with `remove: true` ends it. It also ends at `not_after`, when the gateway answers
  `wake.registration-ended` (W§5), when the device's delegation is revoked or expires (§7.4), and when the waker
  forgets the device (§13.3 retention, M§4.4 registered devices) (spec-gap 174).
- Registering needs no capability beyond what binding already requires (`dsip.signaling`; for a mailbox also
  `dsip.messaging`, M§4.3).
- Wakers advertise the profile in their `hello` capabilities: `"wake": {"profiles": ["wake/0.1"]}`. A client does
  not send `wake-register` to a waker that does not (§11.4).

**Vector plan.** `payload/wake-register-*`; `semantic/wake-register-waker-mismatch`, `-not-after-over-cap`,
`-registration-bad-signature`; a `wake-trace` state vector kind (README), whose events are registrations, bindings,
held traffic and gateway answers and whose output is the wakes sent: `wake-trace-register-replaces`,
`-remove-ends`, `-not-after-ends`, `-revoked-delegation-ends`, `-registration-ended-ends`.

## W§5 Waking (spec-gaps 172, 173)

A waker sends the gateway a `wake` (HTTPS POST of the signed envelope to the gateway's `DSIPWake` endpoint; spec-gap
173), signed by the waker, carrying the device's `registration` as received and:

- `kind`, registry `dsip-wake-kind` with fallback `message`:
  - `call`: the relay holds an `invite` for the device (§13.3), addressed to it or forked to it as a leg of an
    identity-addressed invite (§12.7). One wake per held invite per device.
  - `call-ended`: the relay drops a held `invite` it woke the device for before the device bound (the initiator's
    `cancel`, or the invite's expiry). Apple requires the woken app to have reported a call at once; this ends it
    on the screen instead of leaving it to ring until the app's own timeout.
  - `message`: the mailbox stores an item for the device's identity while the device is not bound. At most one per
    W-Coalesce per device, until the device binds; never for an `ephemeral` deposit (M§11.2).
- `ref`: the invite's `session` for `call` and `call-ended`; absent for `message`.
- `sealed`: W§6, optional.
- `expires`: when the wake is useless: the invite's `expires_at` for `call`, W-Coalesce after the item for `message`.
  The gateway gives it to the provider as the push's expiry (APNs `apns-expiration`, FCM `ttl`).

The gateway verifies the `wake`'s signature (resolving the waker's DID, §8.1), then the registration: signed by the
wake key the handle names, `waker` equal to the `wake`'s signer, `gateway` itself, unexpired. It forwards to the
provider (APNs priority 10 and the VoIP push type for `call`/`call-ended`; FCM high priority) and answers:

- `accepted`: handed to the provider. Not delivered: nothing in APNs or FCM says that.
- `wake.registration-ended`: the provider reports the token dead (APNs 410, FCM `UNREGISTERED`). The waker ends the
  registration (W§4).
- `wake.not-authorized`: the registration does not authorize this waker. The waker ends it.
- `transport.rate-limited` with `retry_after`: the gateway's bound per handle and per waker.

A waker MAY retry a `wake` that failed in transport (no answer, HTTP 5xx) once, before `expires`; it never retries one
answered. Nothing about a wake changes call signaling: the held invite is flushed on the device's binding as §13.3
says, and if the device does not bind in time the initiator's T-Establish (§12.10, 15 s default) ends the attempt as
for any unreachable device.

**Vector plan.** `wake-trace` vectors: `-call-held-wakes`, `-call-bound-no-wake`, `-identity-invite-wakes-each-
offline-device`, `-cancel-before-bind-call-ended`, `-expiry-before-bind-call-ended`, `-bind-then-cancel-no-call-
ended`, `-message-wakes`, `-message-coalesced`, `-message-after-bind-wakes-again`, `-ephemeral-no-wake`,
`-kinds-filter`; gateway verdict vectors, a `wake-gateway` check (README): `-accepted`, `-waker-mismatch`,
`-registration-expired`, `-registration-wrong-key`, `-registration-other-gateway`.

## W§6 What a wake shows (spec-gap 171)

The gateway and the provider see the wake. Neither sees who calls: `sealed` is HPKE (M§6.9's suite, `info`
`"dsip wake hint v1"`) to the registration's `seal_key`, and holds `{"from": <the invite's from>, "on_behalf_of":
<its on_behalf_of>}` for `call`, nothing for the others. The app maps the DID to a contact it already holds and shows
the name on the lock screen at once, replacing it with what the verified invite says once it binds. The hint is the
relay's claim, never verified: the app MUST NOT treat it as the caller until the invite verifies, and MUST show a
call from a DID it does not know as unknown. Sealed size: under 256 bytes, within APNs' 4 KB and FCM's 4 KB.

**Vector plan.** `wake-seal-*` vectors with a fixed HPKE ephemeral key, as the sealed-introduction vectors do: the
plaintext's bytes, the `enc` and `ct`, and opening with the wrong key failing.

## W§7 Timers

| timer | value | meaning |
|---|---|---|
| W-Registration cap | 2,592,000 s (30 days) | longest `not_after − issued_at`; a device re-registers on each binding when under half is left |
| W-Coalesce | 60 s | a mailbox's minimum gap between `message` wakes for one device |

## W§8 Reason tokens

Category **`wake`** (new in §15.1). Fallback for an unknown `wake.*`: end the registration and re-register on the
next binding.

| token | meaning | valid on |
|---|---|---|
| `wake.waker-mismatch` | the registration names another waker | error |
| `wake.registration-invalid` | the registration does not verify, or its lifetime is outside the cap | error |
| `wake.gateway-unknown` | the waker will not use this gateway | error |
| `wake.registration-ended` | the provider no longer knows the token | error |
| `wake.not-authorized` | the registration does not authorize this waker at this gateway | error |
| `wake.unsupported-app` | the gateway does not push for this app or provider | error |

## W§9 Security and privacy considerations

- **The gateway learns** which wakers wake which handles and when, and the platform tokens: the metadata of when a
  person is called or messaged, by which relay. It does not learn the device's DID or identity (spec-gap 175), the
  caller (W§6), or any content. Stated, as §13.3 states the platform dependency.
- **The waker learns** nothing new: it already holds the traffic. It learns the gateway, so which app the device runs.
- **A stolen handle** wakes nobody: the gateway needs a registration naming the signer. A waker that turns abusive is
  bounded by the gateway's rate limits and ended by the device's next `wake-register` with `remove`.
- **A false wake** (a waker waking with nothing held) costs battery and, on iOS, a call the app must report and end:
  bounded by the rate limits; the app ends a `call` wake whose invite does not arrive within T-Establish's maximum.
- **No authority.** A wake proves nothing: the app trusts only what arrives through DSIP and verifies (§8.1).

## W§10 Decisions

Each is a spec-gap; the draft answer is the editor's.

| gap | question | draft |
|---|---|---|
| 169 | How a waker is authorized to wake a device | a device-signed registration naming the waker, shown to the gateway with each wake |
| 170 | Where the device gives a waker its address | a new `wake-register` message, held beyond the binding |
| 171 | What a wake may carry | kind and session, plus the caller's DID sealed to the device |
| 172 | When a waker wakes, coalescing and retries | `call` per held invite, `call-ended`, `message` coalesced 60 s, one retry for transport failure |
| 173 | How wakers and devices reach the gateway | HTTPS POST of a signed envelope to the gateway's `DSIPWake` endpoint |
| 174 | When a registration ends | `not_after` (cap 30 days), replacement, `remove`, provider unregistered, revocation, retention |
| 175 | What identifies the device to the gateway | a per-enrolment wake key, not the device DID |
