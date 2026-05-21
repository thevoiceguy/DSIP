# DSIP: Decentralized Session Initiation Protocol

## A Narrow Core for Trusted Real-Time Media Sessions

**Version:** Draft v0.5  
**Status:** Design Proposal  
**Editor:** James Ferris  

---

## 1. Abstract

DSIP, the **Decentralized Session Initiation Protocol**, is an identity-first signaling and media negotiation protocol for establishing trusted real-time sessions between identity-aware endpoints.

DSIP is inspired by SIP, but it is not a wire-compatible replacement for SIP and it is not limited to telephony. DSIP uses decentralized identifiers, signed signaling, explicit media negotiation, and verifiable session identity to let participants answer a small set of critical questions before media flows:

- Who is initiating or publishing this session?
- Can that identity be verified?
- What kind of session is being requested?
- What media types and codecs are supported?
- What transport and encryption modes are available?
- What policies apply to recording, transcription, relay, AI processing, and redistribution?
- What trust level should the receiver apply?

The long-term vision for DSIP includes calls, video sessions, broadcasts, AI agents, device media, messaging, public safety, and future real-time media use cases. However, the v1.0 scope should be intentionally smaller.

**DSIP Core v1.0 should focus on two initial profiles:**

1. **Interactive Media Profile** — one-to-one and small-group real-time audio/video/data sessions.
2. **Verified Broadcast Profile** — signed publication and subscription metadata for live audio/video streams.

Other use cases, including device control, vehicle media, sensor telemetry, emergency calling, public-safety dispatch, contact-center routing, and rich messaging, should be treated as future profiles that build on the DSIP core rather than being included in the first implementable specification.

The purpose of DSIP v1.0 is not to solve every real-time media problem. It is to define a credible, implementable foundation for trusted session initiation and negotiation.

---

## 2. Design Correction from v0.4

The earlier v0.4 draft expanded DSIP into a universal control plane for nearly every real-time media scenario: calls, video, broadcasts, IoT, AI agents, emergency services, vehicles, sensors, contact centers, and public safety video.

That vision is useful, but the scope is too broad for an implementable v1.0 protocol.

Protocols that try to support every vertical from day one tend to fail in predictable ways:

- The core becomes too large to implement completely.
- Vendors implement incompatible profile subsets.
- Profile dialects emerge without strong interoperability.
- The protocol loses to focused competitors in each vertical.
- Security analysis becomes too broad to be useful.
- Governance becomes impossible because too many industries need different policy models.

SIP suffered from this problem. XMPP suffered from this problem. DSIP should learn from that history.

The corrected direction is:

> **DSIP should define a small, stable session core and a disciplined profile model.**

The core should be useful by itself, but narrow enough that two independent teams can implement it and interoperate.

---

## 3. Updated Definition

DSIP stands for:

> **Decentralized Session Initiation Protocol**

DSIP should not be described primarily as “Decentralized SIP.”

A better definition is:

> DSIP is a decentralized, identity-first protocol for initiating, authenticating, and negotiating trusted real-time media sessions.

An endpoint may eventually be a person, browser, phone, media server, AI agent, broadcaster, device, gateway, or service. But DSIP Core v1.0 should only require endpoint behavior needed for interactive media sessions and verified broadcast publication/subscription.

---

## 4. Scope of DSIP Core v1.0

### 4.1 In Scope

DSIP Core v1.0 defines:

- Endpoint identity using DIDs or DID-compatible identifiers
- Signed signaling envelopes
- Version negotiation
- Capability discovery
- Media offer/answer negotiation
- Codec and transport capability exchange
- Minimal session state
- Trust metadata
- Policy declarations
- Error handling
- Extension negotiation
- Basic relay semantics
- Two initial application profiles:
  - Interactive Media
  - Verified Broadcast

### 4.2 Out of Scope for Core v1.0

The following should not be part of the DSIP Core v1.0 requirement set:

- Full messaging interoperability
- Device command/control
- Sensor telemetry
- Vehicle communication
- Emergency calling to 911/112/999
- Lawful intercept frameworks
- Contact-center queue semantics
- AI agent orchestration
- Payment settlement
- Global reputation algorithms
- Global identity governance
- New media transport protocols
- New audio/video codecs
- Replacement for WebRTC, RTP, HLS, DASH, SRT, RIST, or QUIC media

These are valid future profiles or bindings, but they should not be required for v1.0 interoperability.

### 4.3 Initial Profiles

DSIP v1.0 should define only two required profiles.

#### Interactive Media Profile

Supports real-time conversational sessions such as:

- Voice call
- Video call
- Small group media session
- Browser-to-browser media
- SIP/WebRTC gateway scenario
- AI gateway as an endpoint, but without standardizing AI behavior

#### Verified Broadcast Profile

Supports publication and subscription metadata for live media such as:

- Radio stream
- TV audio/video stream
- Live event stream
- Public meeting stream
- News stream
- Sports commentary stream
- Organization-owned media feed

This profile verifies publisher identity and stream metadata. It does not replace CDNs, HLS, DASH, SRT, RIST, WebRTC, or broadcast contribution/distribution systems.

---

## 5. Non-Goals

DSIP v1.0 should explicitly state what it does not attempt to solve.

DSIP does not define a universal anti-spam system.

DSIP does not make anonymous self-issued identities trustworthy by default.

DSIP does not make emergency calling decentralized.

DSIP does not make AI disclosure technically enforceable.

DSIP does not guarantee that a verified logo means a user should trust the caller.

DSIP does not require blockchain infrastructure.

DSIP does not replace media transports.

DSIP does not require a single global registry.

DSIP does not solve all key recovery and consumer identity UX problems by itself.

DSIP provides protocol mechanisms that deployments and profiles can use to build safer systems. It should not claim to solve social, regulatory, or economic problems solely through message formats.

---

## 6. Core Principles

### 6.1 Small Core, Explicit Profiles

The DSIP core should remain small. Features that are not required for all endpoints should be moved into profiles or extensions.

### 6.2 Identity First, But Not Identity Naive

Every DSIP session should be bound to cryptographic identity. However, identity alone is not trust. A self-issued identity proves key control, not legitimacy.

DSIP must distinguish between:

- Self-issued identity
- Domain-bound identity
- Organization-verified identity
- Credential-backed identity
- Regulated identity
- Anonymous or ephemeral identity

### 6.3 Trust Is Contextual

A credential is only meaningful if the verifier trusts the issuer for that claim.

A client should not display a generic “verified” badge without context. It should display claims in a way that makes the trust basis clear.

Examples:

- “Domain verified: acme.com”
- “Organization credential issued by Example CA”
- “Emergency publisher credential issued by State Authority”
- “Self-issued identity; not externally verified”

### 6.4 Protocol Mechanism, Not Policy Magic

DSIP can provide identity, signatures, credentials, policy declarations, and consent receipts. It cannot force good behavior by malicious actors.

Spam prevention, AI disclosure compliance, moderation, and abuse response require deployment policy, credential issuers, client UX, rate limits, payment models, reputation, regulation, or a combination of those.

### 6.5 Transport Independence

DSIP negotiates media sessions. It does not mandate one media transport.

The first interoperable implementations should likely use WebRTC and/or RTP/SRTP because existing media stacks already solve NAT traversal, congestion control, jitter handling, and encryption.

### 6.6 Realistic Decentralization

DSIP should be honest about decentralization.

- `did:key` is self-certifying but hard to recover and hard to make human-friendly.
- `did:web` is practical for organizations but depends on DNS and Web PKI.
- DHTs may improve censorship resistance but introduce Sybil and eclipse attack risks.
- WebFinger can improve usability but may leak account existence.
- Federation reduces dependence on one provider but does not eliminate trust boundaries.

DSIP should support multiple discovery mechanisms, but v1.0 must define clear authority and conflict-resolution rules.

---

## 7. Relationship to Adjacent Standards

DSIP should reuse existing standards wherever possible and avoid reinventing mature work.

Relevant standards and work areas include:

- W3C DID Core for decentralized identifiers
- W3C Verifiable Credentials for cryptographic claims and presentations
- IETF MLS for group key establishment and secure group messaging
- IETF MIMI for messaging interoperability lessons and identity introduction problems
- IETF SFrame for end-to-end media encryption through SFUs
- SIP, SDP, RTP, SRTP, ICE, TURN, and WebRTC for existing real-time media behavior
- STIR/SHAKEN, PASSporT, and Rich Call Data for PSTN identity interop
- SCITT-style transparency patterns for auditable signed statements
- RFC 4103 / T.140 real-time text for accessibility
- HLS, DASH, SRT, RIST, WebRTC, and QUIC-based systems for media distribution

DSIP should position itself as a session identity and negotiation layer, not as a replacement for all of these systems.

### 7.1 Messaging

DSIP should not try to become a full cross-platform messaging standard in v1.0.

Messaging should either:

- Be deferred to a future DSIP Messaging Profile, or
- Reuse MIMI/MLS concepts where appropriate.

The DSIP core may need small control messages, receipts, or policy acknowledgments, but this is not the same as full user messaging.

### 7.2 Group Security

For group messaging and some control channels, MLS should be considered before inventing a new group key management model.

For media through SFUs, SFrame should be considered before inventing a new E2EE media frame protection mechanism.

### 7.3 SIP/PSTN Interop

SIP/PSTN interop should be a gateway profile, not a core assumption.

A DSIP-to-SIP gateway can translate session signaling, but it cannot preserve all DSIP trust semantics across the PSTN. Identity, consent, policy, and rich session metadata may be downgraded or lost.

---

## 8. Identity Model

### 8.1 Identity Types

DSIP should support several identity classes:

```text
self-issued
personal
organizational
service
broadcaster
gateway
relay
ephemeral
anonymous
regulated
```

The class helps clients apply the right UX and policy.

### 8.2 DID Usage

Recommended DID methods for early DSIP profiles:

```text
did:key    Self-certifying identities, test endpoints, ephemeral users, devices
did:web    Organizations, broadcasters, domains, gateways, service providers
```

Other DID methods may be supported by extension, but v1.0 should keep the required set small.

### 8.3 Identity Keys vs Device Keys

A major usability issue in DID-based systems is key loss and multi-device use.

DSIP should separate:

- **Identity controller key** — controls the DID or long-term identity.
- **Device keys** — used by individual devices to sign session messages.
- **Recovery keys** — used to rotate or regain control after loss.
- **Delegation credentials** — authorize devices, agents, gateways, or services to act for an identity.

A user should be able to use multiple devices without sharing one private key across all devices.

### 8.4 Device Delegation

A DID document or credential should be able to state:

```json
{
  "type": "DeviceDelegation",
  "subject": "did:key:z6MkUser",
  "device": "did:key:z6MkPhoneDevice",
  "capabilities": ["dsip.signaling", "dsip.media.interactive"],
  "issued_at": 1760000000,
  "expires_at": 1760600000
}
```

This allows a phone, laptop, browser, or media appliance to participate without exposing the identity root key.

### 8.5 Key Rotation

DSIP must support key rotation without destroying social identity.

At minimum, the protocol should define:

- Previous key
- New key
- Rotation timestamp
- Signature by previous key when available
- Recovery signature when previous key is lost
- Revocation reason
- Device list update
- Replay protection

### 8.6 Recovery Models

DSIP should not mandate one recovery model, but should define compatible mechanisms.

Possible recovery approaches:

- Recovery key stored offline
- Multi-device quorum
- Social recovery
- Organization-admin recovery
- Hardware security key
- Custodial recovery provider
- Domain recovery for `did:web`

The security properties of these models differ. Clients should expose the recovery model as part of trust metadata when relevant.

### 8.7 Key Transparency

For high-trust deployments, DSIP should support transparency logs or append-only audit mechanisms for key changes, credential issuance, and delegation changes.

This helps detect:

- Silent key substitution
- Compromised issuer behavior
- Unauthorized device addition
- Malicious gateway delegation
- Broadcast publisher hijacking

This should be optional in Core v1.0 but recommended for organizational and broadcast identities.

---

## 9. Discovery Model

### 9.1 Discovery Must Have Authority Rules

v0.4 listed DID documents, DNS, WebFinger, DHTs, federation, and relays as discovery mechanisms, but did not define how they compose.

DSIP v1.0 should define a strict order:

1. **Input identifier is normalized.**
2. **If the input is a DID, resolve it using the DID method.**
3. **If the input is an alias, resolve the alias to a DID using the alias method.**
4. **The DID document is authoritative for DSIP service endpoints.**
5. **Presence, publication, and relay records must be signed by the DID or delegated keys.**
6. **Caches, DHTs, and relays may distribute records but are not authoritative unless the profile explicitly says so.**

### 9.2 Alias Resolution

Human-friendly aliases are necessary for adoption.

Examples:

```text
alice@example.com
support@acme.com
live@wxyz.com
wxyz.com/radio/main
```

Alias methods may include:

- WebFinger
- DNS records
- HTTPS well-known endpoints
- QR codes
- Contact cards
- Enterprise directories

Alias resolution returns a DID. The DID, not the alias resolver, becomes the cryptographic identity for the session.

### 9.3 Conflict Resolution

Conflicts must be handled explicitly.

Examples:

- WebFinger says one DID, DNS says another.
- DID document lists multiple DSIP endpoints.
- A relay publishes stale presence.
- A cached record conflicts with a newly resolved record.

Suggested rules:

- DID resolution wins over alias cache.
- Signed records beat unsigned records.
- Newer sequence numbers beat older sequence numbers.
- Records past expiration are invalid.
- Conflicting live records from the same key should trigger a warning or hard failure depending on profile.
- DHT records are hints, not authority, unless signed and verified.

### 9.4 Honest Treatment of `did:web`

`did:web` is useful and deployable, especially for organizations and broadcasters. But it is not fully decentralized. It depends on DNS, TLS, domain control, and web hosting.

DSIP should describe `did:web` as:

> A practical domain-bound identity method that removes dependence on carrier registrars but still depends on DNS/Web PKI.

That honesty improves the proposal.

### 9.5 DHTs and Decentralized Discovery

DHT-based discovery should be considered experimental for v1.0.

Risks include:

- Sybil attacks
- Eclipse attacks
- Spam indexing
- Privacy leakage
- Poisoned routing records
- Inconsistent availability

DHTs may be useful for censorship resistance or peer-to-peer reachability, but they should not be the default authority mechanism in the first version.

---

## 10. Presence Model

Presence is harder than it looks.

SIP and XMPP both included presence. Both encountered scale, privacy, and federation challenges.

DSIP should treat presence as optional and privacy-sensitive.

### 10.1 Presence Is Not Required for Calling

An endpoint should be able to initiate a DSIP session without global public presence.

A DSIP identity may expose:

- No presence
- Contact-only presence
- Domain-only reachability
- Relay-only reachability
- Public broadcast status
- Temporary session availability

### 10.2 Presence Privacy

Presence can reveal sensitive information:

- Whether a person is online
- When they are active
- Which device they use
- Which network they are on
- Whether they are in a call
- Whether they are at home or traveling

DSIP clients should default to private presence.

### 10.3 Presence Subscription

Presence should use explicit subscription where possible.

A presence record may be visible only to:

- Existing contacts
- Same organization
- Authorized subscribers
- Anonymous users with reduced detail
- Broadcast followers
- Nobody

### 10.4 Signed Presence Records

A signed presence record may look like:

```json
{
  "dsip": "1.0",
  "type": "presence",
  "id": "01HZ...",
  "subject": "did:web:example.com:users:alice",
  "audience": "contacts-only",
  "state": "available",
  "profiles": ["interactive-media"],
  "endpoints": [
    {
      "transport": "wss",
      "uri": "wss://relay.example.com/dsip/alice"
    }
  ],
  "seq": 58,
  "issued_at": 1760000000,
  "expires_at": 1760000180
}
```

The signature covers the payload bytes.

### 10.5 Scale Tradeoff

Short TTLs reduce stale presence but increase traffic. Long TTLs reduce traffic but create stale presence.

DSIP should not pretend there is one universal answer. Presence freshness should be profile-specific.

For example:

```text
interactive-media: short-lived or subscription-driven
broadcast: publication state can tolerate slightly longer TTL
emergency/public safety: future regulated profile with stricter requirements
```

---

## 11. Wire Format

### 11.1 Pick One Mandatory Format

v0.4 allowed JSON or CBOR without choosing a required wire format. That will create incompatible implementations.

DSIP v1.0 should define one mandatory-to-implement envelope format.

Recommended choice:

> **DSIP-JOSE: UTF-8 JSON payloads secured using JWS.**

Reasons:

- Easy for web developers
- Easy to debug
- Familiar to API developers
- Compatible with DID/VC ecosystems
- Works well with HTTPS/WebSocket/QUIC APIs
- Lower adoption friction for early prototypes

A compact binary profile may be defined later:

> **DSIP-COSE: CBOR payloads secured using COSE.**

DSIP-COSE should be optional unless a constrained-device profile later requires it.

### 11.2 Signature Semantics

The signature must cover the exact payload bytes.

Implementations should not rely on JSON field ordering after parsing. The signed object should be serialized, signed, and transmitted as a signed envelope.

A DSIP envelope should include:

```json
{
  "protected": "base64url(jose-protected-header)",
  "payload": "base64url(dsip-json-payload)",
  "signature": "base64url(signature)"
}
```

### 11.3 Payload Rules

To reduce interoperability problems, DSIP JSON payloads should:

- Use UTF-8
- Avoid floating point values
- Use integer timestamps
- Use explicit arrays instead of overloaded strings
- Use registered identifiers for profiles, transports, policies, and codecs
- Use extension namespaces
- Treat unknown non-critical fields as ignorable
- Treat unknown critical fields as fatal

---

## 12. Version and Extension Negotiation

Version negotiation must be designed from the start.

### 12.1 Core Version Fields

Every DSIP payload should include:

```json
{
  "dsip": {
    "core": "1.0",
    "min_core": "1.0",
    "profiles": ["interactive-media/1.0"],
    "extensions": ["relay-basic/1.0"],
    "critical": []
  }
}
```

### 12.2 Compatibility Rules

Suggested rules:

- Major versions are incompatible by default.
- Minor versions are backward-compatible unless marked otherwise.
- Unknown non-critical extensions may be ignored.
- Unknown critical extensions require rejection.
- A responder must indicate the selected mutually supported version.
- Downgrade attempts must be detectable because version negotiation is signed.

### 12.3 Error Codes

Version errors should be explicit:

```text
unsupported-core-version
unsupported-profile-version
unsupported-critical-extension
version-downgrade-detected
unsupported-wire-format
```

---

## 13. Core Signaling Messages

DSIP Core v1.0 should keep message types minimal.

```text
invite       Start an interactive session
answer       Accept an interactive session
reject       Reject a session
update       Modify a negotiated session
bye          End a session
publish      Publish a signed broadcast/session availability record
subscribe    Subscribe to a publication or event stream
notify       Send subscription update
unpublish    Withdraw a publication
error        Report protocol/policy failure
```

Messages such as transfer, conference moderation, device control, AI orchestration, and emergency priority should be profile extensions, not core v1.0.

---

## 14. Media Negotiation

### 14.1 Goals

DSIP media negotiation should allow endpoints to agree on:

- Media type
- Codec
- Codec parameters
- Transport
- Encryption mode
- Relay mode
- Latency target
- Bandwidth constraints
- Accessibility streams
- Recording/transcription/AI processing policy

### 14.2 Registry-Based Codec Identifiers

Codec identifiers should live in a registry, not as hardcoded spec text.

The spec may include examples using Opus, H.264, AV1, AAC, and other codecs, but the normative identifiers should be registered and versioned.

Example:

```json
{
  "media": [
    {
      "type": "audio",
      "direction": "sendrecv",
      "codecs": [
        {
          "id": "codec:audio/opus",
          "sample_rates": [48000],
          "channels": [1, 2],
          "packetization_ms": [20]
        },
        {
          "id": "codec:audio/pcmu",
          "sample_rates": [8000],
          "channels": [1]
        }
      ]
    },
    {
      "type": "video",
      "direction": "sendrecv",
      "codecs": [
        {
          "id": "codec:video/h264",
          "profiles": ["baseline", "main"],
          "resolutions": ["720p", "1080p"],
          "framerates": [30]
        }
      ]
    }
  ]
}
```

### 14.3 Relationship to SDP

DSIP should support SDP interop but should not be limited to SDP.

Possible rule:

- DSIP-native negotiation uses structured JSON media descriptors.
- SIP/WebRTC gateways may include SDP as a transport binding object.
- If both structured media and SDP are present, the binding must define which one is authoritative.

Example:

```json
{
  "transport_binding": {
    "type": "webrtc",
    "sdp": "v=0..."
  }
}
```

### 14.4 Media Policy

Policy should be negotiated alongside media.

```json
{
  "policy": {
    "recording": "consent-required",
    "transcription": "allowed-with-notice",
    "ai_processing": "denied",
    "redistribution": "forbidden",
    "relay": "authorized-only"
  }
}
```

Policy statements do not magically enforce behavior. They provide signed declarations that clients, gateways, relays, and applications can enforce or display.

---

## 15. Interactive Media Profile v1.0

The Interactive Media Profile supports real-time two-way media between two or more endpoints.

### 15.1 Required Capabilities

A minimal implementation should support:

- DID or DID-compatible identity
- Signed invite/answer/reject/bye/error
- Version negotiation
- At least one audio codec
- At least one transport binding
- Media policy declaration
- Error handling

### 15.2 Recommended Transport Binding

The first implementation should define one recommended transport binding for interoperability.

Practical candidates:

- WebRTC binding for browsers and modern applications
- RTP/SRTP binding for SIP and telecom gateways

The spec may define both, but v1.0 interoperability should not require every endpoint to support every binding.

### 15.3 Example Invite Payload

```json
{
  "dsip": {
    "core": "1.0",
    "min_core": "1.0",
    "profiles": ["interactive-media/1.0"],
    "extensions": [],
    "critical": []
  },
  "type": "invite",
  "id": "01HZINVITEABC",
  "from": "did:key:z6MkCaller",
  "to": "did:web:example.com:users:bob",
  "issued_at": 1760000000,
  "expires_at": 1760000030,
  "intent": "interactive",
  "identity": {
    "display_name": "Alice",
    "claims": []
  },
  "media": [
    {
      "type": "audio",
      "direction": "sendrecv",
      "codecs": ["codec:audio/opus", "codec:audio/pcmu"]
    },
    {
      "type": "video",
      "direction": "sendrecv",
      "codecs": ["codec:video/h264"]
    }
  ],
  "transports": [
    {
      "id": "transport:webrtc",
      "ice": "supported"
    }
  ],
  "policy": {
    "recording": "consent-required",
    "ai_processing": "denied"
  }
}
```

---

## 16. Verified Broadcast Profile v1.0

The Verified Broadcast Profile supports signed publication and subscription metadata for live media streams.

The purpose is not to replace CDNs or streaming protocols. The purpose is to verify who published a stream, describe available variants, attach signed metadata, and preserve provenance through relays and transcoders.

### 16.1 Broadcast Publication Record

```json
{
  "dsip": {
    "core": "1.0",
    "min_core": "1.0",
    "profiles": ["verified-broadcast/1.0"],
    "extensions": ["broadcast-provenance/1.0"],
    "critical": []
  },
  "type": "publish",
  "id": "01HZPUBABC",
  "publisher": "did:web:wxyz.com",
  "stream_id": "did:web:wxyz.com:radio:main",
  "title": "WXYZ Live Radio",
  "state": "live",
  "issued_at": 1760000000,
  "expires_at": 1760000300,
  "variants": [
    {
      "id": "main-opus-low-latency",
      "media": ["audio"],
      "codec": "codec:audio/opus",
      "transport": "transport:webrtc",
      "uri": "wss://live.wxyz.com/dsip/webrtc/main"
    },
    {
      "id": "main-aac-hls",
      "media": ["audio"],
      "codec": "codec:audio/aac",
      "transport": "transport:hls",
      "uri": "https://live.wxyz.com/main.m3u8"
    }
  ],
  "policy": {
    "redistribution": "allowed-with-attribution",
    "recording": "allowed",
    "transcoding": "allowed"
  }
}
```

### 16.2 What Is Signed?

Broadcast signatures are tricky because CDNs often transcode media into adaptive bitrate variants. Signing the original raw media bytes will usually break after transcoding.

DSIP should define integrity modes.

```text
metadata-only       Publisher signs stream identity, title, policy, and variant metadata.
manifest-bound      Publisher signs a manifest or manifest hash.
segment-bound       Publisher signs segment hashes or a Merkle root of segments.
derivative-bound    Transcoder signs a derivative stream and references the original publisher record.
frame-bound         Future profile for signing individual media frames or groups of frames.
```

### 16.3 Provenance Through Relays and Transcoders

A relay or transcoder should not overwrite the original publisher identity.

Instead, it should add its own signed provenance statement.

```json
{
  "type": "broadcast.provenance",
  "original_stream": "did:web:wxyz.com:radio:main",
  "original_publication": "01HZPUBABC",
  "processor": "did:web:cdn.example",
  "operation": "transcode",
  "input_variant": "main-opus-low-latency",
  "output_variant": "main-aac-hls",
  "issued_at": 1760000100
}
```

Receivers can then display:

```text
Original publisher: WXYZ
Delivered by: Example CDN
Transcoded by: Example CDN
Integrity mode: derivative-bound
```

This makes provenance honest even when byte-for-byte media signatures cannot survive transcoding.

---

## 17. Rich Session Identity

Rich Caller ID should evolve into **Rich Session Identity**.

However, this must be designed carefully because identity UI can become a phishing vector.

### 17.1 No Generic Verified Badge

Clients should avoid generic “verified” badges.

Instead, display the basis of verification.

Examples:

```text
Self-issued identity
Domain verified by did:web
Organization credential issued by Example Trust Registry
Broadcast credential issued by State Media Registry
Gateway attested by Example Carrier
```

### 17.2 Logo and Brand Claims

Logos, avatars, brand names, and display names must be treated as claims, not truth.

A logo should only be shown as verified if:

- It is included in a signed credential or trusted metadata source.
- The issuer is trusted for brand/logo claims.
- The credential status has been checked.
- The client can explain the trust basis to the user.

### 17.3 Revocation

Credential revocation must be considered real-time enough for session establishment.

At minimum, clients should support:

- Credential expiration
- Status checks
- Revocation lists or status endpoints
- Cached status with short maximum age for high-risk claims
- Hard failure for revoked high-trust credentials

### 17.4 AI Disclosure

DSIP can include an AI disclosure field, but that field is not self-enforcing.

A malicious operator can omit it.

Therefore, AI disclosure should be treated as a policy and credential problem:

- AI agent credentials may require disclosure claims.
- Clients may label endpoints as “AI-disclosed” only when backed by a trusted credential.
- Organizations may require agent credentials for inbound/outbound AI sessions.
- Regulations may impose penalties for false disclosure.

Protocol fields help honest actors interoperate. They do not force dishonest actors to comply.

---

## 18. Abuse, Spam, and Sybil Resistance

Spam and abuse are among the hardest DSIP problems.

A system where anyone can mint unlimited `did:key` identities creates trivial Sybil attacks. At the same time, requiring strong credentials for everyone undermines open participation.

DSIP must acknowledge this tension directly.

### 18.1 Trust Tiers

DSIP should support trust tiers rather than one universal trust model.

```text
Tier 0: Anonymous / ephemeral
Tier 1: Self-issued persistent identity
Tier 2: Relationship-gated identity
Tier 3: Domain-bound identity
Tier 4: Credential-backed identity
Tier 5: Regulated or high-assurance identity
```

Clients and services can decide which tiers are allowed for which actions.

Examples:

- Anonymous calls may be blocked by default.
- Self-issued identities may require prior contact approval.
- Domain-bound identities may reach public business endpoints.
- Credential-backed identities may bypass spam screening.
- Regulated identities may access emergency or public-sector profiles.

### 18.2 Abuse Controls

DSIP should define hooks for abuse control, not one global algorithm.

Mechanisms may include:

- Contact allowlists
- First-contact consent prompts
- Proof-of-work or cost tokens
- Rate limits at relays
- Credential-gated access
- Reputation provider plugins
- User-controlled blocklists
- Organization policy engines
- Signed abuse reports
- Gateway-level traffic screening
- Paid relay quotas

### 18.3 Consent Receipts

Consent receipts can help with accountability, but they are not anti-spam by themselves.

A consent receipt may record:

- Who consented
- What was allowed
- When it was allowed
- Which profile it applies to
- Expiration
- Revocation

### 18.4 First-Contact Problem

The first-contact problem is central.

DSIP should define how an unknown identity requests permission to initiate future sessions without allowing that request mechanism to become spam.

Possible approaches:

- Low-bandwidth introduction envelope
- Contact token shared out of band
- QR-code pairing
- Organization intake endpoints
- Paid or rate-limited introduction requests
- Credential-backed introductions

This should be a v1.0 design focus, not a future afterthought.

---

## 19. Security Threat Model

DSIP should include a real threat model, not only a list of mitigations.

### 19.1 Assets

Assets to protect:

- Identity keys
- Device keys
- Recovery keys
- Session metadata
- Media negotiation contents
- Media encryption keys
- Presence state
- Publication records
- Credential status
- User consent decisions
- Gateway trust mappings

### 19.2 Attackers

Potential attackers:

- Passive network observer
- Malicious relay
- Malicious media server
- Compromised credential issuer
- Compromised DID controller key
- Compromised device key
- Spam originator
- Sybil identity farm
- Malicious broadcaster relay
- Downgrade attacker
- Replay attacker
- Resolver DoS attacker
- Cross-federation replay attacker
- Malicious gateway

### 19.3 Required Protections

DSIP Core v1.0 should require:

- Signed signaling envelopes
- Expiration timestamps
- Nonces or unique message IDs
- Replay detection within a session window
- Version negotiation covered by signatures
- Critical-extension negotiation
- Credential status checking for high-trust claims
- Explicit trust downgrade when crossing gateways
- Policy visibility before sensitive media actions

### 19.4 Downgrade Attacks

Attackers may try to remove encryption, remove critical extensions, force older protocol versions, remove AI disclosure, or strip policy fields.

Mitigation:

- Version and extension lists are signed.
- Required policies are marked critical.
- Responders echo selected versions and extensions.
- Clients fail closed when required extensions are missing.

### 19.5 Traffic Analysis

Even if signaling payloads are encrypted, metadata can leak:

- Who contacted whom
- When contact occurred
- How long sessions lasted
- Which relay was used
- Which profile was used
- Presence patterns

DSIP should support relay privacy and encrypted payloads, but should be honest that metadata privacy is difficult.

### 19.6 Resolver DoS

Resolvers and DID document hosts can be attacked.

Mitigations may include:

- Caching with signed records
- Multiple service endpoints
- Domain-level redundancy
- Optional transparency logs
- Rate limiting
- Relay fallback
- Graceful degradation using recently verified records

---

## 20. Accessibility Requirements

Accessibility should not be bolted on later.

DSIP profiles should treat accessibility media as first-class negotiable streams.

### 20.1 Real-Time Text

Interactive Media Profile should include support for real-time text negotiation.

RTT may use existing RTP/T.140 mechanisms where RTP is used, or equivalent real-time text data channels where WebRTC/QUIC is used.

### 20.2 Captions

Caption streams should include negotiated properties:

- Language
- Format
- Source
- Latency target
- Human-generated vs automatic
- Confidence metadata if machine-generated
- Persistence policy

Example:

```json
{
  "type": "caption",
  "format": "webvtt",
  "language": "en-US",
  "source": "automatic",
  "latency_target_ms": 1500
}
```

### 20.3 Sign Language Video

Sign language video should be a first-class media purpose, not just a generic camera feed.

```json
{
  "type": "video",
  "purpose": "sign-language",
  "language": "ase",
  "resolution_min": "720p",
  "framerate_min": 30
}
```

### 20.4 TTY and Legacy Interop

A future PSTN gateway profile should consider TTY/RTT interop requirements for regulated voice services.

---

## 21. Emergency Services and Regulated Profiles

Emergency calling conflicts with pure decentralization.

911, 112, 999, NG911, and similar systems require regulated behavior that may include:

- Verified location
- Persistent identifiers
- Carrier or provider accountability
- Emergency service routing
- Lawful intercept rules in some jurisdictions
- Abuse prevention
- Call-back mechanisms
- Reliability obligations

DSIP Core v1.0 should not claim to replace emergency calling.

Instead:

> Emergency communication should be a future regulated DSIP profile with stricter identity, location, gateway, and compliance requirements.

### 21.1 Gateway Model

A DSIP emergency profile likely requires carrier-class or public-authority gateways.

This does reintroduce centralization, but that is the regulatory reality of emergency communications.

### 21.2 Location

Location should not be mandatory for all DSIP sessions.

However, location may be mandatory for emergency profiles.

This distinction should be explicit:

```text
Normal DSIP sessions: location optional and privacy-preserving.
Emergency DSIP profile: verified location likely required.
Broadcast profile: location may be publisher metadata, not user metadata.
```

---

## 22. SIP/PSTN Gateway Reality

A DSIP-to-SIP mapping table is only a small part of PSTN interop.

A real gateway must handle:

- SIP INVITE/200 OK/ACK/BYE behavior
- SDP offer/answer mapping
- RTP/SRTP media anchoring
- E.164 numbering
- Number portability
- STIR/SHAKEN attestation
- Rich Call Data
- CNAM behavior
- Rate-center/routing requirements
- Emergency calling rules
- Lawful intercept obligations where applicable
- TCPA and robocall compliance where applicable
- Spam analytics and traffic labeling
- Trust downgrade signaling

DSIP should be honest:

> Crossing into the PSTN is a trust downgrade unless the gateway can preserve and assert DSIP identity semantics through supported PSTN identity mechanisms.

---

## 23. Economic and Operational Model

The v0.4 economic section listed possible businesses but did not explain who pays for the infrastructure.

DSIP should include operational reality.

### 23.1 Costs Exist

Real deployments need:

- TURN servers
- SFUs
- Media relays
- Broadcast relays
- DID resolvers
- Credential issuers
- Revocation infrastructure
- Abuse mitigation
- Monitoring
- Gateway infrastructure
- Customer support

“Free peer-to-peer” is possible only for a subset of sessions. Many users are behind NAT, many sessions need relays, and broadcast needs distribution infrastructure.

### 23.2 Payment Is Not Core Protocol

DSIP should not embed a payment system in v1.0.

Instead, DSIP should allow policy and authorization hooks:

- Relay authorization tokens
- Subscription credentials
- Quota declarations
- Enterprise policy checks
- Paid service endpoints
- Broadcast access tokens

### 23.3 Likely Operating Models

Possible DSIP operating models:

- Self-hosted personal DSIP agent
- Organization-hosted DSIP domain
- Commercial DSIP relay provider
- Enterprise DSIP gateway
- Broadcast identity and publication provider
- Credential issuer
- PSTN/SIP interop provider
- AI media gateway provider

The protocol should support these without requiring any single one.

---

## 24. Governance and Registries

Governance determines whether DSIP becomes a real standard or remains a proposal.

### 24.1 Initial Path

A realistic path could be:

1. Publish DSIP as an open technical draft.
2. Build a reference implementation.
3. Define test vectors and interop tests.
4. Gather feedback from SIP/WebRTC/DID/security communities.
5. Submit an Internet-Draft to the IETF if there is interest.
6. Coordinate DID/VC-related work with W3C ecosystems.
7. Create a lightweight DSIP registry process for early experimentation.

### 24.2 Registries

DSIP needs registries for:

- Core versions
- Profile identifiers
- Extension identifiers
- Media type identifiers
- Codec identifiers
- Transport identifiers
- Policy keys
- Error codes
- Credential claim types
- Endpoint classes
- Integrity modes

### 24.3 Registry Governance

Early registries may be maintained by the project, but a mature DSIP standard should move to a neutral governance body.

Possible homes:

- IETF working group or dispatch path
- W3C community group for identity-related pieces
- Independent DSIP foundation as an incubator
- IANA-style registries if standardized through IETF

### 24.4 Conformance

A DSIP implementation should be able to claim conformance to specific pieces:

```text
DSIP Core 1.0
DSIP Interactive Media Profile 1.0
DSIP Verified Broadcast Profile 1.0
DSIP WebRTC Binding 1.0
DSIP RTP/SRTP Binding 1.0
DSIP Broadcast Provenance Extension 1.0
```

This avoids meaningless claims like “supports DSIP” without saying which profiles are implemented.

---

## 25. Minimal Reference Implementation

A credible prototype should be small.

### 25.1 Phase 1: Core

Build:

- DID generation for `did:key`
- `did:web` resolver
- Signed DSIP-JOSE envelopes
- Version negotiation
- Invite/answer/reject/bye/error messages
- Structured media capability negotiation
- WebSocket signaling transport
- Basic WebRTC media binding
- CLI test tool
- Test vectors

### 25.2 Phase 2: Interactive Media

Build:

- Browser demo
- Native/CLI endpoint demo
- Audio call setup
- Video call setup
- Policy display
- Identity verification display
- Unknown identity warning
- Contact allowlist
- First-contact request flow

### 25.3 Phase 3: Verified Broadcast

Build:

- Broadcast publication record generator
- Signed publication verifier
- HLS/WebRTC variant advertisement
- Subscribe flow
- Basic publisher UI
- Basic receiver UI
- CDN/relay provenance proof-of-concept

### 25.4 Phase 4: SIP/WebRTC Gateway

Build:

- DSIP to SIP INVITE gateway
- SDP mapping
- RTP/SRTP media bridge
- Trust downgrade indicator
- Optional STIR/PASSporT/RCD mapping research

---

## 26. Example: Interactive Session Flow

1. Alice enters Bob’s alias.
2. Alice resolves the alias to Bob’s DID.
3. Alice resolves Bob’s DID document.
4. Alice discovers Bob’s DSIP service endpoint.
5. Alice sends a signed DSIP invite.
6. Bob verifies Alice’s DID and message signature.
7. Bob applies local trust policy.
8. Bob answers with selected media, codec, transport, and policy.
9. Both sides establish media using the negotiated binding.
10. Media flows.
11. Either side sends signed `bye`.

---

## 27. Example: Verified Broadcast Flow

1. WXYZ publishes a signed DSIP publication record.
2. A listener resolves `live@wxyz.com` or `did:web:wxyz.com:radio:main`.
3. The receiver verifies the publisher identity.
4. The receiver checks publication expiration and policy.
5. The receiver selects a compatible stream variant.
6. The receiver subscribes or fetches the advertised media endpoint.
7. If a CDN transcodes the stream, the CDN adds a signed provenance statement.
8. The receiver displays the original publisher and delivery path.

---

## 28. Summary

The stronger DSIP direction is not “SIP for everything.”

The stronger direction is:

> **A small decentralized session core with explicit profiles for trusted real-time media.**

DSIP should stay ambitious, but the v1.0 protocol must be narrow enough to implement, test, secure, and govern.

The first credible version should focus on:

- DID-based identity
- Signed signaling
- Version negotiation
- Media capability negotiation
- Trust-aware session identity
- Abuse-aware first-contact behavior
- Interactive media sessions
- Verified broadcast publication/subscription
- Clear extension and profile boundaries

Future profiles can add AI agents, device media, emergency services, contact centers, messaging, and other verticals once the core has proven itself.

The goal is not to create another protocol that can theoretically do everything.

The goal is to create a protocol that does a few foundational things well enough that others can build on it.

---

## 29. Short Positioning Statement

> DSIP is a decentralized session initiation protocol for trusted real-time media. It uses verifiable identity, signed signaling, and explicit media negotiation to let endpoints establish interactive sessions or publish verified live media without depending on phone numbers, carrier registrars, or proprietary platform identity.

---

## 30. Suggested New Title

**DSIP: A Decentralized Session Protocol for Trusted Real-Time Media**

Alternative titles:

- **DSIP: Rethinking Session Initiation for a Decentralized Media Internet**
- **DSIP: Verifiable Identity and Session Negotiation for Real-Time Media**
- **DSIP: An Open Protocol for Trusted Calls, Video, and Live Media**
- **DSIP: Beyond Phone Numbers, Toward Verifiable Real-Time Communication**

