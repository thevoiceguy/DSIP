# DSIP: Decentralized Session Initiation Protocol

## An Identity-First Protocol for Trusted Real-Time Media

**Version:** Draft v0.4  
**Status:** Proposal  
**Editor:** James Ferris  

---

## 1. Abstract

DSIP, the **Decentralized Session Initiation Protocol**, is an identity-first signaling and negotiation protocol for establishing trusted real-time media sessions between people, devices, applications, services, broadcasters, and AI agents.

DSIP is inspired by SIP, but it is not limited to telephony. Where SIP primarily initiated voice and video calls between user agents, DSIP initiates verifiable media sessions between any identity-aware endpoint. These sessions may include voice, video, messaging, live broadcast, conferencing, AI interaction, device media, sensor streams, captions, metadata, or future real-time media types.

DSIP replaces carrier-owned numbers, centralized registrars, siloed application identities, and hop-by-hop trust with:

- Self-sovereign identity using Decentralized Identifiers (DIDs)
- Cryptographically signed signaling
- Decentralized discovery and presence
- First-class media and codec negotiation
- Transport-independent session establishment
- Verifiable source identity for calls, broadcasts, devices, and AI agents
- Privacy-preserving security and selective disclosure
- Pragmatic interoperation with SIP, PSTN, WebRTC, HLS/DASH, and future media transports

The goal of DSIP is not only to modernize phone calls. The goal is to create an open trust and session layer for real-time communication across the internet.

---

## 2. Why DSIP Needs to Evolve Beyond Calls

The original DSIP concept began as a decentralized successor to SIP for secure voice, video, and messaging. That remains an important use case, but it is no longer the whole vision.

Real-time communication is expanding beyond phones and PBXs. Modern communication now includes:

- Human-to-human calls
- Video meetings
- AI voice agents
- AI-to-AI interactions
- Contact center media
- Live captions and transcription
- Smart speakers and voice assistants
- Vehicle communications
- Intercoms and access systems
- Public safety audio/video
- Radio and TV broadcasts
- Live streaming
- Gaming voice/video
- Remote device media
- Machine-to-machine media streams
- Sensor and telemetry channels

Today, each ecosystem solves identity, discovery, signaling, trust, and media negotiation differently.

Phone networks use numbers, carriers, SIP, SS7, and regulatory trust chains. Video platforms use proprietary account systems and signaling. Broadcasters use URLs, platform identities, HLS/DASH manifests, or app-specific discovery. AI voice systems use WebSockets, APIs, SIP trunks, or custom glue. IoT devices often depend on vendor clouds.

The result is a fragmented world where every platform has its own identity model, its own trust model, its own signaling layer, and its own media assumptions.

DSIP proposes a common control plane for trusted real-time media.

---

## 3. Updated Definition

DSIP stands for:

> **Decentralized Session Initiation Protocol**

DSIP is not merely “Decentralized SIP.”

A better definition is:

> DSIP is an identity-first signaling, discovery, and media negotiation protocol for establishing trusted real-time sessions between any identity-aware endpoint.

An endpoint may be:

- A person
- A phone
- A browser
- A mobile app
- A SIP gateway
- A video room
- A conference bridge
- An AI agent
- A contact center queue
- A radio station
- A TV broadcaster
- A camera
- A smart speaker
- A vehicle
- An IoT device
- A public safety system
- A media relay
- A software service

The endpoint does not need to be a phone. It only needs a verifiable identity, discoverable capabilities, and a way to participate in a negotiated media session.

---

## 4. Motivation

### 4.1 Identity Is Broken Across Real-Time Communications

Traditional caller identity is weak. Phone numbers can be spoofed. CNAM is inconsistent. STIR/SHAKEN improves parts of the PSTN problem, but it is still bound to carrier-controlled telephone numbers and does not solve identity across internet-native communication.

Video platforms, messaging platforms, broadcast platforms, and AI communication systems each create their own closed identity systems. A verified identity in one platform does not automatically carry to another.

DSIP makes identity intrinsic to the session.

### 4.2 Signaling Is Fragmented

SIP, WebRTC signaling, proprietary video platforms, streaming manifests, contact center APIs, and AI voice APIs all solve overlapping problems in incompatible ways.

They all need to answer similar questions:

- Who is initiating this session?
- Who is the intended recipient or audience?
- Can the source be verified?
- What media types are supported?
- What codecs are available?
- Which transport should carry the media?
- Is the session live, interactive, broadcast, recorded, or relayed?
- What security and privacy policies apply?

DSIP provides a common session layer for those questions.

### 4.3 Deepfake Audio and Video Require Verifiable Source Identity

As synthetic audio and video become easier to create, the internet needs a way to verify the source of real-time media.

A DSIP-compatible client should be able to determine whether a media session is:

- A verified person
- A verified organization
- A verified broadcaster
- A verified AI agent
- A verified device
- A relay of a verified source
- An unverified or anonymous source

This is not only a telecom issue. It applies to news, emergency broadcasts, business communications, customer support, public safety, and AI-generated media.

### 4.4 Codec and Transport Negotiation Need a Modern Standard

SIP/SDP solved a major problem by allowing endpoints to negotiate media. DSIP keeps that idea, but expands it for modern media environments.

DSIP should negotiate:

- Audio codecs
- Video codecs
- Text and caption streams
- Data channels
- Transcription streams
- AI context streams
- Broadcast variants
- Latency requirements
- Bandwidth constraints
- Encryption modes
- Consent and recording policy
- Transport bindings
- Relay and federation options

### 4.5 Real-Time Media Is No Longer Only Conversational

A call is one type of session. DSIP should also support:

- One-to-one communication
- One-to-many broadcast
- Many-to-many conferences
- Publish/subscribe media
- Federated rebroadcast
- AI-assisted sessions
- Device media streams
- Emergency alerts
- Low-latency live events

The session model should be explicit, negotiated, and extensible.

---

## 5. Core Principles

1. **Identity-first communication**  
   Every DSIP participant is identified by a DID or equivalent verifiable identity.

2. **End-to-end verifiability**  
   DSIP signaling is signed. Identity is proven cryptographically, not simply asserted by a network intermediary.

3. **Media-agnostic design**  
   DSIP supports audio, video, messaging, captions, metadata, data channels, sensor streams, and future media types.

4. **Transport independence**  
   DSIP negotiates sessions that may use RTP/SRTP, WebRTC, QUIC, WebTransport, HLS, DASH, multicast, or future transports.

5. **Decentralized discovery**  
   Endpoints are discovered using DID documents, DNS, WebFinger, DHTs, federation, and other decentralized or federated mechanisms.

6. **Codec negotiation as a first-class feature**  
   DSIP treats media capability exchange as a central protocol function, not an afterthought.

7. **Privacy by design**  
   DSIP supports selective disclosure, encrypted signaling payloads, ephemeral identities, private presence, and minimal metadata exposure.

8. **Composable application profiles**  
   Phone calls, video conferences, broadcasts, AI agents, messaging, and device streams are profiles built on the same foundation.

9. **Pragmatic interop**  
   DSIP must interoperate with SIP/PSTN, WebRTC, existing streaming systems, emergency networks, and enterprise communication platforms.

10. **Open participation**  
   Users, companies, governments, developers, broadcasters, and open-source communities should be able to operate DSIP endpoints, resolvers, relays, gateways, and media services.

---

## 6. Scope and Non-Goals

### 6.1 DSIP Defines

DSIP defines:

- Identity binding for real-time sessions
- Endpoint discovery
- Presence and availability records
- Session initiation messages
- Session state updates
- Media capability advertisement
- Codec negotiation
- Transport negotiation
- Security and trust metadata
- Application profile conventions
- Interoperation models

### 6.2 DSIP Does Not Require

DSIP does not require:

- A blockchain
- A single global registrar
- Carrier-controlled phone numbers
- A specific codec
- A specific media transport
- A specific relay network
- A single application provider
- A single identity provider
- A single commercial trust authority

### 6.3 DSIP Is Not Intended to Replace Every Media Protocol

DSIP should not replace RTP, SRTP, WebRTC, HLS, DASH, QUIC, or media codecs.

Instead, DSIP should act as the control plane that discovers endpoints, verifies identities, negotiates capabilities, selects transports, and establishes policy before media flows.

---

## 7. Layered Architecture

DSIP is best understood as a layered protocol stack.

```text
+-----------------------------------------------------------+
| Application Profiles                                      |
| call | conference | broadcast | AI agent | device | msg    |
+-----------------------------------------------------------+
| Session Layer                                             |
| invite | answer | reject | update | bye | publish | join   |
+-----------------------------------------------------------+
| Media Negotiation Layer                                   |
| audio | video | text | data | captions | codecs | policy  |
+-----------------------------------------------------------+
| Trust and Identity Layer                                  |
| DIDs | signatures | VCs | attestation | reputation        |
+-----------------------------------------------------------+
| Discovery and Presence Layer                              |
| DID docs | DNS | WebFinger | DHT | federation | relays     |
+-----------------------------------------------------------+
| Transport Bindings                                        |
| QUIC | WebSocket | HTTPS | libp2p | SIP gateway          |
+-----------------------------------------------------------+
| Media Plane                                               |
| SRTP | WebRTC | RTP | QUIC media | HLS | DASH | multicast |
+-----------------------------------------------------------+
```

This layered model keeps DSIP flexible. A phone call, live TV stream, AI agent session, and device video feed should not need completely different trust and discovery models.

---

## 8. Identity Layer

### 8.1 DID-Based Identity

DSIP endpoints are identified using Decentralized Identifiers.

Recommended DID methods:

- `did:key` for individuals, ephemeral endpoints, agents, and devices
- `did:web` for organizations, brands, broadcasters, public agencies, and enterprises
- Optional ledger-backed DID methods for audit-heavy environments

Example identities:

```text
did:key:z6MkAlice...
did:web:example.com:users:alice
did:web:acme.com:support
did:web:acme.com:agents:billing-bot
did:web:wxyz.com:radio:main
did:web:city.gov:emergency-alerts
did:web:vehicle.example:vin:123456
did:web:building.example:front-door-camera
```

### 8.2 Endpoint Classes

DSIP should define endpoint classes to help clients make trust and UX decisions.

Possible endpoint classes:

```text
person
organization
agent
device
broadcaster
relay
gateway
conference
queue
emergency-service
application
anonymous
```

A DSIP client could render these differently:

```text
Verified Person: James Ferris
Verified Organization: ACME Bank
Verified AI Agent: ACME Billing Assistant
Verified Broadcast: WXYZ Emergency Weather Feed
Verified Device: Building A Front Door Intercom
Unverified Endpoint: Anonymous Caller
```

### 8.3 Verifiable Credentials

DSIP should support Verifiable Credentials for identity claims.

Examples:

- Display name credential
- Organization credential
- Employee role credential
- Agent authorization credential
- Device ownership credential
- Broadcaster license credential
- Emergency service credential
- Reputation credential
- Compliance credential

A support bot could prove it is authorized by a company. A broadcaster could prove it controls an official station feed. A device could prove it belongs to a building or vehicle.

### 8.4 Device and Agent Identity

DSIP should treat devices and AI agents as first-class identities, not as secondary extensions of user accounts.

A device may have:

- A manufacturer credential
- An owner credential
- A location or deployment credential
- A secure element key
- A rotation policy
- A revocation mechanism

An AI agent may have:

- An operator credential
- A role credential
- A capability manifest
- A policy declaration
- A disclosure flag indicating that it is non-human

Example:

```json
{
  "id": "did:web:acme.com:agents:support",
  "class": "agent",
  "operator": "did:web:acme.com",
  "disclosure": "ai-agent",
  "roles": ["customer-support", "billing"],
  "capabilities": ["voice", "transfer", "transcription", "human-escalation"]
}
```

---

## 9. Discovery and Presence

### 9.1 Discovery Goals

DSIP discovery should answer:

- Where is this identity reachable?
- What services does it expose?
- Is it online, offline, busy, publishing, or relay-only?
- Which transports are available?
- Which application profiles are supported?
- Which media capabilities are advertised?
- Which trust credentials are available?

### 9.2 DID Document Service Entry

A DID document may expose a DSIP service entry.

```json
{
  "id": "did:web:example.com:users:alice",
  "service": [
    {
      "id": "#dsip",
      "type": "DSIPService",
      "serviceEndpoint": {
        "https": ["https://dsip.example.com/alice"],
        "wss": ["wss://relay.example.com/dsip/alice"],
        "quic": ["quic://dsip.example.com:443/alice"],
        "libp2p": ["/dns4/dsip.example.com/udp/443/quic-v1/p2p/12D3KooW..."]
      }
    }
  ]
}
```

### 9.3 Human-Friendly Names

Humans should not need to exchange raw DID strings.

DSIP should support:

- WebFinger aliases
- DNS TXT/SRV discovery
- QR codes
- Contact cards
- Organization directories
- Verified short names
- Optional handle systems

Examples:

```text
alice@example.com
support@acme.com
wxyz.com/radio/main
city.gov/emergency/live
frontdoor@building.example
```

These aliases resolve to DIDs, not to carrier-owned numbers.

### 9.4 Presence Records

A DSIP presence record is a short-lived signed record that describes current reachability and optional capabilities.

```json
{
  "type": "dsip.presence.v1",
  "did": "did:web:example.com:users:alice",
  "state": "available",
  "profiles": ["call", "message", "video"],
  "endpoints": {
    "wss": ["wss://relay.example.com/dsip/conn/abcd"],
    "quic": ["quic://198.51.100.10:443/session"]
  },
  "ttl": 180,
  "seq": 58,
  "exp": 1760000000,
  "sig": "base64url(signature)"
}
```

Presence should be optional and privacy-preserving. Some endpoints may only expose relay-based reachability. Some identities may not publish presence at all.

### 9.5 Broadcast Publication Records

Broadcast endpoints need a related but different concept: publication.

```json
{
  "type": "dsip.publication.v1",
  "publisher": "did:web:wxyz.com",
  "stream_id": "did:web:wxyz.com:radio:main",
  "title": "WXYZ Live Radio",
  "state": "live",
  "profiles": ["broadcast", "audio"],
  "variants": [
    {
      "media": "audio",
      "codec": "opus",
      "sample_rate": 48000,
      "channels": 2,
      "transport": "webrtc",
      "endpoint": "wss://live.wxyz.com/dsip"
    },
    {
      "media": "audio",
      "codec": "aac",
      "transport": "hls",
      "endpoint": "https://live.wxyz.com/main.m3u8"
    }
  ],
  "exp": 1760000000,
  "sig": "base64url(signature-by-broadcaster)"
}
```

This lets receivers verify the source of a live audio or video feed, even if the stream is distributed through third-party relays.

---

## 10. Signaling Protocol

### 10.1 Envelope Format

All DSIP signaling messages are carried in signed envelopes.

DSIP envelopes may be encoded as JSON or CBOR. Signatures may use JWS or COSE.

```json
{
  "type": "dsip.invite.v1",
  "id": "uuid",
  "ts": 1760000000,
  "from": "did:key:z6MkCaller",
  "to": "did:web:example.com:users:bob",
  "profile": "call",
  "intent": "interactive",
  "capabilities": {},
  "media": {},
  "network": {},
  "policy": {},
  "identity": {},
  "sig": {
    "alg": "Ed25519",
    "kid": "did:key:z6MkCaller#key-1",
    "value": "base64url(signature)"
  }
}
```

### 10.2 Core Message Types

Minimum conversational session messages:

```text
dsip.invite      Start a session
dsip.answer      Accept a session
dsip.reject      Reject a session
dsip.update      Modify session parameters
dsip.candidate   Exchange network candidates
dsip.bye         End a session
dsip.error       Report a protocol or policy failure
```

Publication and subscription messages:

```text
dsip.publish     Publish a live stream or availability record
dsip.subscribe   Subscribe to a stream, presence, or event source
dsip.notify      Send subscription updates
dsip.unpublish   Stop publishing
dsip.unsubscribe Stop subscribing
```

Conference and group messages:

```text
dsip.join        Join a room or group session
dsip.leave       Leave a room or group session
dsip.refer       Refer or transfer a participant
dsip.control     Send authorized control actions
dsip.floor       Request or grant speaking/control floor
```

Messaging and data messages:

```text
dsip.msg         Send encrypted message payload
dsip.receipt     Delivery/read receipt
dsip.typing      Typing or composition indicator
dsip.data        Application-defined data payload
```

### 10.3 Session Intent

DSIP should separate session intent from media type.

Examples:

```text
interactive      Real-time two-way communication
broadcast        One-to-many live media
conference       Many-to-many communication
relay            Third-party relay or rebroadcast
recording        Capture or archive media
monitoring       Listen-only or observe-only session
ai-assist        AI participates in or augments the session
device-control   Media session with control channel
emergency        Emergency or public safety priority session
```

This matters because a video stream may be a call, a broadcast, a camera feed, or an emergency event.

---

## 11. Application Profiles

DSIP should define application profiles that build on the same protocol foundation.

### 11.1 Call Profile

The call profile supports classic one-to-one or one-to-few interactive sessions.

Common media:

- Audio
- Video
- Text chat
- Captions
- Screen share
- Data channel

Common actions:

- Invite
- Answer
- Reject
- Hold/resume
- Transfer
- Add participant
- End

### 11.2 Conference Profile

The conference profile supports rooms, meetings, webinars, and group conversations.

Common topologies:

- Mesh
- SFU
- MCU
- Hybrid

Capabilities:

- Join/leave
- Participant list
- Moderator controls
- Floor control
- Recording policy
- Captions
- Screen share
- Breakout groups

### 11.3 Broadcast Profile

The broadcast profile supports one-to-many media distribution.

Examples:

- Radio broadcast
- TV audio/video
- Emergency broadcast
- Sports commentary
- Live event stream
- Public meeting stream
- Concert stream
- Government announcement

Broadcast profile features:

- Publisher identity verification
- Stream publication records
- Media variants
- Low-latency and high-scale options
- Relay authorization
- Signed metadata
- Emergency override
- Multi-language audio tracks
- Captions and transcripts

### 11.4 AI Agent Profile

The AI agent profile supports real-time interaction with AI systems.

Examples:

- Customer support agent
- Personal assistant
- Translation agent
- Transcription agent
- Voice bot
- Meeting assistant
- Agent-to-agent negotiation

Required properties:

- AI disclosure
- Operator identity
- Capability advertisement
- Human escalation support
- Recording/transcription policy
- Data retention policy
- Consent model

### 11.5 Device Media Profile

The device media profile supports real-time sessions with cameras, intercoms, smart speakers, vehicles, industrial equipment, and sensors.

Examples:

- Doorbell camera
- Building intercom
- Vehicle voice/video session
- Factory floor panel
- Baby monitor
- Security camera
- Emergency call box

Capabilities:

- Audio/video stream
- Push-to-talk
- Control channel
- Device attestation
- Location policy
- Owner authorization
- Local network fallback

### 11.6 Messaging Profile

The messaging profile supports encrypted asynchronous and synchronous messaging.

Common features:

- One-to-one messages
- Group messages
- Delivery receipts
- Typing indicators
- Edits/deletes
- Attachments
- Offline envelopes
- MLS for groups

Messaging remains a DSIP profile, not the core definition of the protocol.

---

## 12. Media Negotiation

### 12.1 Goals

DSIP media negotiation should allow endpoints to agree on:

- Media types
- Codecs
- Codec parameters
- Bitrate
- Resolution
- Frame rate
- Sample rate
- Channel count
- Packetization interval
- Latency target
- Transport
- Encryption
- Relay mode
- Simulcast/SVC options
- Captions/transcription streams
- Recording permissions
- AI processing permissions

### 12.2 Media Types

Initial media types:

```text
audio
video
text
data
caption
transcript
screen
metadata
control
sensor
ai-context
```

Future media types should be added through an extension registry.

### 12.3 Capability Advertisement

Example capability advertisement:

```json
{
  "media": {
    "audio": {
      "codecs": [
        { "name": "opus", "sample_rates": [16000, 48000], "channels": [1, 2] },
        { "name": "pcmu", "sample_rates": [8000], "channels": [1] },
        { "name": "aac", "sample_rates": [44100, 48000], "channels": [2] }
      ]
    },
    "video": {
      "codecs": [
        { "name": "av1", "resolutions": ["720p", "1080p", "4k"], "framerates": [24, 30, 60] },
        { "name": "vp9", "resolutions": ["720p", "1080p"], "framerates": [30, 60] },
        { "name": "h264", "resolutions": ["480p", "720p", "1080p"], "framerates": [24, 30] }
      ]
    },
    "caption": {
      "formats": ["webvtt", "ttml", "plain-text", "json-events"]
    },
    "data": {
      "channels": ["control", "metadata", "ai-context"]
    }
  },
  "transports": ["webrtc", "srtp", "quic", "webtransport", "hls", "dash"],
  "encryption": ["dtls-srtp", "sframe", "mls", "tls"],
  "latency": {
    "target_ms": 150,
    "max_ms": 500
  }
}
```

### 12.4 Negotiated Result

Example negotiated session:

```json
{
  "accepted_media": [
    {
      "type": "audio",
      "codec": "opus",
      "sample_rate": 48000,
      "channels": 2,
      "bitrate": 64000
    },
    {
      "type": "video",
      "codec": "h264",
      "resolution": "1080p",
      "framerate": 30,
      "bitrate": 2500000
    },
    {
      "type": "caption",
      "format": "webvtt",
      "source": "server-assisted"
    }
  ],
  "transport": "webrtc",
  "encryption": "dtls-srtp",
  "relay": "sfu",
  "recording": {
    "allowed": true,
    "consent": "required"
  }
}
```

### 12.5 Relationship to SDP

DSIP may carry SDP for interoperability, especially with SIP and WebRTC systems.

However, DSIP should not be limited to SDP. DSIP should define a structured media negotiation model that can map to SDP when needed.

This allows DSIP to negotiate modern and future media sessions without being constrained by legacy assumptions.

---

## 13. Transport Bindings

DSIP signaling should support multiple transport bindings.

Potential signaling transports:

- HTTPS
- WebSocket
- QUIC
- WebTransport
- libp2p
- SIP gateway mapping
- Message queue or broker-based transport for enterprise environments

Potential media transports:

- RTP
- SRTP
- WebRTC
- QUIC media
- WebTransport
- HLS
- DASH
- SRT
- RIST
- Multicast RTP
- Future low-latency media transports

DSIP should negotiate the best transport based on the session profile.

A phone call may prefer SRTP or WebRTC. A live broadcast may prefer QUIC or HLS. A local emergency alert may prefer multicast. An enterprise AI gateway may prefer RTP plus a WebSocket side channel.

---

## 14. Trust, Reputation, and Source Verification

### 14.1 Trust Model

DSIP trust is based on cryptographic identity and verifiable claims.

A receiver should be able to verify:

- The message was signed by the claimed sender
- The sender controls the DID
- The DID resolves to expected service endpoints
- Any attached credentials are valid
- The session has not been replayed or tampered with
- The media source matches the negotiated session

### 14.2 Rich Real-Time Identity

The original DSIP concept included Rich Caller ID. In v0.4, this should expand to **Rich Session Identity**.

Rich Session Identity may include:

- Display name
- Organization
- Role
- Endpoint class
- Avatar or logo
- Verified website
- AI disclosure
- Device type
- Broadcast title
- Emergency status
- Trust score
- Issuer credentials

Example:

```json
{
  "type": "rsi.v1",
  "displayName": "WXYZ News Live",
  "class": "broadcaster",
  "organization": "did:web:wxyz.com",
  "logo": "https://wxyz.com/logo.png",
  "credentials": [
    {
      "type": ["VerifiableCredential", "BroadcasterCredential"],
      "issuer": "did:web:fcc.example",
      "credentialSubject": {
        "id": "did:web:wxyz.com:tv:main",
        "service": "broadcast-video"
      }
    }
  ]
}
```

### 14.3 Verified Relays and Rebroadcasts

Broadcast and relay scenarios require source preservation.

A third party may relay a stream, but receivers should still be able to verify the original publisher.

DSIP should support:

- Original publisher signature
- Relay signature
- Relay authorization proof
- Chain of custody metadata
- Tamper-evident stream metadata

This is useful for public safety, journalism, government broadcasts, live sports, and federated content distribution.

---

## 15. Privacy and Security

### 15.1 Threats

DSIP should address:

- Caller/source spoofing
- Deepfake impersonation
- Replay attacks
- Presence tracking
- Metadata leakage
- Relay abuse
- Unauthorized recording
- Unauthorized AI processing
- Key compromise
- Device cloning
- Spam and robocalling
- Broadcast hijacking
- Emergency alert spoofing

### 15.2 Mitigations

Mitigations include:

- Signed signaling
- Short-lived envelopes
- Nonces and sequence numbers
- Encrypted payloads
- DID key rotation
- Device attestation
- Verifiable credentials
- Selective disclosure
- Ephemeral DIDs
- Relay rate limiting
- Reputation policies
- Consent receipts
- Media path binding
- Emergency publisher allowlists

### 15.3 Consent and Policy

DSIP should make policy explicit.

Examples:

```json
{
  "policy": {
    "recording": "consent-required",
    "transcription": "allowed",
    "ai_processing": "allowed-with-disclosure",
    "retention": "30-days",
    "redistribution": "forbidden",
    "relay": "authorized-only"
  }
}
```

Policies should be signed and visible to participants before or during session establishment.

---

## 16. Emergency and Public Safety

Emergency communication remains critical, but in v0.4 it should be generalized beyond emergency calling.

DSIP should support:

- Emergency calls
- Emergency broadcasts
- Public safety video
- Verified alert feeds
- Dispatch channels
- Location-aware routing
- Priority treatment
- Fallback to PSTN/NG911 where required

### 16.1 Emergency Session Types

```text
emergency-call
emergency-broadcast
public-safety-video
dispatch-audio
verified-alert
```

### 16.2 Emergency Identity

Emergency identities should be operated or certified by appropriate authorities.

Examples:

```text
did:web:911.us
did:web:112.eu
did:web:city.gov:emergency-alerts
did:web:county.gov:dispatch
did:web:weather.gov:alerts
```

### 16.3 Location and Privacy

Location should not be mandatory for all DSIP use cases.

Instead, DSIP should define context-specific location disclosure:

- No location shared by default
- Approximate region for routing when needed
- Precise location for emergency sessions
- Device-attested location for regulated use cases
- Zero-knowledge region proof for privacy-preserving eligibility

The earlier idea of verifiable geolocation remains valuable, but it should not be globally required for all DSIP endpoints.

---

## 17. Interoperability

### 17.1 SIP and PSTN

DSIP should interoperate with SIP and PSTN through gateways.

Mappings may include:

```text
dsip.invite        <-> SIP INVITE
dsip.answer        <-> SIP 200 OK
dsip.bye           <-> SIP BYE
dsip.refer         <-> SIP REFER
dsip.media         <-> SDP
dsip.identity      <-> SIP Identity / P-Asserted-Identity / STIR-SHAKEN context
DSIP DID           <-> E.164 number credential or gateway identity
```

SIP/PSTN interop will be imperfect because the PSTN cannot preserve all DSIP trust semantics end-to-end.

### 17.2 WebRTC

DSIP can be used as a standardized signaling and identity layer for WebRTC.

In this model:

- DSIP handles identity, discovery, session negotiation, and policy
- WebRTC handles ICE, DTLS-SRTP, congestion control, and media transport

### 17.3 Broadcast Systems

DSIP can bind to existing broadcast and streaming systems.

Examples:

- HLS playlist as negotiated media variant
- DASH manifest as negotiated media variant
- WebRTC low-latency stream for interactive broadcast
- SRT/RIST contribution feed
- Multicast local distribution

DSIP does not need to replace these systems. It can verify the publisher, advertise variants, negotiate access, and preserve trust metadata.

### 17.4 AI Voice Systems

DSIP can interoperate with AI media systems through gateways.

Examples:

- DSIP to OpenAI Realtime API gateway
- DSIP to Deepgram/AssemblyAI transcription gateway
- DSIP to TTS gateway
- DSIP to SIP-based AI agent
- DSIP to contact center AI assistant

The AI profile should make AI identity, disclosure, retention, and escalation explicit.

---

## 18. Network Components

### 18.1 DSIP Agent

A DSIP Agent is any endpoint capable of participating in DSIP signaling.

Responsibilities:

- Manage identity keys
- Resolve DIDs
- Publish presence or publication records
- Verify signatures
- Advertise capabilities
- Negotiate media
- Enforce local policy
- Establish media transport

### 18.2 Resolver

Resolvers retrieve and verify DID documents, service records, aliases, and trust metadata.

### 18.3 Relay

Relays forward signaling and optionally support store-and-forward envelopes.

Relays should not need plaintext access to signaling payloads unless explicitly authorized.

### 18.4 Media Relay

Media relays include TURN servers, SFUs, MCUs, broadcast relays, edge caches, and media gateways.

### 18.5 Gateway

Gateways bridge DSIP to other systems:

- SIP/PSTN
- WebRTC applications
- Contact centers
- Broadcast platforms
- AI APIs
- Enterprise communication systems
- IoT vendor clouds

### 18.6 Trust Authority / Credential Issuer

Credential issuers provide verifiable claims. DSIP should not require one global trust authority. Different communities and industries may define their own trusted issuers.

---

## 19. Example Flows

### 19.1 Person-to-Person Call

1. Alice selects Bob’s verified handle.
2. Alice resolves Bob’s DID.
3. Alice retrieves Bob’s presence record.
4. Alice sends a signed `dsip.invite` with audio/video capabilities.
5. Bob verifies Alice’s identity and credentials.
6. Bob answers with mutually supported media.
7. ICE or another negotiated transport completes.
8. Encrypted media flows.
9. Either side sends `dsip.bye` to end the session.

### 19.2 Verified Radio Broadcast

1. A radio station publishes a signed DSIP publication record.
2. A listener searches for or follows the station identity.
3. The listener verifies the broadcaster DID and credentials.
4. The client selects the best supported media variant.
5. The listener subscribes to the stream.
6. Audio flows over WebRTC, QUIC, HLS, or another negotiated transport.
7. Metadata remains signed by the broadcaster.

### 19.3 Verified TV Broadcast with Alternate Audio

1. A TV broadcaster publishes a video stream with multiple audio tracks.
2. The DSIP publication record lists variants for video, English audio, Spanish audio, captions, and audio-only mode.
3. The receiver verifies the broadcaster.
4. The receiver negotiates H.264 video, English Opus audio, and WebVTT captions.
5. During an emergency, the broadcaster publishes a signed emergency override message.
6. Receivers verify the override and switch to the alert track.

### 19.4 AI Customer Support Agent

1. A user contacts `support@acme.com`.
2. The alias resolves to `did:web:acme.com:agents:support`.
3. The agent presents credentials proving it is operated by ACME.
4. The agent discloses that it is AI.
5. The session negotiates voice, transcript, and optional screen share.
6. The user consents to transcription.
7. The AI handles the call or escalates to a human using `dsip.refer` or `dsip.join`.

### 19.5 Device Video Session

1. A building intercom publishes limited DSIP reachability.
2. A resident initiates a signed session to the device.
3. The device verifies the resident’s access credential.
4. The session negotiates audio, video, and a control channel.
5. The resident speaks to the visitor and optionally unlocks the door through an authorized control action.

---

## 20. Economic Model

DSIP should support both free and commercial operation.

Possible models:

- Free peer-to-peer sessions
- Paid relays
- Paid SFU/media relay usage
- Broadcast subscription access
- Enterprise-managed DSIP services
- Credential issuance services
- Reputation and abuse-prevention services
- Contact center / AI agent platforms
- Developer APIs and SDKs

Payments should be optional. The protocol should work without built-in payments, but should allow metering and authorization where required.

---

## 21. Governance and Extension Model

DSIP should define a core protocol and a registry of extensions.

Potential registries:

- Application profiles
- Media types
- Codec identifiers
- Transport bindings
- Error codes
- Credential types
- Policy fields
- Endpoint classes
- Trust frameworks

The core should remain small enough to implement, while extensions allow DSIP to evolve.

---

## 22. Minimal DSIP v0.4 Implementation

A minimal DSIP prototype should include:

- DID identity generation
- DID resolution for `did:key` and `did:web`
- Signed signaling envelopes
- Basic presence record
- `invite`, `answer`, `reject`, `bye`, and `error`
- Audio capability negotiation
- Video capability negotiation
- WebRTC transport binding
- Basic rich session identity display
- Simple relay support
- SIP gateway proof of concept

A second milestone should include:

- Broadcast publication records
- Subscribe/notify flow
- AI agent profile
- Device profile
- Messaging profile
- Policy negotiation
- Credential verification
- Media relay authorization

---

## 23. Relationship to SIP

SIP was one of the most important real-time communication protocols ever created. It gave the internet a way to initiate sessions, negotiate media using SDP, and build interoperable voice and video systems.

DSIP should preserve the good ideas:

- Session initiation
- User agents
- Media negotiation
- Proxy/relay concepts
- Interoperability
- Extensibility
- Separation of signaling and media

But DSIP should not inherit all of SIP’s assumptions:

- Phone numbers as primary identity
- Carrier-controlled trust
- Hop-by-hop security
- Registrar-centric reachability
- Legacy telephony bias
- Weak caller identity
- SDP-only media expression
- Limited awareness of AI, devices, broadcasts, and modern application models

DSIP is the spiritual successor to SIP, not a wire-compatible replacement.

---

## 24. Conclusion

DSIP began as an idea for decentralized SIP. The stronger vision is larger.

The internet needs a common way to establish trusted real-time media sessions across people, devices, applications, broadcasters, AI agents, and communication systems.

That requires more than a new phone protocol. It requires a decentralized session layer that can answer:

- Who is participating?
- Can their identity be verified?
- What kind of session is being requested?
- What media types are supported?
- Which codecs and transports can be used?
- What policies apply?
- Can the media source be trusted?
- Can the session interoperate with existing systems?

DSIP should become that layer.

> **DSIP is an identity-first protocol for trusted real-time media sessions.**

Phone calls are one use case. Video meetings are another. Radio and TV broadcasts are another. AI agents, device streams, public safety systems, and future media applications are all part of the same larger communication fabric.

The future of real-time communication should not be locked inside phone numbers, carrier registrars, proprietary meeting platforms, vendor clouds, or app-specific identities.

It should be open, verifiable, decentralized, and media-native from the start.

---

## 25. Glossary

**AI Agent** — A software-based participant capable of real-time interaction using speech, text, video, or data.

**Application Profile** — A DSIP-defined usage pattern such as call, conference, broadcast, messaging, AI agent, or device media.

**DID** — Decentralized Identifier.

**DSIP Agent** — Any endpoint that implements DSIP signaling and identity verification.

**Endpoint** — A person, device, service, application, agent, gateway, broadcaster, or relay that participates in DSIP.

**Media Negotiation** — The process of agreeing on media types, codecs, transports, encryption, and policy.

**Publication Record** — A signed record describing a live or available broadcast/media stream.

**Rich Session Identity** — Verifiable identity metadata associated with a DSIP session.

**Session Intent** — The purpose of a session, such as call, broadcast, conference, AI assist, emergency, or device control.

**Transport Binding** — A mapping between DSIP negotiation and an underlying signaling or media transport.

**VC** — Verifiable Credential.

