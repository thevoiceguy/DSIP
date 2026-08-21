# DSIP RTP/SRTP Media Binding 1.0 — `transport:rtp`

**Status:** DRAFT, companion document to DSIP (staged for v0.8). Normative for the `transport:rtp`
media transport binding, used by the Gateway Profile toward SIP/PSTN trunks. **Conformance:** the
SDP-mapping and reason vectors that exercise it are in `impl/vectors/gateway/` (G§6); a dedicated
`media-binding-rtp/` category is added when the binding lands in code (plan G5 follow-on).
Resolves spec-gap 30 (§17.2/§24.4 list this binding; it did not exist).
**Editor's note:** written from the reference gateway's SIP-side media
(`impl/crates/dsip-gateway/src/host/media.rs`, `sip_leg.rs`), which uses forge-media's RTP/SRTP.

RFC 2119 / RFC 8174 keywords. This binding's sections are cited `R§n`.

---

## R§1 Scope

`transport:rtp` describes non-WebRTC RTP media as used by SIP and telecom endpoints: RTP/RTCP
(RFC 3550) keyed by SDES (`a=crypto`, RFC 4568) or DTLS-SRTP (RFC 5763/5764), or — behind a trunk
the operator explicitly vouches for — plain RTP. It is the SIP-side counterpart to the WebRTC
Media Binding; a gateway (Gateway Profile) bridges one of each.

This binding defines the descriptor (R§2), the SDP profile and keying modes (R§3), the encryption
floor and the plain-RTP exception (R§4), codec mapping and transcoding (R§5), and DTMF (R§6).

Out of scope: ICE (SIP endpoints in scope here are reachable trunk addresses or use the operator's
SBC for NAT traversal; ICE is the WebRTC binding's concern), and BUNDLE (one m= section per media).

## R§2 Descriptor

A `transport:rtp` descriptor rides in `transports[]` on `invite`/`update`/`answer`:

```json
{ "id": "transport:rtp", "srtp": "sdes", "sdp": "v=0\r\n…m=audio 20000 RTP/SAVP 0 8\r\n…" }
```

- `id` (required): `transport:rtp`.
- `srtp` (required on offers): the keying mode — `sdes` | `dtls` | `none`. `none` is permitted only
  under R§4.
- `sdp` (required): the SDP offer/answer for this leg.

As in the WebRTC binding (B§2.1), the structured `media` descriptors are authoritative for *what*
is negotiated; the SDP is authoritative for RTP transport parameters (addresses, payload types,
`a=crypto` or `a=fingerprint`).

## R§3 SDP profile and keying

- **SDES** (`srtp: sdes`): `m=audio <port> RTP/SAVP …` with one or more `a=crypto` lines
  (`AES_CM_128_HMAC_SHA1_80` REQUIRED to accept; AEAD suites SHOULD be offered where supported).
  The answerer selects one crypto line and returns its own key.
- **DTLS-SRTP** (`srtp: dtls`): `m=audio <port> UDP/TLS/RTP/SAVP …`, `a=fingerprint:sha-256`,
  `a=setup` per RFC 5763 (offer `actpass`, answer `active`/`passive`) — the same role rules as the
  WebRTC binding B§3.3, over an RTP `m=` line rather than a WebRTC one.
- **Plain RTP** (`srtp: none`): `m=audio <port> RTP/AVP …`, no keying. Permitted only under R§4.

`a=rtcp-mux` MAY be present but is not required (unlike WebRTC, where it is). One `m=` section per
media type; no BUNDLE.

## R§4 Encryption floor and the plain-RTP exception

Core §17.2 requires transport-encrypted media. On this binding:

- An endpoint MUST offer and prefer SDES or DTLS-SRTP.
- Plain RTP (`srtp: none`) MUST NOT be used except toward a trunk the operator has explicitly
  configured as trusted (a private interconnect, or an SBC that terminates SRTP upstream). A
  gateway that accepts or offers plain RTP MUST emit `gateway.downgraded` with `no-srtp-on-trunk`
  (Gateway Profile G§7) so the DSIP side sees the lost guarantee.
- A DSIP endpoint (non-gateway) MUST reject a plain-RTP offer with `media.encryption-required`.

## R§5 Codecs and transcoding

Codec ids map to `a=rtpmap` as in the WebRTC binding B§3.4, plus the narrowband PSTN codecs:

| DSIP id | rtpmap | payload type (static) |
|---|---|---|
| `codec:audio/pcmu` | `PCMU/8000` | 0 |
| `codec:audio/pcma` | `PCMA/8000` | 8 |
| `codec:audio/g722` | `G722/8000` (samples at 16 kHz) | 9 |
| `codec:audio/opus` | `opus/48000/2` | dynamic (e.g. 111) |

A gateway transcodes between this binding's codec and the peer leg's (Opus 48 kHz ⇄ G.711 8 kHz /
G.722 16 kHz) when they differ, and passes through when they match. Sample-rate conversion is the
implementation's concern; the reference uses a simple decimate/hold in round one and a resampler is
a quality follow-on.

## R§6 DTMF

RFC 2833 telephone-event (`a=rtpmap:<pt> telephone-event/8000`, `a=fmtp:<pt> 0-16`) is the SIP-side
DTMF carriage and is negotiated on the `m=` line as usual. Whether and how DTMF crosses into DSIP
is the Gateway Profile's open question (G§9, spec-gap 26); this binding only carries it on the RTP
leg.

## R§7 Conformance

An endpoint claiming `transport:rtp` 1.0 MUST implement R§2–R§5, MUST honour the encryption floor
of R§4, and (for a gateway) MUST emit the downgrade signal when plain RTP is used. It conforms as
`DSIP RTP/SRTP Media Binding 1.0` (§24.4).
