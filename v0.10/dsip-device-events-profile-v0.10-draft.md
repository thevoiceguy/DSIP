# Draft: DSIP Device Events Profile (`device-events/0.1`)

**Status:** DRAFT, companion profile to DSIP v0.10. Cite as `E§n`. Decided 2026-10-04 from
`impl/docs/v0.9-research.md` (track B): DSIP works **alongside** SNMP and syslog, not instead of them. SNMP keeps
polling and MIBs. A site gateway turns traps and syslog alarms into signed events, delivers them durably across the
WAN to a NOC, and the people there acknowledge and escalate them. Conformance: the `device-events/` vectors.

## E§1 Scope

This profile defines:

- the **gateway**, which receives SNMP notifications and syslog on its LAN and signs device events;
- the **`device-event`** and **`alarm-ack`** content objects, which travel as Messaging Profile content (M§8) in an
  MLS group, the **alarm group**, hubbed at the NOC's mailbox;
- how a trap becomes an event (E§3) and an event becomes an alarm (E§4);
- the **alarm list** every member computes from the group's ordered content (E§5);
- the **escalation agent**, a member that calls the on-call person when an alarm is not acknowledged (E§6).

Out of scope: polling, telemetry and metrics; alarm correlation and root cause; acknowledgements flowing back to
devices (SNMP SET, NETCONF); standardized vendor mapping content.

## E§2 Roles and identity

- **Device.** It speaks SNMP or syslog on the LAN and has no DSIP identity. It appears in an event only as a
  **claim**: its address, plus the basis on which the gateway believes the event came from it. The gateway is the
  signer and the device is a claim, as G§2 and G§5 make a SIP caller a claim of the gateway.
- **Gateway.** A device delegated by the organisation's identity (§7.4) with the delegation capability
  `dsip.events`. It is a member of the alarm group. A revoked gateway's events stop verifying (§7.4).
- **Members.** Operators' devices, and the escalation agent (E§6).
- **Basis** (`event.source.basis`), a registry-governed token (shape `[a-z][a-z0-9-]*`):

  | basis | meaning |
  |---|---|
  | `snmpv1` | SNMPv1 trap: community string only, unauthenticated |
  | `snmpv2c` | SNMPv2c trap or inform: community string only, unauthenticated |
  | `snmpv3-auth` | SNMPv3, `authNoPriv` |
  | `snmpv3-authpriv` | SNMPv3, `authPriv` |
  | `snmpv3-tls` | SNMPv3 over TLS (RFC 6353) with the Transport Security Model (RFC 5591), the device's certificate verified (v0.10) |
  | `syslog-tls` | syslog over TLS (RFC 5425), the device's certificate verified |
  | `syslog-udp` | syslog over UDP (RFC 5426), unauthenticated |
  | `gateway` | raised by the gateway itself (e.g. its own state) |

  A client MUST render the basis with the event, as G§5 requires for STIR attestation. An unknown basis renders as
  unauthenticated.
- **What an authenticated basis adds to the claim.** The address alone is spoofable on a LAN; the authenticated
  identity is what the basis verified, so `event.source` carries it:
  - `snmpv3-auth`, `snmpv3-authpriv`: `"usm": {"engine_id": "<hex>", "user": "<name>"}`, the authoritative engine
    and the user whose key verified the message;
  - `syslog-tls`: `"certificate_sha256": "<hex>"`, the SHA-256 of the device's verified leaf certificate.
  - `snmpv3-tls`: `"certificate_sha256"` as for `syslog-tls`, and `"tsm": {"security_name": "<name>"}`, the name
    the certificate mapped to (E§3).
  - Optionally `"name"` (v0.10): the name the gateway's configuration gives that certificate (or, for other
    authenticated bases, that identity). It is the gateway's claim, rendered beside the fingerprint, and absent when
    the gateway has none. A member MUST NOT render it without the identity it names.

## E§3 From a notification to an event

**SNMPv1 traps** are translated to SNMPv2 notification parameters exactly as RFC 3584 §3.1 specifies:

- `sysUpTime` is taken from the v1 time-stamp;
- for generic-trap 6 (`enterpriseSpecific`), `snmpTrapOID` is the enterprise OID followed by `0` and the
  specific-trap number;
- for generic-trap 0–5, `snmpTrapOID` is `1.3.6.1.6.3.1.1.5.1` to `.6`;
- the gateway is a proxy forwarding a received trap, so it appends `snmpTrapAddress.0` (`1.3.6.1.6.3.18.1.3.0`, the
  agent-addr) and `snmpTrapEnterprise.0` (`1.3.6.1.6.3.1.1.4.3.0`, the enterprise) when the trap does not already
  carry them.

**SNMPv2c and SNMPv3** traps and informs carry `sysUpTime.0` and `snmpTrapOID.0` as their first two varbinds
(RFC 3416 §4.2.6, §4.2.7). Those two are lifted into `uptime` and `trap_oid`.

**The community string is never carried.** The gateway drops it, and drops `snmpTrapCommunity.0`
(`1.3.6.1.6.3.18.1.4.0`) from every varbind list. RFC 3584 §3.1 (4) would append it, but it is a shared secret.

**Informs** are acknowledged to the device (the SNMP Response-PDU) only after the alarm group's hub answers `accepted`
for the event, which means it is stored durably (M§9.3). An inform thus becomes an end-to-end "stored"
acknowledgement rather than a one-hop one. If the hub refuses or cannot be reached, the gateway does not answer, and
the device retries as SNMP specifies.

An inform is identified by its source and request id. A retransmission of an inform whose event is still pending
deposits nothing more and is not answered. A retransmission after the answer (the response was lost) is answered
again, without a new event. A refused deposit is forgotten, so the next retransmission deposits anew. The gateway
remembers an answered inform for 300 s. A pending one is kept until the hub decides, including across an outage
(M§9.4). The `device-events/inform-*` traces pin these rules.

**SNMPv3** is accepted with the User-based Security Model only (USM, RFC 3414), at `authNoPriv` or `authPriv`. A
gateway configures users as `(engine_id, user)` with an authentication protocol and, for `authPriv`, a privacy
protocol, each given as a localized key or a password (RFC 3414 A.2, localized with the message's authoritative
engine ID). A password user MAY omit `engine_id`, and then matches that user name from any engine.

- **Authentication:** `md5` and `sha` (HMAC-96, RFC 3414), `sha224`, `sha256`, `sha384`, `sha512` (RFC 7860).
- **Privacy:** `aes128` (AES-128-CFB, RFC 3826; the privacy key is localized with the authentication protocol's
  hash and truncated to 16 bytes).
- **Refused:** other security models, `noAuthNoPriv` (it proves nothing that v2c does not), and DES (RFC 3414 §8:
  56-bit, broken).

A received message is checked in the order of RFC 3414 §3.2, and the first failure is reported. The steps and their
reason tokens are those of `impl/vectors/README.md` (component `snmpv3`):
`malformed`, `unsupported-security-model`, `unknown-engine-id`, `unknown-user`, `unsupported-security-level`,
`wrong-digest`, `not-in-time-window`, `decryption-error`, `not-a-notification`, `engine-id-mismatch`.

- **Who is authoritative.** A trap's authoritative engine is the device; an inform's is the gateway (RFC 3412
  §7.2). A message naming the gateway's own engine ID is checked against the gateway's clock; any other against the
  gateway's cached notion of that engine's clock. A trap naming the gateway's engine ID, or an inform naming
  another, is `engine-id-mismatch`.
- **Timeliness for traps** (RFC 3414 §3.2 step 7b). The first authenticated message from an engine seeds its cache
  entry `(boots, time)`, since a trap receiver performs no discovery. Thereafter a message is outside the window if
  its boots is below the cached boots, or equal with a time more than 150 s behind the cached time advanced by the
  local clock, or if the cached boots is 2^31−1. A newer `(boots, time)` updates the cache. A replayed trap is
  therefore refused once it is 150 s old.
- **Timeliness for informs** (step 7a): boots equal to the gateway's, and time within 150 s of the gateway's.
- **Discovery** (RFC 3414 §4). A reportable message with an empty engine ID is answered with a Report carrying
  `usmStatsUnknownEngineIDs` and the gateway's engine ID, boots and time. An authenticated inform outside the window
  is answered with an authenticated Report carrying `usmStatsNotInTimeWindows`, so the sender can synchronize. No
  other failure is reported: the gateway drops it silently.
- **The response to an inform** is sent once the hub has stored the event, as for v2c. It is a Response-PDU at the
  inform's security level, under the gateway's engine ID, boots and time.

**SNMPv3 over TLS** (v0.10; RFC 6353's TLS Transport Model with RFC 5591's Transport Security Model). The basis is
`snmpv3-tls`.

- **Transport.** TLS over TCP; notifications arrive at port 10162. The device is the TLS client and MUST present a
  certificate, which the gateway verifies against its trust anchors. DTLS over UDP is not specified here.
- **The security name** comes from the gateway's certificate-to-name table, RFC 6353's `snmpTlstmCertToTSNTable`.
  Each row is `{id, fingerprint, map, data?}`, with `fingerprint` the SHA-256 of a certificate in hex. The name is
  fixed for the whole connection.
  - **Rows** are considered in ascending `id`. A row matches when its fingerprint, compared without case, is that of
    the presented certificate or of a CA certificate in its verified path.
  - **Maps:**
    - `specified`: `data`.
    - `san-rfc822`: the first rfc822Name subjectAltName, with the part after its last `@` in lowercase (ASCII).
      A name without `@` fails.
    - `san-dns`: the first dNSName, in lowercase (ASCII).
    - `san-ip`: the first iPAddress, 4 bytes as a dotted quad or 16 bytes as 32 lowercase hex digits. Any other
      length fails.
    - `san-any`: the first subjectAltName that is one of those three types, mapped as its type.
    - Only the first subjectAltName of the type is tried: when its name fails, the row fails.
    - `common-name`: the subject's first CommonName (deprecated in RFC 6353).
    - An unknown map, or a map with nothing to map, fails.
  - **The result** must be 1–32 octets of UTF-8 (VACM's limit). A row that fails, or gives a name outside that, is
    passed over for the next.
  - **No transport prefix** is added (`snmpTsmConfigurationUsePrefix` false).
  - **With no name**, the connection is closed and nothing on it is accepted (RFC 6353 §5.3.2).
- **Framing.** A message is one BER SEQUENCE, read whole from the stream: the first byte is `0x30`; the length is
  definite, short form or long form with 1–4 length bytes; the whole message is at most 65,536 bytes. A stream that
  breaks these rules is closed, since nothing after it can be found. A partial message waits for more bytes, as does
  a single byte, which the next one decides.
- **Each message** is checked in this order, and the first failure is reported:
  - `malformed`: USM's structure rules (README, component `snmpv3`), except that `securityParameters` is any OCTET
    STRING, which is ignored, and `msgData` is always a plaintext ScopedPDU (TSM never encrypts in the message).
  - `unsupported-security-model`: `msgSecurityModel` is not 4, the TSM. USM over TLS is refused, so a message has
    one security model.
  - `not-a-notification`: the PDU is not a trap or an inform, and not the discovery request below.
  
  Any `msgFlags` security level is accepted, since the connection itself provides `authPriv` (RFC 5591 §5.2 step 4).
  A message refused here is dropped; the connection stays open.
- **Discovery** (RFC 5343). A sender learns the gateway's snmpEngineID before its first inform. It sends a
  GetRequest-PDU whose contextEngineID is `80 00 00 00 06` (RFC 5343's localEngineID) and whose only varbind is
  `snmpEngineID.0` (`1.3.6.1.6.3.10.2.1.1.0`). The gateway answers at once with a Response-PDU on the same
  connection. The Response has the request's `msgID`, request-id, contextEngineID (the localEngineID: RFC 5343
  §3.1 registers it, and RFC 3412 answers in the context asked) and contextName. The varbind's value is the
  gateway's engine ID, as an OCTET STRING. It is the only request the
  gateway answers; it deposits nothing.
- **The response to an inform** is sent on the same connection once the hub has stored the event, as for v2c. It is
  a Response-PDU with the inform's `msgID`, request-id, varbinds, contextEngineID and contextName, and its `msgFlags`
  without the reportable bit. `msgSecurityModel` is 4, `securityParameters` is empty, and the error status and
  index are 0.

**Syslog** (RFC 5424 and its transports) is carried as its fields. Its severity maps to an alarm severity through a
table the gateway MAY override per rule. By default:

| syslog severity | alarm severity |
|---|---|
| 0 Emergency, 1 Alert, 2 Critical | `critical` |
| 3 Error | `major` |
| 4 Warning | `warning` |
| 5 Notice, 6 Informational, 7 Debug | none: an event, not an alarm |

Impl (spec-gap 103): this default is a convention, not a standard, so a gateway's configuration may differ.

A syslog message is parsed into `raw.syslog`:

```json
{"syslog": {"format": "rfc5424", "facility": 4, "severity": 3, "timestamp": "2026-10-05T12:00:00Z",
            "hostname": "sw1", "app_name": "linkd", "procid": null, "msgid": "LINKDOWN",
            "structured_data": [{"id": "if@32473", "params": [{"name": "ifIndex", "value": "3"}]}],
            "msg": "port 3 down"}}
```

- **RFC 5424** applies when the `<PRI>` is followed by a version and a space. Its header fields are taken as given,
  `-` becoming `null`; the timestamp is the device's claim and is not interpreted. Parameter values are unescaped
  (`\"`, `\\`, `\]`). A leading BOM is removed from the message.
- **RFC 3164** (BSD syslog), which most network equipment still sends, applies otherwise: an optional
  `Mmm dd hh:mm:ss` timestamp and hostname, then an optional `TAG[pid]:` giving `app_name` and `procid`. Its
  `msgid` is `null` and its `structured_data` empty.
- Bytes that are not UTF-8 are replaced with U+FFFD. Trailing CR and LF are removed from the message.
- A datagram without a valid `<PRI>` (0–191) is malformed and dropped.

The exact grammar is in `impl/vectors/README.md` (checks `syslog`).

Over UDP (RFC 5426) the basis is `syslog-udp`. Over TLS (RFC 5425, octet-counted framing) it is `syslog-tls` only
when the device presented a certificate that chains to a CA the gateway trusts for its devices.

## E§4 From an event to an alarm

An alarm is **state**, not a message (RFC 8632 §3.1). It is identified by `(resource, type, qualifier)`:

- `resource` is the thing in trouble, as fine-grained as the gateway can tell;
- `type` is a registry-governed alarm type;
- `qualifier` distinguishes instances of a type and defaults to `""`.

A gateway maps notifications to alarms with a **rule table** shaped like RFC 3877's `alarmModelTable`. Each rule is:

- `trap_oid`;
- optionally `varbind: {oid, value}`, matched exactly;
- `action`: `raise`, `clear` or `notify`;
- `type`;
- `severity`, for `raise`;
- optionally `resource_varbind`, an OID prefix.

The **first matching rule** wins. The resource is `<source address>`, or `<source address>/<value>` when
`resource_varbind` names a varbind whose OID equals the prefix or extends it by `.n`. An unmatched notification, or a
`notify` rule, gives an event with no alarm. The profile standardizes the shape of the table, not its contents.

A rule for syslog has `syslog` in place of `trap_oid`, with any of `app_name`, `msgid`, `hostname` and `facility`
(matched exactly) and `msg_contains` (a substring of the message). A trap rule never matches syslog, nor a syslog rule
a trap.

- A `raise` rule's severity is the rule's `severity`, or else the syslog severity table's. If both give none, the
  message is an event with no alarm.
- `resource_sd: {"id", "param"}` names a structured-data parameter. The resource is `<source address>/<value>` from
  the first element with that `id` and, in it, the first parameter with that name; otherwise `<source address>`.
- An unmatched syslog message whose severity the table maps to an alarm severity raises
  `(<source address>, syslog, <app_name or "">)`. Otherwise it is an event with no alarm.

**Hold-down** (optional, v0.10). A gateway MAY damp a flapping alarm by **delaying clears** for `H` seconds (`0`, the
default, turns it off):
- A clear is not deposited at once. It is held, and deposited when it has held for `H` seconds.
- A raise for the same alarm `(resource, type, qualifier)` while its clear is held cancels the clear and is deposited.
  Members never saw the clear, so they count a repeat (E§5): a link that flaps faster than `H` is one alarm with a
  count, never a stream of clears and raises.
- A second clear while one is held changes nothing; the first keeps its time.
- Every other event, including one with no alarm, is deposited at once. So is an event from an SNMP inform: the
  inform is answered only once its event is stored (E§3), so its clear is never held.

Members' rules (E§5) are unchanged: hold-down changes only which events a gateway deposits, and when. Its rules are
the `device-events/holddown-*` traces.

## E§5 The `device-event` object and the alarm list

```json
{"object": "content", "kind": "device-event", "id": "…", "conversation": "…", "sender": "<gateway identity>",
 "sent_at": 1790000000,
 "event": {
   "source": {"address": "192.0.2.7", "basis": "snmpv2c"},
   "raw": {"snmp": {"version": "v2c", "uptime": 123400, "trap_oid": "1.3.6.1.6.3.1.1.5.3",
                    "varbinds": [{"oid": "1.3.6.1.2.1.2.2.1.1.2", "type": "Integer32", "value": "2"}]}},
   "alarm": {"resource": "192.0.2.7/2", "type": "link-down", "qualifier": "", "severity": "major", "cleared": false,
             "text": "ifIndex 2 down"}
 }}
```

A gateway's own liveness is a `device-event` with `event.heartbeat: {"interval_s": n}` and no `raw`.

Every member computes the same **alarm list** by applying the group's content in hub `seq` order (M§6.5) to the
machine below. Its transitions are the `device-events/` traces, and `impl/vectors/README.md` states them exactly.

- **Raise.** A report for an unknown key that is not cleared creates the alarm (`raised`). A cleared report for an
  unknown key creates nothing.
- **Repeat.** The same severity, still not cleared, only counts. It emits nothing, so a repeated trap pages nobody.
- **Change.** A different severity while active gives `changed`.
- **Clear.** A cleared report on an active alarm gives `cleared`. The alarm remains, with its history; clearing is
  not acknowledging.
- **Re-raise** (spec-gap 103). A report that is not cleared on a cleared alarm **reopens the same alarm**
  (RFC 8632): `raised` with `reopened: true`, and the operator state returns to `none` so the alarm gets attention
  again. A flapping link is one alarm with a count, not many.
- **Severity** is `indeterminate < warning < minor < major < critical`, a registry-governed token. An unknown token
  orders as `indeterminate`. `cleared` is not a severity.

**Acknowledgement** is its own content object, never the read receipt. Read (M§10.3) means seen; an
acknowledgement means "I own this". RFC 8632 keeps operator state separate from resource state:

```json
{"object": "content", "kind": "alarm-ack", "alarm": {"resource": "…", "type": "…", "qualifier": ""},
 "state": "ack" | "closed", "text": "…"}
```

- `ack` means being handled.
- `closed` means the corrective action is done. It is final until a re-raise reopens the alarm, and an `ack` after
  `closed` is ignored.
- Neither clears the alarm.

**Gateway silence.** A member that has seen a gateway's heartbeat raises the alarm
`(<gateway identity>, dsip-gateway-silent, "")`, severity `major`, when no heartbeat arrives for twice its
`interval_s`. The next heartbeat clears it.

## E§6 Escalation

An **escalation agent** is a member of the alarm group with its own DSIP identity, a small service. It runs the
alarm list with a policy `{min_severity, after_s}`. When an alarm has been active, at or above `min_severity`, with
operator state `none`, for `after_s`, the agent places a DSIP call (§12) to the on-call person.

- The trigger is normative and its timers are pinned by the traces.
- The rota, the call target and further tiers are local policy.
- Any of these cancels a pending escalation: an `ack` or `closed`, a clear, or the severity falling below
  `min_severity`.
- Each raise or reopen escalates at most once.

Impl (spec-gap 103): mailboxes and hubs stay storage and ordering services (M§4). Escalation belongs to a member, not
the NOC's mailbox.

## E§7 Registries

- `dsip-delegation-capability`: `dsip.events`.
- `dsip-device-event-basis`: the E§2 table.
- `dsip-alarm-type`: shape `[a-z][a-z0-9-]*`, open. The profile registers `dsip-gateway-silent`.
- `dsip-alarm-severity`: `indeterminate`, `warning`, `minor`, `major`, `critical`.
