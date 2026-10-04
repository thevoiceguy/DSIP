# Draft: DSIP Device Events Profile (`device-events/0.1`)

**Status:** DRAFT, companion profile to DSIP v0.9. Cite as `E§n`. Decided 2026-10-04 from
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
  | `syslog-tls` | syslog over TLS (RFC 5425), the device's certificate verified |
  | `syslog-udp` | syslog over UDP (RFC 5426), unauthenticated |
  | `gateway` | raised by the gateway itself (e.g. its own state) |

  A client MUST render the basis with the event, as G§5 requires for STIR attestation. An unknown basis renders as
  unauthenticated.

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

**Syslog** (RFC 5424 and its transports) is carried as its fields. Its severity maps to an alarm severity through a
table the gateway MAY override per rule. By default:

| syslog severity | alarm severity |
|---|---|
| 0 Emergency, 1 Alert, 2 Critical | `critical` |
| 3 Error | `major` |
| 4 Warning | `warning` |
| 5 Notice, 6 Informational, 7 Debug | none: an event, not an alarm |

Impl (spec-gap 103): this default is a convention, not a standard, so a gateway's configuration may differ.

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
