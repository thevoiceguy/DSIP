/**
 * Device Events Profile (`device-events/0.1`, draft): SNMP notifications and syslog become
 * signed events, events become alarms, every member computes the same alarm list, and an
 * escalation agent pages when an alarm stays unacknowledged.
 *
 * Spec: E§3, E§4, E§5, E§6 (`v0.9/dsip-device-events-profile-v0.9-draft.md`); RFC 3584 §3.1
 * (v1 → v2 translation), RFC 3416 §4.2.6–§4.2.7 (the first two varbinds), RFC 8632 §3.1 (alarm
 * as state, operator state apart from resource state). The exact output shapes, orderings and
 * timer rules are the vectors README's, "Kind: `device-events`".
 */
import type { Json, JsonObject } from "../did.js";

/** One varbind, as carried. Spec: E§3 */
export interface Varbind {
  /** Dotted OID. */
  oid: string;
  /** SNMP type name, e.g. `Integer32`. */
  type: string;
  /** The value, as a string. */
  value: string;
}

const SYS_UPTIME = "1.3.6.1.2.1.1.3.0";
const SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0";
const SNMP_TRAP_ADDRESS = "1.3.6.1.6.3.18.1.3.0";
const SNMP_TRAP_ENTERPRISE = "1.3.6.1.6.3.1.1.4.3.0";
const SNMP_TRAP_COMMUNITY = "1.3.6.1.6.3.18.1.4.0";
const GENERIC_TRAPS = "1.3.6.1.6.3.1.1.5.";
/** The gateway-silence alarm type. Spec: E§5, E§7 */
const GATEWAY_SILENT = "dsip-gateway-silent";

const MALFORMED: JsonObject = { error: "malformed-trap" };

/**
 * The input varbinds, each reduced to exactly `{oid, type, value}`, or `null` when the list or a
 * varbind is not of that shape. Spec: E§3; README "Kind: `device-events`" (other members dropped).
 * README "Kind: `device-events`": a varbind list that is not an array, or a varbind without string
 * `oid`/`type` or without `value` (any JSON), is `malformed-trap`.
 */
function varbinds(list: unknown): Varbind[] | null {
  if (!Array.isArray(list)) return null;
  const out: Varbind[] = [];
  for (const v of list as Json[]) {
    if (v === null || typeof v !== "object" || Array.isArray(v)) return null;
    if (typeof v["oid"] !== "string" || typeof v["type"] !== "string" || !("value" in v)) return null;
    out.push({ oid: v["oid"], type: v["type"], value: v["value"] as string });
  }
  return out;
}

const isInt = (x: unknown): x is number => typeof x === "number" && Number.isInteger(x);

/**
 * A received trap as the `raw.snmp` object of an event, or `{error: "malformed-trap"}`.
 *
 * Spec: E§3 — v1 translated per RFC 3584 §3.1 with the proxy's snmpTrapAddress.0 and
 * snmpTrapEnterprise.0 appended when absent; v2c/v3 lift sysUpTime.0 and snmpTrapOID.0 out of
 * varbinds 0 and 1 (RFC 3416); the community and snmpTrapCommunity.0 are never carried.
 * README "Kind: `device-events`": a v1 field missing or mistyped (`generic` outside 0–6 included),
 * a v2c/v3 sysUpTime.0 value that is not a string of decimal digits at most 2^53 − 1, or a
 * snmpTrapOID.0 value that is not a string, is `malformed-trap`.
 */
export function translateTrap(trap: JsonObject): JsonObject {
  const version = trap["version"];
  let uptime: number;
  let trapOid: string;
  let vbs: Varbind[];
  if (version === "v1") {
    const enterprise = trap["enterprise"];
    const agentAddr = trap["agent_addr"];
    const generic = trap["generic"];
    const timestamp = trap["timestamp"];
    const list = varbinds(trap["varbinds"]);
    if (
      typeof enterprise !== "string" ||
      typeof agentAddr !== "string" ||
      !isInt(generic) || generic < 0 || generic > 6 ||
      !isInt(trap["specific"]) ||
      !isInt(timestamp) ||
      list === null
    )
      return MALFORMED;
    uptime = timestamp;
    // Spec: E§3 / RFC 3584 §3.1 (2), (3)
    trapOid = generic === 6 ? `${enterprise}.0.${String(trap["specific"])}` : `${GENERIC_TRAPS}${generic + 1}`;
    vbs = list;
    // Spec: E§3 — the gateway is a proxy: append each only when not already carried
    if (!vbs.some((v) => v.oid === SNMP_TRAP_ADDRESS))
      vbs.push({ oid: SNMP_TRAP_ADDRESS, type: "IpAddress", value: agentAddr });
    if (!vbs.some((v) => v.oid === SNMP_TRAP_ENTERPRISE))
      vbs.push({ oid: SNMP_TRAP_ENTERPRISE, type: "OBJECT IDENTIFIER", value: enterprise });
  } else if (version === "v2c" || version === "v3") {
    const all = varbinds(trap["varbinds"]);
    // Spec: E§3 / RFC 3416 §4.2.6 — sysUpTime.0 then snmpTrapOID.0, first
    if (all === null || all.length < 2 || all[0]!.oid !== SYS_UPTIME || all[1]!.oid !== SNMP_TRAP_OID) return MALFORMED;
    const up = all[0]!.value;
    // README "Kind: `device-events`": decimal digits, at most 2^53 − 1
    if (typeof up !== "string" || !/^[0-9]+$/.test(up) || BigInt(up) > BigInt(Number.MAX_SAFE_INTEGER)) return MALFORMED;
    uptime = Number(up);
    if (typeof all[1]!.value !== "string") return MALFORMED;
    trapOid = all[1]!.value;
    vbs = all.slice(2);
  } else {
    return MALFORMED;
  }
  // Spec: E§3 — the community is a shared secret, never carried (unlike RFC 3584 §3.1 (4))
  vbs = vbs.filter((v) => v.oid !== SNMP_TRAP_COMMUNITY);
  return { snmp: { version: version, uptime, trap_oid: trapOid, varbinds: vbs as unknown as Json[] } };
}

/**
 * The syslog default table. Spec: E§3
 * Impl: spec-gap 103 — a convention, not a standard; a gateway may override any row.
 */
const SYSLOG_DEFAULT: Record<string, string | null> = {
  "0": "critical",
  "1": "critical",
  "2": "critical",
  "3": "major",
  "4": "warning",
  "5": null,
  "6": null,
  "7": null,
};

/**
 * A syslog severity (0–7) as an alarm severity, or `null` for an event that is not an alarm.
 *
 * Spec: E§3
 * Impl: spec-gap 103 — the default table above, overridden row by row by the gateway's `table`.
 */
export function syslogSeverity(severity: number, table?: JsonObject): JsonObject {
  const k = String(severity);
  const v = table && k in table ? table[k] : SYSLOG_DEFAULT[k];
  return { severity: (v ?? null) as Json };
}

/** One row of a gateway's rule table. Spec: E§4 */
export interface Rule {
  /** The notification OID this rule matches. */
  trap_oid: string;
  /** An exact varbind condition, optional. */
  varbind?: { oid: string; value: Json };
  /** `raise`, `clear` or `notify`. */
  action: string;
  /** The alarm type. */
  type?: string;
  /** The severity, for `raise`. */
  severity?: string;
  /** An OID prefix naming the varbind that refines the resource. */
  resource_varbind?: string;
}

/**
 * Map a translated notification to an alarm report through the rule table.
 *
 * Spec: E§4 — the first matching rule wins; `notify`, or no match, is an event with no alarm;
 * the resource is the source, or `source/value` of the varbind `resource_varbind` names
 * (equal, or extended by `.n`).
 */
export function mapEvent(raw: JsonObject, rules: Rule[], source: string): JsonObject {
  const snmp = raw["snmp"] as JsonObject;
  const vbs = varbinds(snmp["varbinds"]) ?? [];
  const rule = rules.find(
    (r) =>
      r.trap_oid === snmp["trap_oid"] &&
      (!r.varbind || vbs.some((v) => v.oid === r.varbind!.oid && String(v.value) === String(r.varbind!.value))),
  );
  if (!rule || rule.action === "notify") return { notify: true };
  let resource = source;
  if (rule.resource_varbind !== undefined) {
    const p = rule.resource_varbind;
    const hit = vbs.find((v) => v.oid === p || v.oid.startsWith(p + "."));
    if (hit) resource = `${source}/${String(hit.value)}`;
  }
  const cleared = rule.action === "clear";
  return {
    alarm: {
      resource,
      type: rule.type ?? "",
      qualifier: "",
      severity: cleared ? null : (rule.severity ?? null),
      cleared,
    },
  };
}

/** An alarm key `[resource, type, qualifier]`. Spec: E§4 */
type Key = [string, string, string];

/** Severity order; any other token orders as `indeterminate`. Spec: E§5, E§7 */
const SEVERITY_RANK: Record<string, number> = { indeterminate: 0, warning: 1, minor: 2, major: 3, critical: 4 };
function rank(s: string | null): number {
  return s !== null && Object.hasOwn(SEVERITY_RANK, s) ? SEVERITY_RANK[s]! : 0;
}

/**
 * Impl: keys sort element by element by Unicode code point (the README says "sorted by key"
 * without naming a collation; code points match a byte-wise UTF-8 order).
 */
function cmpStr(a: string, b: string): number {
  const x = Array.from(a), y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d) return d;
  }
  return x.length - y.length;
}
function cmpKey(a: Key, b: Key): number {
  return cmpStr(a[0], b[0]) || cmpStr(a[1], b[1]) || cmpStr(a[2], b[2]);
}

interface Alarm {
  key: Key;
  severity: string | null;
  cleared: boolean;
  operator: string;
  count: number;
  escalated: boolean;
  due: number | null;
}

/** The escalation policy. Spec: E§6 */
interface Policy {
  min_severity: string;
  after_s: number;
}

/**
 * The alarm list every member computes from the alarm group's ordered content, with the
 * escalation agent's timers and the gateway-silence watch.
 *
 * Spec: E§5 (raise, repeat, change, clear, re-raise; acknowledgement; gateway silence), E§6
 * (escalation once per raise, cancelled by ack/closed, clear, or severity below the threshold).
 * Impl: spec-gap 103 — a re-raise reopens the same alarm and returns its operator state to
 * `none`; escalation is run by a member (this machine), not by the NOC's mailbox.
 */
export class AlarmList {
  private now: number;
  private readonly policy: Policy | null;
  private readonly alarms = new Map<string, Alarm>();
  /** Each gateway's last heartbeat and interval. */
  private readonly gateways = new Map<string, { interval: number; last: number }>();

  /** Spec: E§6 — `context.escalation` is the agent's policy; absent, nothing escalates. */
  constructor(context: JsonObject) {
    this.now = context["now"] as number;
    this.policy = (context["escalation"] as unknown as Policy | undefined) ?? null;
  }

  /** Apply one event; returns `{emit, alarms}`. Spec: E§5, E§6 */
  step(event: JsonObject): JsonObject {
    const emit: JsonObject[] = [];
    if ("report" in event) {
      this.report(event["report"] as JsonObject, emit);
    } else if ("ack" in event) {
      this.ack(event["ack"] as JsonObject, emit);
    } else if ("heartbeat" in event) {
      const hb = event["heartbeat"] as JsonObject;
      const gw = hb["gateway"] as string;
      this.gateways.set(gw, { interval: hb["interval_s"] as number, last: this.now });
      // Spec: E§5 — the next heartbeat clears the silence alarm
      const a = this.alarms.get(JSON.stringify([gw, GATEWAY_SILENT, ""]));
      if (a && !a.cleared) this.report({ resource: gw, type: GATEWAY_SILENT, qualifier: "", severity: null, cleared: true }, emit);
    } else if ("advance" in event) {
      this.now += event["advance"] as number;
      // Spec: E§5 — no heartbeat for twice interval_s raises dsip-gateway-silent (major);
      // README "Kind: `device-events`": gateways in order of their id, compared as strings
      for (const [gw, g] of [...this.gateways].sort((a, b) => cmpStr(a[0], b[0]))) {
        const a = this.alarms.get(JSON.stringify([gw, GATEWAY_SILENT, ""]));
        if ((!a || a.cleared) && this.now - g.last > 2 * g.interval)
          this.report({ resource: gw, type: GATEWAY_SILENT, qualifier: "", severity: "major", cleared: false }, emit);
      }
      // Spec: E§6 — due escalations, by due time then key; each raise escalates at most once
      const due = [...this.alarms.values()]
        .filter((a) => a.due !== null && a.due <= this.now)
        .sort((a, b) => a.due! - b.due! || cmpKey(a.key, b.key));
      for (const a of due) {
        emit.push({ escalate: { key: a.key, severity: a.severity } });
        a.escalated = true;
        a.due = null;
      }
    } else {
      throw new Error(`unknown device-events event ${JSON.stringify(event)}`);
    }
    this.retime();
    return { emit: emit as Json[], alarms: this.snapshot() };
  }

  /** A report for `(resource, type, qualifier)`. Spec: E§5 */
  private report(r: JsonObject, emit: JsonObject[]): void {
    const key: Key = [r["resource"] as string, r["type"] as string, (r["qualifier"] as string | undefined) ?? ""];
    const id = JSON.stringify(key);
    const severity = (r["severity"] as string | null | undefined) ?? null;
    const cleared = r["cleared"] === true;
    const a = this.alarms.get(id);
    if (!a) {
      // Spec: E§5 Raise — a cleared report for an unknown key creates nothing
      if (cleared) return;
      this.alarms.set(id, { key, severity, cleared: false, operator: "none", count: 1, escalated: false, due: null });
      emit.push({ raised: { key, severity, reopened: false } });
    } else {
      a.count += 1; // every report on an existing alarm counts, clears included
      if (a.cleared) {
        if (cleared) return;
        // Spec: E§5 Re-raise. Impl: spec-gap 103 — reopen the same alarm, operator state back to none
        a.cleared = false;
        a.severity = severity;
        a.operator = "none";
        a.escalated = false;
        emit.push({ raised: { key, severity, reopened: true } });
      } else if (cleared) {
        // Spec: E§5 Clear — the alarm remains; clearing is not acknowledging
        a.cleared = true;
        emit.push({ cleared: { key } });
      } else if (severity !== a.severity) {
        // Spec: E§5 Change
        a.severity = severity;
        emit.push({ changed: { key, severity } });
      }
      // Spec: E§5 Repeat — same severity only counts
    }
    this.retime();
  }

  /** An `alarm-ack`. Spec: E§5 — `closed` is final until a re-raise; neither clears. */
  private ack(ev: JsonObject, emit: JsonObject[]): void {
    const k = ev["alarm"] as JsonObject;
    const a = this.alarms.get(JSON.stringify([k["resource"], k["type"], k["qualifier"] ?? ""]));
    const state = ev["state"] as string;
    if (!a || a.operator === "closed" || a.operator === state) return;
    a.operator = state;
    emit.push({ operator: { key: a.key, state, by: ev["by"] ?? null } });
  }

  /**
   * Re-evaluate every escalation timer. Spec: E§6 — eligible: policy set, active, operator
   * `none`, not escalated since the last raise, severity ≥ min_severity. A running timer is kept
   * while the alarm stays eligible; an ineligible one loses it.
   * Impl: re-evaluated after each report and at the end of each event, so in an `advance` a
   * silence alarm raised in step 1 gets its timer before step 2 looks for due ones.
   */
  private retime(): void {
    for (const a of this.alarms.values()) {
      const eligible =
        this.policy !== null &&
        !a.cleared &&
        a.operator === "none" &&
        !a.escalated &&
        rank(a.severity) >= rank(this.policy.min_severity);
      if (!eligible) a.due = null;
      else if (a.due === null) a.due = this.now + this.policy!.after_s;
    }
  }

  private snapshot(): Json[] {
    return [...this.alarms.values()]
      .sort((a, b) => cmpKey(a.key, b.key))
      .map((a) => ({
        key: a.key,
        severity: a.severity,
        cleared: a.cleared,
        operator: a.operator,
        count: a.count,
        escalation_due: a.due,
      }));
  }
}

/**
 * The `device-events` vector kind: a stateless check, or an alarm-list trace returning one
 * `{emit, alarms}` per step. Spec: E§3–E§6
 */
export function runDeviceEvents(context: JsonObject, input: JsonObject): Json {
  if (Array.isArray(input["steps"])) {
    const list = new AlarmList(context);
    return (input["steps"] as JsonObject[]).map((s) => list.step(s["event"] as JsonObject));
  }
  switch (input["check"]) {
    case "trap":
      return translateTrap(input["trap"] as JsonObject);
    case "syslog-severity":
      return syslogSeverity(input["severity"] as number, input["table"] as JsonObject | undefined);
    case "map":
      return mapEvent(input["raw"] as JsonObject, input["rules"] as unknown as Rule[], input["source"] as string);
    default:
      throw new Error(`unknown device-events check ${String(input["check"])}`);
  }
}
