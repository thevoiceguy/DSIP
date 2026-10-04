"""Device Events Profile (draft, `device-events/0.1`) — reference for the `device-events/` vectors.

Spec: E§3 (a notification becomes an event: RFC 3584 §3.1, the community never carried, the syslog severity table),
E§4 (the rule table: an event becomes an alarm), E§5 (the alarm list: raise, repeat, change, clear, reopen;
operator state; gateway silence), E§6 (the escalation trigger). Contract: impl/vectors/README.md, kind `device-events`.

Impl (spec-gap 103): a re-raise reopens the same alarm and resets its operator state; the syslog default table;
escalation is run by a member (the agent), not the mailbox.
"""
from __future__ import annotations

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SNMP_TRAP_ADDRESS = "1.3.6.1.6.3.18.1.3.0"
SNMP_TRAP_COMMUNITY = "1.3.6.1.6.3.18.1.4.0"
SNMP_TRAP_ENTERPRISE = "1.3.6.1.6.3.1.1.4.3.0"
GENERIC_TRAPS = "1.3.6.1.6.3.1.1.5."  # + generic-trap + 1 (RFC 3584 §3.1 (3))

SEVERITIES = ["indeterminate", "warning", "minor", "major", "critical"]
SYSLOG_DEFAULT = {0: "critical", 1: "critical", 2: "critical", 3: "major", 4: "warning", 5: None, 6: None, 7: None}
SILENT = "dsip-gateway-silent"


def rank(sev) -> int:
    """Severity order; an unknown token orders as `indeterminate` (E§5, registry fallback)."""
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


# --- E§3 --------------------------------------------------------------------------------------

def normalize_trap(t: dict) -> dict:
    """A received SNMP notification → the event's `raw.snmp` (or `{"error": "malformed-trap"}`)."""
    v = t.get("version")
    raw_vbs = t.get("varbinds")
    if not isinstance(raw_vbs, list) or not all(
            isinstance(x, dict) and isinstance(x.get("oid"), str) and isinstance(x.get("type"), str) and "value" in x
            for x in raw_vbs):
        return {"error": "malformed-trap"}
    vbs = [{"oid": x["oid"], "type": x["type"], "value": x["value"]} for x in raw_vbs]
    if v == "v1":
        isint = lambda x: isinstance(x, int) and not isinstance(x, bool)  # noqa: E731
        if not (isinstance(t.get("enterprise"), str) and isinstance(t.get("agent_addr"), str) and isint(t.get("generic"))
                and isint(t.get("specific")) and isint(t.get("timestamp")) and 0 <= t["generic"] <= 6):
            return {"error": "malformed-trap"}
        g = t["generic"]
        trap_oid = f"{t['enterprise']}.0.{t['specific']}" if g == 6 else f"{GENERIC_TRAPS}{g + 1}"
        present = {x["oid"] for x in vbs}
        if SNMP_TRAP_ADDRESS not in present:
            vbs.append({"oid": SNMP_TRAP_ADDRESS, "type": "IpAddress", "value": t["agent_addr"]})
        if SNMP_TRAP_ENTERPRISE not in present:
            vbs.append({"oid": SNMP_TRAP_ENTERPRISE, "type": "OBJECT IDENTIFIER", "value": t["enterprise"]})
        uptime = t["timestamp"]
    elif v in ("v2c", "v3"):
        if len(vbs) < 2 or vbs[0]["oid"] != SYS_UPTIME or vbs[1]["oid"] != SNMP_TRAP_OID:
            return {"error": "malformed-trap"}
        up = vbs[0]["value"]
        if not (isinstance(up, str) and up.isascii() and up.isdigit() and int(up) <= 2**53 - 1) \
                or not isinstance(vbs[1]["value"], str):
            return {"error": "malformed-trap"}
        uptime, trap_oid = int(up), vbs[1]["value"]
        vbs = vbs[2:]
    else:
        return {"error": "malformed-trap"}
    # E§3: the community is a shared secret — never carried, whatever RFC 3584 §3.1 (4) appends
    vbs = [x for x in vbs if x["oid"] != SNMP_TRAP_COMMUNITY]
    return {"snmp": {"version": v, "uptime": uptime, "trap_oid": trap_oid, "varbinds": vbs}}


def syslog_severity(sev: int, table: dict | None = None):
    """RFC 5424 severity → alarm severity, or None (an event, not an alarm). E§3; Impl: the default table."""
    t = dict(SYSLOG_DEFAULT)
    for k, val in (table or {}).items():
        t[int(k)] = val
    return t.get(sev)


# --- E§4 --------------------------------------------------------------------------------------

def map_alarm(raw: dict, rules: list, source: str) -> dict:
    """First matching rule → `{"alarm": …}`, or `{"notify": true}` for no alarm."""
    snmp = raw["snmp"]
    for r in rules:
        if r["trap_oid"] != snmp["trap_oid"]:
            continue
        want = r.get("varbind")
        if want and not any(x["oid"] == want["oid"] and str(x["value"]) == str(want["value"]) for x in snmp["varbinds"]):
            continue
        if r["action"] == "notify":
            return {"notify": True}
        resource = source
        prefix = r.get("resource_varbind")
        if prefix:
            hit = next((x for x in snmp["varbinds"] if x["oid"] == prefix or x["oid"].startswith(prefix + ".")), None)
            if hit is not None:
                resource = f"{source}/{hit['value']}"
        cleared = r["action"] == "clear"
        return {"alarm": {"resource": resource, "type": r["type"], "qualifier": "",
                          "severity": None if cleared else r.get("severity"), "cleared": cleared}}
    return {"notify": True}


def run_check(i: dict) -> dict:
    c = i["check"]
    if c == "trap":
        return normalize_trap(i["trap"])
    if c == "syslog-severity":
        return {"severity": syslog_severity(i["severity"], i.get("table"))}
    if c == "map":
        return map_alarm(i["raw"], i["rules"], i["source"])
    raise ValueError(f"unknown check {c}")


# --- E§5, E§6: the alarm list -------------------------------------------------------------------

def key_of(a: dict) -> tuple:
    return (a["resource"], a["type"], a.get("qualifier", ""))


class AlarmList:
    """The alarm list every member computes from the group's ordered content; the agent also escalates."""

    def __init__(self, ctx: dict):
        self.now = ctx.get("now", 0)
        self.policy = ctx.get("escalation")  # {"min_severity", "after_s"} or None
        self.alarms: dict[tuple, dict] = {}
        self.gateways: dict[str, dict] = {}  # gateway → {"interval_s", "last"}

    def _arm(self, k):
        """Start, keep or cancel the escalation timer per E§6."""
        a = self.alarms[k]
        due = self.policy is not None and not a["cleared"] and a["operator"] == "none" \
            and not a["escalated"] and rank(a["severity"]) >= rank(self.policy["min_severity"])
        if not due:
            a["due"] = None
        elif a["due"] is None:
            a["due"] = self.now + self.policy["after_s"]

    def _report(self, al: dict) -> list:
        k = key_of(al)
        a = self.alarms.get(k)
        jk = list(k)
        if a is None:
            if al["cleared"]:
                return []
            self.alarms[k] = {"severity": al["severity"], "cleared": False, "operator": "none", "count": 1,
                              "due": None, "escalated": False}
            self._arm(k)
            return [{"raised": {"key": jk, "severity": al["severity"], "reopened": False}}]
        a["count"] += 1
        if al["cleared"]:
            if a["cleared"]:
                return []
            a["cleared"] = True
            self._arm(k)
            return [{"cleared": {"key": jk}}]
        if a["cleared"]:
            # spec-gap 103: reopen the same alarm; operator state back to none, escalation re-armed
            a.update({"cleared": False, "severity": al["severity"], "operator": "none", "escalated": False, "due": None})
            self._arm(k)
            return [{"raised": {"key": jk, "severity": al["severity"], "reopened": True}}]
        if al["severity"] == a["severity"]:
            return []
        a["severity"] = al["severity"]
        self._arm(k)
        return [{"changed": {"key": jk, "severity": al["severity"]}}]

    def _ack(self, e: dict) -> list:
        k = key_of(e["alarm"])
        a = self.alarms.get(k)
        if a is None or a["operator"] == "closed" or a["operator"] == e["state"]:
            return []
        a["operator"] = e["state"]
        self._arm(k)
        return [{"operator": {"key": list(k), "state": e["state"], "by": e.get("by")}}]

    def _heartbeat(self, h: dict) -> list:
        g = h["gateway"]
        self.gateways[g] = {"interval_s": h["interval_s"], "last": self.now}
        k = (g, SILENT, "")
        if k in self.alarms and not self.alarms[k]["cleared"]:
            return self._report({"resource": g, "type": SILENT, "qualifier": "", "severity": None, "cleared": True})
        return []

    def _advance(self, s: int) -> list:
        self.now += s
        out = []
        for g in sorted(self.gateways):
            st = self.gateways[g]
            k = (g, SILENT, "")
            active = k in self.alarms and not self.alarms[k]["cleared"]
            if not active and self.now - st["last"] > 2 * st["interval_s"]:
                out += self._report({"resource": g, "type": SILENT, "qualifier": "", "severity": "major", "cleared": False})
        due = sorted((a["due"], k) for k, a in self.alarms.items() if a["due"] is not None and a["due"] <= self.now)
        for _, k in due:
            a = self.alarms[k]
            a["due"], a["escalated"] = None, True
            out.append({"escalate": {"key": list(k), "severity": a["severity"]}})
        return out

    def step(self, ev: dict) -> list:
        if "report" in ev:
            return self._report(ev["report"])
        if "ack" in ev:
            return self._ack(ev["ack"])
        if "heartbeat" in ev:
            return self._heartbeat(ev["heartbeat"])
        if "advance" in ev:
            return self._advance(ev["advance"])
        raise ValueError(f"unknown event {ev}")

    def snapshot(self) -> list:
        return [{"key": list(k), "severity": a["severity"], "cleared": a["cleared"], "operator": a["operator"],
                 "count": a["count"], "escalation_due": a["due"]} for k, a in sorted(self.alarms.items())]


def run(v: dict):
    i = v["input"]
    if "check" in i:
        return run_check(i)
    m = AlarmList(v["context"])
    return [{"emit": m.step(st["event"]), "alarms": m.snapshot()} for st in i["steps"]]
