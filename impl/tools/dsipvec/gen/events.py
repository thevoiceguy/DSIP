"""`device-events/` vectors — Device Events Profile draft (E§3–E§6). Expectations are written out by hand."""
from __future__ import annotations

from .common import vector

ENT = "1.3.6.1.4.1.9999.1"
UP = "1.3.6.1.2.1.1.3.0"
TOID = "1.3.6.1.6.3.1.1.4.1.0"
TADDR = "1.3.6.1.6.3.18.1.3.0"
TCOMM = "1.3.6.1.6.3.18.1.4.0"
TENT = "1.3.6.1.6.3.1.1.4.3.0"
LINKDOWN, LINKUP = "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.6.3.1.1.5.4"
IFINDEX = "1.3.6.1.2.1.2.2.1.1"
GW = "did:web:noc.example:gw:site1"


def ev(vid, desc, refs, inp, expect, ctx=None):
    return vector(f"device-events/{vid}", "device-events", desc, refs, ctx or {}, inp, expect)


def vb(oid, typ, value):
    return {"oid": oid, "type": typ, "value": value}


def k(res, typ, q=""):
    return [res, typ, q]


def alarm(key, sev, cleared=False, op="none", count=1, due=None):
    return {"key": key, "severity": sev, "cleared": cleared, "operator": op, "count": count, "escalation_due": due}


def rep(res, typ, sev=None, cleared=False):
    return {"report": {"resource": res, "type": typ, "qualifier": "", "severity": sev, "cleared": cleared}}


def ack(res, typ, state, by="did:web:noc.example:users:ann"):
    return {"ack": {"alarm": {"resource": res, "type": typ, "qualifier": ""}, "state": state, "by": by}}


def trace(vid, desc, refs, ctx, steps):
    return ev(vid, desc, refs, {"steps": [{"event": e} for e, _ in steps]}, [x for _, x in steps], ctx)


def vectors() -> list[dict]:
    out = []
    # --- E§3: notifications → events --------------------------------------------------------------
    v1 = {"version": "v1", "enterprise": ENT, "agent_addr": "192.0.2.7", "generic": 2, "specific": 0, "timestamp": 4200,
          "community": "public", "varbinds": [vb(IFINDEX + ".2", "Integer32", "2")]}
    out.append(ev("trap-v1-generic-linkdown", "An SNMPv1 linkDown (generic 2) → snmpTrapOID linkDown; snmpTrapAddress.0 and "
                  "snmpTrapEnterprise.0 appended; the community is not carried (RFC 3584 §3.1).", ["E§3"],
                  {"check": "trap", "trap": v1},
                  {"snmp": {"version": "v1", "uptime": 4200, "trap_oid": LINKDOWN,
                            "varbinds": [vb(IFINDEX + ".2", "Integer32", "2"), vb(TADDR, "IpAddress", "192.0.2.7"),
                                         vb(TENT, "OBJECT IDENTIFIER", ENT)]}}))
    out.append(ev("trap-v1-generic-coldstart", "Generic-trap 0 → coldStart 1.3.6.1.6.3.1.1.5.1.", ["E§3"],
                  {"check": "trap", "trap": dict(v1, generic=0, varbinds=[])},
                  {"snmp": {"version": "v1", "uptime": 4200, "trap_oid": "1.3.6.1.6.3.1.1.5.1",
                            "varbinds": [vb(TADDR, "IpAddress", "192.0.2.7"), vb(TENT, "OBJECT IDENTIFIER", ENT)]}}))
    out.append(ev("trap-v1-enterprise-specific", "Generic-trap 6 → enterprise.0.specific.", ["E§3"],
                  {"check": "trap", "trap": dict(v1, generic=6, specific=17, varbinds=[])},
                  {"snmp": {"version": "v1", "uptime": 4200, "trap_oid": ENT + ".0.17",
                            "varbinds": [vb(TADDR, "IpAddress", "192.0.2.7"), vb(TENT, "OBJECT IDENTIFIER", ENT)]}}))
    out.append(ev("trap-v1-proxy-varbinds-not-duplicated", "A v1 trap already carrying snmpTrapAddress.0 gets it once, not twice.",
                  ["E§3"], {"check": "trap", "trap": dict(v1, varbinds=[vb(TADDR, "IpAddress", "198.51.100.1")])},
                  {"snmp": {"version": "v1", "uptime": 4200, "trap_oid": LINKDOWN,
                            "varbinds": [vb(TADDR, "IpAddress", "198.51.100.1"), vb(TENT, "OBJECT IDENTIFIER", ENT)]}}))
    v2 = {"version": "v2c", "community": "public",
          "varbinds": [vb(UP, "TimeTicks", "123400"), vb(TOID, "OBJECT IDENTIFIER", LINKDOWN), vb(IFINDEX + ".3", "Integer32", "3")]}
    out.append(ev("trap-v2c", "A v2c trap: sysUpTime.0 and snmpTrapOID.0 lifted out; the rest kept in order.", ["E§3"],
                  {"check": "trap", "trap": v2},
                  {"snmp": {"version": "v2c", "uptime": 123400, "trap_oid": LINKDOWN, "varbinds": [vb(IFINDEX + ".3", "Integer32", "3")]}}))
    out.append(ev("trap-community-varbind-stripped", "A forwarded trap carrying snmpTrapCommunity.0: dropped, never carried.",
                  ["E§3"], {"check": "trap", "trap": dict(v2, varbinds=v2["varbinds"] + [vb(TCOMM, "OCTET STRING", "s3cret")])},
                  {"snmp": {"version": "v2c", "uptime": 123400, "trap_oid": LINKDOWN, "varbinds": [vb(IFINDEX + ".3", "Integer32", "3")]}}))
    out.append(ev("trap-v2-missing-uptime", "A v2 notification whose first varbind is not sysUpTime.0.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=v2["varbinds"][1:])}, {"error": "malformed-trap"}))
    out.append(ev("trap-v2-oid-not-second", "snmpTrapOID.0 must be the second varbind.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=[v2["varbinds"][0], v2["varbinds"][2], v2["varbinds"][1]])},
                  {"error": "malformed-trap"}))

    out.append(ev("trap-v2-uptime-not-decimal", "sysUpTime.0 must be a string of decimal digits.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=[vb(UP, "TimeTicks", "12a"), v2["varbinds"][1]])},
                  {"error": "malformed-trap"}))
    out.append(ev("trap-v2-uptime-beyond-2p53", "A sysUpTime.0 above 2^53−1.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=[vb(UP, "TimeTicks", str(2**53)), v2["varbinds"][1]])},
                  {"error": "malformed-trap"}))
    out.append(ev("trap-v2-uptime-leading-zeros", "A sysUpTime.0 of \"007\" is a string of decimal digits: 7.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=[vb(UP, "TimeTicks", "007"), v2["varbinds"][1]])},
                  {"snmp": {"version": "v2c", "uptime": 7, "trap_oid": LINKDOWN, "varbinds": []}}))
    out.append(ev("trap-v2-trap-oid-not-string", "snmpTrapOID.0's value must be a string.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=[v2["varbinds"][0], vb(TOID, "OBJECT IDENTIFIER", 3)])},
                  {"error": "malformed-trap"}))
    out.append(ev("trap-varbind-without-type", "A varbind with no type.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=v2["varbinds"][:2] + [{"oid": IFINDEX + ".3", "value": "3"}])},
                  {"error": "malformed-trap"}))
    out.append(ev("trap-v1-generic-out-of-range", "A v1 generic-trap of 7 is not a generic trap.", ["E§3"],
                  {"check": "trap", "trap": dict(v1, generic=7)}, {"error": "malformed-trap"}))
    out.append(ev("trap-v1-missing-enterprise", "A v1 trap with no enterprise.", ["E§3"],
                  {"check": "trap", "trap": {k: x for k, x in v1.items() if k != "enterprise"}}, {"error": "malformed-trap"}))
    out.append(ev("trap-varbind-extra-member-dropped", "Only oid, type and value of each varbind are carried.", ["E§3"],
                  {"check": "trap", "trap": dict(v2, varbinds=v2["varbinds"][:2] + [dict(vb(IFINDEX + ".3", "Integer32", "3"), raw="AgEA")])},
                  {"snmp": {"version": "v2c", "uptime": 123400, "trap_oid": LINKDOWN, "varbinds": [vb(IFINDEX + ".3", "Integer32", "3")]}}))

    # --- E§3: syslog severity ----------------------------------------------------------------------
    for sev, want in [(0, "critical"), (2, "critical"), (3, "major"), (4, "warning"), (5, None), (7, None)]:
        out.append(ev(f"syslog-severity-{sev}", f"The default table: syslog severity {sev} → {want or 'not an alarm'}.", ["E§3"],
                      {"check": "syslog-severity", "severity": sev}, {"severity": want}))
    out.append(ev("syslog-severity-override", "A gateway's table overrides the default for one severity.", ["E§3"],
                  {"check": "syslog-severity", "severity": 4, "table": {"4": "minor"}}, {"severity": "minor"}))

    # --- E§4: the rule table -----------------------------------------------------------------------
    raw = {"snmp": {"version": "v2c", "uptime": 1, "trap_oid": LINKDOWN, "varbinds": [vb(IFINDEX + ".3", "Integer32", "3")]}}
    rules = [{"trap_oid": LINKDOWN, "action": "raise", "type": "link-down", "severity": "major", "resource_varbind": IFINDEX},
             {"trap_oid": LINKUP, "action": "clear", "type": "link-down", "resource_varbind": IFINDEX}]
    out.append(ev("map-raise-with-resource", "linkDown → raise link-down on 192.0.2.7/3 (the ifIndex varbind).", ["E§4"],
                  {"check": "map", "raw": raw, "rules": rules, "source": "192.0.2.7"},
                  {"alarm": {"resource": "192.0.2.7/3", "type": "link-down", "qualifier": "", "severity": "major", "cleared": False}}))
    up = {"snmp": dict(raw["snmp"], trap_oid=LINKUP)}
    out.append(ev("map-clear", "linkUp → clear the same alarm key.", ["E§4"],
                  {"check": "map", "raw": up, "rules": rules, "source": "192.0.2.7"},
                  {"alarm": {"resource": "192.0.2.7/3", "type": "link-down", "qualifier": "", "severity": None, "cleared": True}}))
    out.append(ev("map-unmatched-is-notify", "A notification no rule matches is an event with no alarm.", ["E§4"],
                  {"check": "map", "raw": {"snmp": dict(raw["snmp"], trap_oid="1.3.6.1.6.3.1.1.5.1")}, "rules": rules,
                   "source": "192.0.2.7"}, {"notify": True}))
    out.append(ev("map-first-rule-wins", "Two matching rules: the first wins.", ["E§4"],
                  {"check": "map", "raw": raw, "rules": [{"trap_oid": LINKDOWN, "action": "notify", "type": "x"}] + rules,
                   "source": "192.0.2.7"}, {"notify": True}))
    out.append(ev("map-varbind-condition", "A rule with a varbind condition matches only that value.", ["E§4"],
                  {"check": "map", "raw": raw, "rules": [
                      {"trap_oid": LINKDOWN, "varbind": {"oid": IFINDEX + ".3", "value": "9"}, "action": "raise", "type": "x",
                       "severity": "minor"},
                      {"trap_oid": LINKDOWN, "varbind": {"oid": IFINDEX + ".3", "value": "3"}, "action": "raise", "type": "uplink-down",
                       "severity": "critical"}], "source": "192.0.2.7"},
                  {"alarm": {"resource": "192.0.2.7", "type": "uplink-down", "qualifier": "", "severity": "critical", "cleared": False}}))
    out.append(ev("map-raise-without-severity", "A raise rule naming no severity gives severity null.", ["E§4"],
                  {"check": "map", "raw": raw, "rules": [{"trap_oid": LINKDOWN, "action": "raise", "type": "link-down"}],
                   "source": "192.0.2.7"},
                  {"alarm": {"resource": "192.0.2.7", "type": "link-down", "qualifier": "", "severity": None, "cleared": False}}))
    out.append(ev("map-resource-varbind-absent", "resource_varbind names no varbind present: the resource is the source.", ["E§4"],
                  {"check": "map", "raw": {"snmp": dict(raw["snmp"], varbinds=[])}, "rules": rules, "source": "192.0.2.7"},
                  {"alarm": {"resource": "192.0.2.7", "type": "link-down", "qualifier": "", "severity": "major", "cleared": False}}))

    # --- E§5: the alarm list -----------------------------------------------------------------------
    R, T = "192.0.2.7/3", "link-down"
    K = k(R, T)
    out.append(trace("alarm-raise-repeat-clear", "Raise; a repeat only counts (nothing emitted); clear keeps the alarm.", ["E§5"],
                     {"now": 1000}, [
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}],
                                               "alarms": [alarm(K, "major")]}),
                         (rep(R, T, "major"), {"emit": [], "alarms": [alarm(K, "major", count=2)]}),
                         (rep(R, T, cleared=True), {"emit": [{"cleared": {"key": K}}], "alarms": [alarm(K, "major", True, count=3)]}),
                         (rep(R, T, cleared=True), {"emit": [], "alarms": [alarm(K, "major", True, count=4)]}),
                     ]))
    out.append(trace("alarm-clear-unknown-creates-nothing", "A clear for an alarm never raised creates nothing.", ["E§5"], {"now": 0}, [
        (rep(R, T, cleared=True), {"emit": [], "alarms": []}),
    ]))
    out.append(trace("alarm-severity-change", "A different severity while active: changed.", ["E§5"], {"now": 0}, [
        (rep(R, T, "minor"), {"emit": [{"raised": {"key": K, "severity": "minor", "reopened": False}}], "alarms": [alarm(K, "minor")]}),
        (rep(R, T, "critical"), {"emit": [{"changed": {"key": K, "severity": "critical"}}], "alarms": [alarm(K, "critical", count=2)]}),
    ]))
    out.append(trace("alarm-reraise-reopens-and-resets-ack", "spec-gap 103: a re-raise after a clear reopens the same alarm and "
                     "returns its operator state to none.", ["E§5"], {"now": 0}, [
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}],
                                               "alarms": [alarm(K, "major")]}),
                         (ack(R, T, "ack"), {"emit": [{"operator": {"key": K, "state": "ack", "by": "did:web:noc.example:users:ann"}}],
                                             "alarms": [alarm(K, "major", op="ack")]}),
                         (rep(R, T, cleared=True), {"emit": [{"cleared": {"key": K}}], "alarms": [alarm(K, "major", True, "ack", 2)]}),
                         (rep(R, T, "minor"), {"emit": [{"raised": {"key": K, "severity": "minor", "reopened": True}}],
                                               "alarms": [alarm(K, "minor", False, "none", 3)]}),
                     ]))
    out.append(trace("alarm-ack-then-closed-is-final", "ack → closed; an ack after closed is ignored; closing does not clear.",
                     ["E§5"], {"now": 0}, [
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}],
                                               "alarms": [alarm(K, "major")]}),
                         (ack(R, T, "closed"), {"emit": [{"operator": {"key": K, "state": "closed", "by": "did:web:noc.example:users:ann"}}],
                                                "alarms": [alarm(K, "major", op="closed")]}),
                         (ack(R, T, "ack"), {"emit": [], "alarms": [alarm(K, "major", op="closed")]}),
                     ]))
    out.append(trace("alarm-ack-unknown-ignored", "An acknowledgement for an alarm not in the list changes nothing.", ["E§5"], {"now": 0}, [
        (ack(R, T, "ack"), {"emit": [], "alarms": []}),
    ]))
    out.append(trace("alarm-unknown-severity-orders-lowest", "An unregistered severity token is kept, and orders as indeterminate "
                     "(below the escalation threshold).", ["E§5", "E§6"], {"now": 0, "escalation": {"min_severity": "warning", "after_s": 60}}, [
                         (rep(R, T, "catastrophic"), {"emit": [{"raised": {"key": K, "severity": "catastrophic", "reopened": False}}],
                                                      "alarms": [alarm(K, "catastrophic")]}),
                     ]))
    G, KS = GW, k(GW, "dsip-gateway-silent")
    out.append(trace("gateway-silence", "No heartbeat for twice the interval raises dsip-gateway-silent; the next heartbeat clears it.",
                     ["E§5"], {"now": 0}, [
                         ({"heartbeat": {"gateway": G, "interval_s": 60}}, {"emit": [], "alarms": []}),
                         ({"advance": 120}, {"emit": [], "alarms": []}),
                         ({"advance": 1}, {"emit": [{"raised": {"key": KS, "severity": "major", "reopened": False}}],
                                           "alarms": [alarm(KS, "major")]}),
                         ({"advance": 600}, {"emit": [], "alarms": [alarm(KS, "major")]}),
                         ({"heartbeat": {"gateway": G, "interval_s": 60}}, {"emit": [{"cleared": {"key": KS}}],
                                                                           "alarms": [alarm(KS, "major", True, count=2)]}),
                     ]))

    GA, GB = "did:web:noc.example:gw:a", "did:web:noc.example:gw:b"
    out.append(trace("gateway-silence-two-in-id-order", "Two gateways go silent in one advance: raised in order of gateway id, "
                     "not of first heartbeat.", ["E§5"], {"now": 0}, [
                         ({"heartbeat": {"gateway": GB, "interval_s": 10}}, {"emit": [], "alarms": []}),
                         ({"heartbeat": {"gateway": GA, "interval_s": 10}}, {"emit": [], "alarms": []}),
                         ({"advance": 21}, {"emit": [{"raised": {"key": k(GA, "dsip-gateway-silent"), "severity": "major", "reopened": False}},
                                                     {"raised": {"key": k(GB, "dsip-gateway-silent"), "severity": "major", "reopened": False}}],
                                            "alarms": [alarm(k(GA, "dsip-gateway-silent"), "major"), alarm(k(GB, "dsip-gateway-silent"), "major")]}),
                     ]))
    out.append(trace("alarm-ack-without-by", "An acknowledgement with no `by`: emitted as null.", ["E§5"], {"now": 0}, [
        (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}], "alarms": [alarm(K, "major")]}),
        ({"ack": {"alarm": {"resource": R, "type": T}, "state": "ack"}},
         {"emit": [{"operator": {"key": K, "state": "ack", "by": None}}], "alarms": [alarm(K, "major", op="ack")]}),
    ]))

    # --- E§6: escalation ---------------------------------------------------------------------------
    P = {"min_severity": "major", "after_s": 300}
    out.append(trace("escalate-unacked", "An unacknowledged major alarm escalates after after_s, once.", ["E§6"],
                     {"now": 1000, "escalation": P}, [
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}],
                                               "alarms": [alarm(K, "major", due=1300)]}),
                         ({"advance": 299}, {"emit": [], "alarms": [alarm(K, "major", due=1300)]}),
                         ({"advance": 1}, {"emit": [{"escalate": {"key": K, "severity": "major"}}], "alarms": [alarm(K, "major")]}),
                         ({"advance": 1000}, {"emit": [], "alarms": [alarm(K, "major")]}),
                     ]))
    out.append(trace("escalate-cancelled-by-ack", "An ack before after_s cancels the escalation.", ["E§6"], {"now": 0, "escalation": P}, [
        (rep(R, T, "critical"), {"emit": [{"raised": {"key": K, "severity": "critical", "reopened": False}}],
                                 "alarms": [alarm(K, "critical", due=300)]}),
        (ack(R, T, "ack"), {"emit": [{"operator": {"key": K, "state": "ack", "by": "did:web:noc.example:users:ann"}}],
                            "alarms": [alarm(K, "critical", op="ack")]}),
        ({"advance": 600}, {"emit": [], "alarms": [alarm(K, "critical", op="ack")]}),
    ]))
    out.append(trace("escalate-cancelled-by-clear", "A clear before after_s cancels the escalation.", ["E§6"], {"now": 0, "escalation": P}, [
        (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}], "alarms": [alarm(K, "major", due=300)]}),
        (rep(R, T, cleared=True), {"emit": [{"cleared": {"key": K}}], "alarms": [alarm(K, "major", True, count=2)]}),
        ({"advance": 600}, {"emit": [], "alarms": [alarm(K, "major", True, count=2)]}),
    ]))
    out.append(trace("escalate-below-threshold-never", "A minor alarm under min_severity major never escalates; rising to major "
                     "starts the timer then.", ["E§6"], {"now": 0, "escalation": P}, [
                         (rep(R, T, "minor"), {"emit": [{"raised": {"key": K, "severity": "minor", "reopened": False}}],
                                               "alarms": [alarm(K, "minor")]}),
                         ({"advance": 500}, {"emit": [], "alarms": [alarm(K, "minor")]}),
                         (rep(R, T, "major"), {"emit": [{"changed": {"key": K, "severity": "major"}}],
                                               "alarms": [alarm(K, "major", count=2, due=800)]}),
                         (rep(R, T, "minor"), {"emit": [{"changed": {"key": K, "severity": "minor"}}],
                                               "alarms": [alarm(K, "minor", count=3)]}),
                         ({"advance": 400}, {"emit": [], "alarms": [alarm(K, "minor", count=3)]}),
                     ]))
    out.append(trace("escalate-severity-rise-keeps-timer", "Rising from major to critical keeps the running timer.", ["E§6"],
                     {"now": 0, "escalation": P}, [
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}],
                                               "alarms": [alarm(K, "major", due=300)]}),
                         ({"advance": 200}, {"emit": [], "alarms": [alarm(K, "major", due=300)]}),
                         (rep(R, T, "critical"), {"emit": [{"changed": {"key": K, "severity": "critical"}}],
                                                  "alarms": [alarm(K, "critical", count=2, due=300)]}),
                         ({"advance": 100}, {"emit": [{"escalate": {"key": K, "severity": "critical"}}],
                                             "alarms": [alarm(K, "critical", count=2)]}),
                     ]))
    out.append(trace("escalate-again-after-reopen", "A reopened alarm can escalate again (once per raise).", ["E§6"],
                     {"now": 0, "escalation": P}, [
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}],
                                               "alarms": [alarm(K, "major", due=300)]}),
                         ({"advance": 300}, {"emit": [{"escalate": {"key": K, "severity": "major"}}], "alarms": [alarm(K, "major")]}),
                         (rep(R, T, cleared=True), {"emit": [{"cleared": {"key": K}}], "alarms": [alarm(K, "major", True, count=2)]}),
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": True}}],
                                               "alarms": [alarm(K, "major", count=3, due=600)]}),
                         ({"advance": 300}, {"emit": [{"escalate": {"key": K, "severity": "major"}}], "alarms": [alarm(K, "major", count=3)]}),
                     ]))
    K2 = k("192.0.2.9/1", T)
    out.append(trace("escalate-order-by-due-then-key", "Several escalations due in one advance: by due time, then key.", ["E§6"],
                     {"now": 0, "escalation": P}, [
                         (rep("192.0.2.9/1", T, "major"), {"emit": [{"raised": {"key": K2, "severity": "major", "reopened": False}}],
                                                           "alarms": [alarm(K2, "major", due=300)]}),
                         (rep(R, T, "major"), {"emit": [{"raised": {"key": K, "severity": "major", "reopened": False}}],
                                               "alarms": [alarm(K, "major", due=300), alarm(K2, "major", due=300)]}),
                         ({"advance": 300}, {"emit": [{"escalate": {"key": K, "severity": "major"}},
                                                      {"escalate": {"key": K2, "severity": "major"}}],
                                             "alarms": [alarm(K, "major"), alarm(K2, "major")]}),
                     ]))
    # --- E§3: informs, answered only once stored -------------------------------------------------------
    S = "192.0.2.7:161"
    CTX = {"component": "informs", "now": 0}

    def inf(rid):
        return {"inform": {"source": S, "request_id": rid}}

    def ok(rid):
        return {"accepted": {"key": [S, rid]}}

    def no(rid):
        return {"refused": {"key": [S, rid]}}

    def st(rid, status):
        return {"key": [S, rid], "status": status}

    out.append(trace("inform-answered-once-stored", "An inform deposits one event and is answered only when the hub accepts it.",
                     ["E§3"], CTX, [
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                         (ok(7), {"emit": [{"respond": {"key": [S, 7]}}], "informs": [st(7, "answered")]}),
                     ]))
    out.append(trace("inform-retransmission-while-pending", "A retransmission before the hub accepts deposits nothing and is not "
                     "answered: the device keeps retrying.", ["E§3"], CTX, [
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                         (inf(7), {"emit": [], "informs": [st(7, "pending")]}),
                         (inf(7), {"emit": [], "informs": [st(7, "pending")]}),
                         (ok(7), {"emit": [{"respond": {"key": [S, 7]}}], "informs": [st(7, "answered")]}),
                     ]))
    out.append(trace("inform-retransmission-after-answer", "A retransmission after the answer (the response was lost) is answered "
                     "again, without a second event.", ["E§3"], CTX, [
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                         (ok(7), {"emit": [{"respond": {"key": [S, 7]}}], "informs": [st(7, "answered")]}),
                         (inf(7), {"emit": [{"respond": {"key": [S, 7]}}], "informs": [st(7, "answered")]}),
                     ]))
    out.append(trace("inform-refused-deposits-again", "The hub refused the deposit: no answer, and the device's next retransmission "
                     "deposits anew.", ["E§3"], CTX, [
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                         (no(7), {"emit": [], "informs": []}),
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                     ]))
    out.append(trace("inform-distinct-request-ids", "Two informs with different request ids are two events.", ["E§3"], CTX, [
        (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
        (inf(8), {"emit": [{"deposit": {"key": [S, 8]}}], "informs": [st(7, "pending"), st(8, "pending")]}),
        (ok(8), {"emit": [{"respond": {"key": [S, 8]}}], "informs": [st(7, "pending"), st(8, "answered")]}),
    ]))
    out.append(trace("inform-answered-forgotten-after-300s", "An answered inform is remembered 300 s; after that the same request id "
                     "is a new inform.", ["E§3"], CTX, [
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                         (ok(7), {"emit": [{"respond": {"key": [S, 7]}}], "informs": [st(7, "answered")]}),
                         ({"advance": 299}, {"emit": [], "informs": [st(7, "answered")]}),
                         ({"advance": 1}, {"emit": [], "informs": []}),
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                     ]))
    out.append(trace("inform-keys-sort-numerically", "Request ids sort as numbers: 9 before 10.", ["E§3"], CTX, [
        (inf(10), {"emit": [{"deposit": {"key": [S, 10]}}], "informs": [st(10, "pending")]}),
        (inf(9), {"emit": [{"deposit": {"key": [S, 9]}}], "informs": [st(9, "pending"), st(10, "pending")]}),
    ]))
    out.append(trace("inform-accept-for-unknown-ignored", "An acceptance for an inform not pending changes nothing.", ["E§3"], CTX, [
        (ok(9), {"emit": [], "informs": []}),
    ]))
    out.append(trace("inform-pending-never-expires", "A pending inform is not forgotten: its event may still be accepted after an outage.",
                     ["E§3"], CTX, [
                         (inf(7), {"emit": [{"deposit": {"key": [S, 7]}}], "informs": [st(7, "pending")]}),
                         ({"advance": 3600}, {"emit": [], "informs": [st(7, "pending")]}),
                         (ok(7), {"emit": [{"respond": {"key": [S, 7]}}], "informs": [st(7, "answered")]}),
                     ]))
    from . import events_v3  # SNMPv3 (USM) and syslog
    out += events_v3.usm_key_vectors() + events_v3.snmpv3_vectors() + events_v3.syslog_vectors()
    return out
