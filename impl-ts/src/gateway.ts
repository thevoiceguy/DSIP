/**
 * Gateway Profile 1.0: the normative tables a DSIP ↔ SIP/PSTN gateway applies, and the B2BUA
 * controller that joins a DSIP leg to a SIP leg.
 *
 * Spec: G§3 (controller), G§4 (reason mapping both ways; core §15.5), G§5 (PSTN caller identity as
 * a `tel` claim), G§6 (SDP ↔ descriptors), G§7 (trust downgrade; core §6.3), G§8 (early media),
 * G§9 (DTMF). `G§n` cites `v0.8/dsip-gateway-profile-v0.8.md`.
 *
 * The controller never re-implements the §12 state machine: it tells the hosted DSIP engine what
 * to do with the engine's own local events (`place_call`, `alert`, `accept`, …).
 */
import type { Json, JsonObject } from "./did.js";
import { verificationBasis } from "./trust.js";

// ---- G§4.1 inbound: SIP/Q.850 → DSIP

/** Spec: G§4.1 — Q.850 cause → DSIP token; checked before the SIP status. */
const Q850_IN: Record<number, string> = {
  1: "identity.unknown", 28: "identity.unknown",
  16: "user.hangup", 31: "user.hangup",
  17: "endpoint.busy",
  18: "endpoint.unavailable", 19: "endpoint.unavailable", 20: "endpoint.unavailable",
  21: "user.declined",
  22: "identity.not-in-service",
  34: "gateway.unreachable", 38: "gateway.unreachable", 41: "gateway.unreachable", 42: "gateway.unreachable",
  43: "gateway.unreachable", 44: "gateway.unreachable",
  47: "media.failed",
  63: "media.unsupported", 65: "media.unsupported", 79: "media.unsupported",
  102: "session.timeout",
};

/** Spec: G§4.1 — SIP status → DSIP token, when no mapped Q.850 cause is present. */
const STATUS_IN: Record<number, string> = {
  403: "policy.blocked", 487: "session.cancelled",
  404: "identity.unknown", 484: "identity.unknown", 604: "identity.unknown",
  488: "media.unsupported", 415: "media.unsupported", 606: "media.unsupported",
  408: "endpoint.unavailable", 480: "endpoint.unavailable",
  486: "endpoint.busy", 600: "endpoint.busy",
  410: "identity.not-in-service",
  502: "gateway.unreachable", 503: "gateway.unreachable", 504: "gateway.unreachable",
  603: "user.declined",
};

/**
 * Spec: G§4 — tokens describing a failed *attempt*; after ACTIVE they are reported as `gateway.mapped`.
 * Impl: G§4 lists "busy, declined, unknown, moved, cancelled, blocked"; the suite also treats
 * `endpoint.unavailable` and `identity.not-in-service` so — both say why a call could not be set
 * up, which a mid-call teardown cannot mean (spec-gap 78).
 */
const ATTEMPT_TOKENS = [
  "endpoint.busy", "endpoint.unavailable", "user.declined", "identity.unknown", "identity.not-in-service",
  "identity.moved", "session.cancelled", "policy.blocked",
];

/** What an inbound SIP outcome becomes on the DSIP leg. */
export interface InboundReason {
  reason: string;
  carry: "reject" | "bye" | "error";
  detail?: string;
}

/** Spec: G§4.1 */
export function reasonInbound(i: { sip_status?: number; q850?: number; phase?: string; moved_to?: string }): InboundReason {
  const phase = i.phase ?? "pre-answer";
  const carry = phase === "active" ? "bye" : phase === "transport" ? "error" : "reject";
  // A BYE with no Reason is a normal hangup
  if (i.q850 === undefined && i.sip_status === undefined) return { reason: "user.hangup", carry };
  const byCause = i.q850 !== undefined ? Q850_IN[i.q850] : undefined;
  let reason = byCause ?? (i.sip_status !== undefined ? STATUS_IN[i.sip_status] : undefined) ?? "gateway.mapped";
  // The cause, when mapped, is the more specific signal; an unmappable one is still what gets reported
  let detail = byCause !== undefined || i.sip_status === undefined ? `Q.850 ${i.q850}` : `SIP ${i.sip_status}`;
  if (reason === "identity.not-in-service" && i.moved_to !== undefined) [reason, detail] = ["identity.moved", i.moved_to];
  if (phase === "active" && ATTEMPT_TOKENS.includes(reason)) reason = "gateway.mapped";
  return { reason, carry, detail };
}

// ---- G§4.2 outbound: DSIP → SIP

/** Spec: G§4.2 — registered token → [SIP status, Q.850 cause]. */
const OUT: Record<string, [number, number?]> = {
  "user.declined": [603, 21], "user.blocked": [603, 21], "user.no-answer": [480, 19], "user.cancelled": [487],
  "endpoint.busy": [486, 17], "endpoint.unavailable": [480, 18], "endpoint.capability": [488, 79],
  "identity.not-in-service": [410, 22], "identity.moved": [410, 22], "identity.suspended": [403, 21], "identity.unknown": [404, 1],
  "session.expired": [480, 102], "session.timeout": [480, 102], "session.failed": [500, 41],
  "policy.blocked": [403, 21], "policy.trust-insufficient": [403, 21], "policy.first-contact-required": [403, 21],
  "policy.rate-limited": [503, 42], "policy.terminated": [480, 31],
  "media.unsupported": [488, 65], "media.offer-required": [488, 65], "media.encryption-required": [488, 65],
  "transport.unknown-recipient": [404, 1], "transport.rate-limited": [503, 42],
  "transport.envelope-too-large": [503, 41], "transport.hello-required": [503, 41], "transport.hello-rejected": [503, 41],
  "transport.routing-refused": [503, 41],
  "gateway.unreachable": [503, 38], "gateway.mapped": [500, 41],
};

/** Spec: G§4.2 — the causes of the tokens that end an ACTIVE call in the ordinary way. */
const BYE_CAUSES: Record<string, number> = {
  "user.hangup": 16, "session.already-answered": 16, "session.cancelled": 16, "media.failed": 47, "policy.terminated": 31,
};

/** Spec: G§4.2 — fallback by §15.1 category; causes are those of the category's representative row. */
const OUT_CATEGORY: Record<string, [number, number]> = {
  user: [603, 21], endpoint: [480, 18], identity: [404, 1], session: [500, 41], media: [488, 65],
  policy: [403, 21], transport: [503, 41], gateway: [503, 38],
};

/** Spec: G§4.2; every crossing carries `Reason: DSIP;text="<token>"` (G§3). */
export function reasonOutbound(token: string, phase: string): JsonObject {
  const reason_header = { protocol: "DSIP", text: token };
  const category = token.split(".")[0]!;
  // §15.1: an unrecognized category is read as session.failed
  const [status, cause] = OUT[token] ?? OUT_CATEGORY[category] ?? OUT["session.failed"]!;
  if (phase === "active") {
    // G§4.2 (spec-gap 79): the BYE rows — a normal ending is cause 16, a failed media path 47, a policy
    // termination 31; any other registered token keeps the cause of its own row (`session.timeout` → 102 says
    // more than "normal clearing"); an unregistered token has no row, so 16
    const q850 = BYE_CAUSES[token] ?? OUT[token]?.[1] ?? 16;
    return { method: "BYE", q850, reason_header };
  }
  return {
    status, ...(cause !== undefined ? { q850: cause } : {}), reason_header,
    ...(token === "policy.rate-limited" ? { retry_after: true } : {}),
  };
}

// ---- G§5 claims

/** The gateway's own identity; the vectors fix it (vectors README, kind `gateway`). */
export const GATEWAY_DID = "did:web:gw.example";

/** Spec: G§5 — the PSTN caller is a claim the gateway makes, never the signer. */
export function telClaim(i: { from_tn: string; identity?: { attest: string; verified: boolean; orig_tn: string }; cnam?: string }): JsonObject {
  // A PASSporT whose `orig` names a different number attests some other call: discarded
  const usable = i.identity !== undefined && i.identity.orig_tn === i.from_tn ? i.identity : undefined;
  const claim: JsonObject = {
    type: "tel", number: i.from_tn,
    attestation: usable?.attest ?? "none", verified: usable?.verified === true, verifier: GATEWAY_DID,
    ...(i.cnam !== undefined ? { cnam: i.cnam } : {}),
  };
  return { claim, trust_basis: verificationBasis(GATEWAY_DID, [claim]) };
}

// ---- G§6 SDP ↔ descriptors

/** Trunk encoding name ⇄ DSIP codec id. Spec: G§6 */
const CODECS: [string, string][] = [
  ["opus", "codec:audio/opus"], ["PCMU", "codec:audio/pcmu"], ["PCMA", "codec:audio/pcma"], ["G722", "codec:audio/g722"],
  ["H264", "codec:video/h264"], ["VP8", "codec:video/vp8"], ["AV1", "codec:video/av1"],
];

/** Spec: G§6 — each m=audio/m=video with a known codec becomes a descriptor; the direction carries. */
export function sdpToDescriptors(sdp: string): JsonObject {
  const lines = sdp.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines[0] !== "v=0" || !lines.some((l) => l.startsWith("m="))) return { error: "unparseable" };
  const media: JsonObject[] = [];
  let srtp = "none";
  let current: { kind: string; codecs: JsonObject[]; direction: string } | null = null;
  const flush = (): void => {
    if (current && current.codecs.length) media.push({ type: current.kind, direction: current.direction, codecs: current.codecs });
  };
  for (const line of lines) {
    if (line.startsWith("m=")) {
      flush();
      const [kind, , proto] = line.slice(2).split(" ");
      current = kind === "audio" || kind === "video" ? { kind, codecs: [], direction: "sendrecv" } : null;
      if (proto?.startsWith("UDP/TLS/RTP/SAVP")) srtp = "dtls";
    } else if (line.startsWith("a=crypto:") && srtp === "none") {
      srtp = "sdes";
    } else if (current && line.startsWith("a=rtpmap:")) {
      const name = line.split(" ")[1]?.split("/")[0]?.toLowerCase();
      const known = CODECS.find(([encoding]) => encoding.toLowerCase() === name);
      if (known) current.codecs.push({ id: known[1] });
    } else if (current && ["a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"].includes(line)) {
      current.direction = line.slice(2);
    }
  }
  flush();
  return { media, srtp };
}

/** Spec: G§6 — the negotiated codecs and direction become the SIP leg's m= lines. */
export function descriptorsToSdp(media: JsonObject[]): JsonObject {
  return {
    m_lines: media.map((d) => ({
      kind: d["type"]!,
      encodings: ((d["codecs"] ?? []) as JsonObject[]).map((c) => CODECS.find(([, id]) => id === c["id"])?.[0]).filter((e) => e !== undefined) as string[],
      direction: d["direction"] ?? "sendrecv",
    })),
  };
}

// ---- G§7 downgrade

/** Spec: G§7 — the guarantees a crossing loses, each named, in table order. */
export function downgrade(facts: JsonObject): { downgraded: boolean; lost: string[] } {
  const lost: string[] = [];
  const outbound = facts["direction"] === "outbound";
  if (facts["trunk_srtp"] === false) lost.push("no-srtp-on-trunk");
  if (outbound && facts["identity_assertable"] === false) lost.push("identity-not-assertable");
  if (!outbound && (facts["attestation"] ?? "none") === "none") lost.push("no-attestation");
  if (facts["policy_present"] === true) lost.push("policy-unenforceable");
  return { downgraded: lost.length > 0, lost };
}

/** The `detail` of the informational `error gateway.downgraded`, or `null` when nothing was lost. Spec: G§7 */
export function downgradeError(facts: JsonObject): JsonObject | null {
  const { downgraded, lost } = downgrade(facts);
  return downgraded ? { losses: lost } : null;
}

// ---- G§3 controller

/** The B2BUA controller for one call. Spec: G§3.1 (outbound), G§3.2 (inbound), G§8, G§9 */
export class GatewayCall {
  private dsip: string;
  private sip: string;
  private answered = false;

  constructor(private readonly ctx: { direction: "inbound" | "outbound"; early_media?: string }) {
    this.dsip = "idle";
    this.sip = "idle";
  }

  /** Apply one event; returns what each leg is told, and both leg states. */
  step(e: JsonObject): JsonObject {
    const emit = "timer" in e ? this.timerC() : "dsip" in e ? this.fromDsip(e["dsip"] as JsonObject) : this.fromSip(e["sip"] as JsonObject);
    return { emit, state: { dsip: this.dsip, sip: this.sip } };
  }

  private get up(): boolean {
    return this.dsip === "active" && this.answered;
  }

  private timerC(): Json[] {
    // G§3.1: no final response → CANCEL, and the DSIP leg is refused gateway.unreachable
    [this.dsip, this.sip] = ["ended", "terminated"];
    return [{ sip: "CANCEL" }, { dsip: { local: "auto_reject", reason: "gateway.unreachable", detail: "SIP Timer C" } }];
  }

  private dtmfToDsip(s: JsonObject): Json {
    const data: JsonObject = { digits: s["dtmf"]!, ...("duration_ms" in s ? { duration_ms: s["duration_ms"]! } : {}) };
    return { dsip: { local: "info", about: "media:dtmf", data } };
  }

  private fromDsip(m: JsonObject): Json[] {
    const type = m["type"] as string;
    if (type === "info") {
      // G§9: only media:dtmf crosses, and only while the call is up
      if (m["about"] !== "media:dtmf") return [{ ignore: `dsip info ${String(m["about"])}` }];
      if (!this.up) return [{ ignore: "dsip dtmf outside the established call" }];
      const data = m["data"] as JsonObject;
      return [{ sip: { request: "INFO", dtmf: data["digits"]!, ...("duration_ms" in data ? { duration_ms: data["duration_ms"]! } : {}) } }];
    }
    if (this.ctx.direction === "outbound") {
      if (type === "invite") {
        [this.dsip, this.sip] = ["inviting", "calling"];
        return [{ sip: "INVITE" }];
      }
      if (type === "cancel") {
        this.dsip = "ended";
        return [{ sip: "CANCEL" }];
      }
    } else {
      if (type === "progress") {
        this.dsip = "alerting";
        return m["status"] === "ringing" ? [{ sip: { response: 180 } }] : [];
      }
      if (type === "answer") {
        // G§3.2: a screening answer makes the SIP leg sendonly toward the PSTN
        [this.dsip, this.sip, this.answered] = ["active", "confirmed", true];
        return [{ sip: { response: 200, direction: m["answered_by"] === "screening" ? "sendonly" : "sendrecv" } }, { media: "bridge" }];
      }
      if (type === "reject") {
        [this.dsip, this.sip] = ["ended", "terminated"];
        const { status, ...rest } = reasonOutbound(m["reason"] as string, "pre-answer");
        return [{ sip: { response: status!, ...rest } }];
      }
    }
    if (type === "update") return [{ sip: { request: "re-INVITE", direction: m["direction"]! } }];
    if (type === "bye") {
      const { method, ...rest } = reasonOutbound(m["reason"] as string, "active");
      [this.dsip, this.sip] = ["ended", "terminated"];
      return [{ sip: { request: method!, ...rest } }, { media: "release" }];
    }
    throw new Error(`gateway: unexpected DSIP ${type}`);
  }

  private fromSip(s: JsonObject): Json[] {
    if (s["event"] === "dtmf") return this.up ? [this.dtmfToDsip(s)] : [{ ignore: "sip dtmf outside the established call" }];
    if ("status" in s) return this.sipResponse(s);
    switch (s["request"]) {
      case "INVITE": {
        // G§3.2: the DSIP invite carries the G§5 tel claim; the caller is a claim, the gateway is the signer
        const { claim, trust_basis } = telClaim(s as never);
        [this.dsip, this.sip] = ["offered", "early"];
        return [{ dsip: { local: "place_call", claims: [claim!], trust_basis: trust_basis! } }, { sip: { response: 100 } }];
      }
      case "ACK":
        return [];
      case "CANCEL":
        [this.dsip, this.sip] = ["ended", "terminated"];
        return [{ sip: { response: 200 } }, { dsip: { local: "cancel" } }, { sip: { response: 487 } }];
      case "BYE": {
        const { reason } = reasonInbound({ q850: s["q850"] as number | undefined, phase: "active" });
        [this.dsip, this.sip] = ["ended", "terminated"];
        return [{ sip: { response: 200 } }, { dsip: { local: "hangup", reason } }, { media: "release" }];
      }
      case "REFER":
        return [{ sip: { response: 603 } }]; // G§3.2: transfer is out of scope this version
      case "re-INVITE":
        return [{ dsip: { local: "update", direction: s["direction"]! } }];
      case "INFO":
        // G§9: a SIP INFO is always answered 200, carried or not
        return [{ sip: { response: 200 } }, this.up ? this.dtmfToDsip(s) : { ignore: "sip dtmf outside the established call" }];
      default:
        throw new Error(`gateway: unexpected SIP request ${String(s["request"])}`);
    }
  }

  private sipResponse(s: JsonObject): Json[] {
    const status = s["status"] as number;
    if (status === 100) return [];
    if (status < 200) {
      const out: Json[] = [];
      if (this.dsip === "inviting") out.push({ dsip: { local: "alert" } });
      this.sip = "early";
      if (this.dsip === "inviting") this.dsip = "proceeding";
      // G§8: early media answers the DSIP leg unless the trunk policy is `never`
      if (status === 183 && s["sdp"] === true && (this.ctx.early_media ?? "auto") !== "never" && !this.answered) {
        [this.dsip, this.answered] = ["active", true];
        out.push({ dsip: { local: "accept", answered_by: "gateway" } }, { media: "bridge" });
      }
      return out;
    }
    if (status < 300) {
      this.sip = "confirmed";
      if (this.dsip === "ended") {
        // G§3.1: a 2xx crossing our CANCEL is ACKed, then torn down (§12.5 rule 3 on the SIP leg)
        this.sip = "terminated";
        const { method, ...rest } = reasonOutbound("session.cancelled", "active");
        return [{ sip: "ACK" }, { sip: { request: method!, ...rest } }];
      }
      if (this.answered) return [{ sip: "ACK" }];
      [this.dsip, this.answered] = ["active", true];
      return [{ sip: "ACK" }, { dsip: { local: "accept", answered_by: "gateway" } }, { media: "bridge" }];
    }
    this.sip = "terminated";
    if (this.dsip === "ended") return []; // e.g. the 487 to our own CANCEL
    const mapped = reasonInbound({ sip_status: status, q850: s["q850"] as number | undefined, phase: this.answered ? "active" : "pre-answer" });
    this.dsip = "ended";
    const local = this.answered ? "hangup" : "auto_reject";
    return [{ dsip: { local, reason: mapped.reason, ...(mapped.detail !== undefined ? { detail: mapped.detail } : {}) } }];
  }
}
