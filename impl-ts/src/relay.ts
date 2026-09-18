/**
 * The forking relay: per-leg attempt tracking, attempt outcomes, store-and-forward, and the
 * introduction inbox.
 *
 * Spec: §12.7 (forking rules 3 and 6), §13.2 (bindings), §13.3 (offline delivery boundary),
 * §19.4 (introductions to unknown recipients are accepted without a routing response).
 *
 * The relay routes verified envelopes; it never reads media and never answers for anyone.
 */
import type { Json, JsonObject } from "./did.js";

type LegState = "delivered" | "answered" | "rejected" | "expired" | "cancelled";

interface Attempt {
  from: string;
  to: string;
  expires?: number;
  legs: Map<string, LegState>;
  outcome: null | "answered" | "rejected" | "cancelled" | "no-response";
  /** Leg rejections in arrival order, for the attempt outcome (§12.7 rule 6). */
  rejections: { leg: string; reason: string }[];
}

interface Queued {
  to: string;
  msg: JsonObject;
  until: number;
}

/** Spec: §12.7 rule 6 — most informative first; tokens outside this order rank by arrival. */
const INFORMATIVE = ["user.declined", "user.no-answer", "endpoint.busy", "endpoint.unavailable"];

/** Trace context for a relay (vectors README, kind `state`). */
export interface RelayContext {
  start: number;
  /** Longest a queued envelope is kept, seconds (§13.3). */
  offline_retention_s?: number;
}

/** A store-and-forward, forking relay. */
export class Relay {
  private now: number;
  private emit: Json[] = [];
  private readonly bound = new Map<string, string>(); // device → identity, in binding order
  private readonly known = new Set<string>(); // identities and devices that have ever bound here
  private readonly attempts = new Map<string, Attempt>();
  private queue: Queued[] = [];

  constructor(private readonly ctx: RelayContext) {
    this.now = ctx.start;
  }

  /** Apply one trace event; returns the ordered emissions. */
  step(e: JsonObject): Json[] {
    this.emit = [];
    if ("advance" in e) {
      this.now += e["advance"] as number;
      this.expireQueue();
    } else if ("recv" in e) {
      this.recv(e["recv"] as JsonObject);
    } else if (e["relay"] === "invite") {
      this.fork(e["session"] as string, e["from"] as string, e["to"] as string, e["legs"] as string[], undefined, false);
    } else if (e["relay"] === "leg_expired") {
      this.legEnded(e["session"] as string, e["leg"] as string, "expired");
    } else if (e["relay"] === "bind") {
      this.bind(e["device"] as string, e["identity"] as string);
    } else if (e["relay"] === "unbind") {
      this.bound.delete(e["device"] as string);
    } else {
      throw new Error(`unknown relay event ${JSON.stringify(e)}`);
    }
    return this.emit;
  }

  /** The snapshot members a step's `expect` names. */
  snapshot(expect: JsonObject): JsonObject {
    const out: JsonObject = {};
    if ("attempts" in expect) {
      const attempts: JsonObject = {};
      for (const id of Object.keys(expect["attempts"] as JsonObject)) {
        const a = this.attempts.get(id);
        if (a) attempts[id] = { legs: Object.fromEntries(a.legs), outcome: a.outcome };
      }
      out["attempts"] = attempts;
    }
    if ("inbox" in expect) {
      const inbox: Record<string, number> = {};
      for (const q of this.queue) inbox[q.to] = (inbox[q.to] ?? 0) + 1;
      out["inbox"] = inbox;
    }
    return out;
  }

  private devicesOf(identity: string): string[] {
    return [...this.bound.entries()].filter(([, id]) => id === identity).map(([device]) => device);
  }

  private fork(session: string, from: string, to: string, legs: string[], expires: number | undefined, withId: boolean): void {
    const attempt: Attempt = { from, to, expires, legs: new Map(), outcome: null, rejections: [] };
    this.attempts.set(session, attempt);
    for (const leg of legs) this.addLeg(session, attempt, leg, withId);
  }

  private addLeg(session: string, attempt: Attempt, leg: string, withId: boolean): void {
    attempt.legs.set(leg, "delivered");
    this.emit.push({ deliver: { leg, type: "invite", ...(withId ? { id: session } : {}) } });
  }

  /** §13.3: hold an envelope for a recipient that is not connected, until it expires or retention runs out. */
  private hold(to: string, msg: JsonObject): void {
    const retention = this.now + (this.ctx.offline_retention_s ?? Infinity);
    const until = Math.min(typeof msg["expires_at"] === "number" ? msg["expires_at"] : Infinity, retention);
    this.queue.push({ to, msg, until });
    this.emit.push({ queue: { to, type: msg["type"]! } });
  }

  private expireQueue(): void {
    this.queue = this.queue.filter((q) => {
      if (q.until > this.now) return true;
      // §13.3: queued envelopes expire silently; the initiator's timers are the backstop
      this.emit.push({ dequeue: { to: q.to, type: q.msg["type"]!, why: "expired" } });
      return false;
    });
  }

  private bind(device: string, identity: string): void {
    this.bound.set(device, identity);
    this.known.add(device).add(identity);
    // Flush what was held for this identity or this device, in order.
    const mine = this.queue.filter((q) => q.to === identity || q.to === device);
    this.queue = this.queue.filter((q) => !mine.includes(q));
    const flushed = new Set<string>();
    for (const { msg } of mine) {
      const id = msg["id"] as string;
      if (msg["type"] === "invite") {
        flushed.add(id);
        this.fork(id, msg["from"] as string, identity, [device], msg["expires_at"] as number | undefined, true);
      } else {
        this.emit.push({ deliver: { leg: device, type: msg["type"]!, id } });
      }
    }
    // §12.7 rule 3: a device that binds while an attempt is live becomes a leg, if the invite is unexpired
    for (const [session, a] of this.attempts) {
      const live = a.outcome === null && (a.expires === undefined || a.expires >= this.now);
      if (live && a.to === identity && !a.legs.has(device) && !flushed.has(session)) this.addLeg(session, a, device, true);
    }
  }

  private recv(m: JsonObject): void {
    const type = m["type"] as string;
    const to = m["to"] as string | undefined;
    if (type === "invite") {
      const devices = this.devicesOf(to!);
      if (devices.length) return this.fork(m["id"] as string, m["from"] as string, to!, devices, m["expires_at"] as number | undefined, false);
      // §13.2/§13.3: unknown recipient = never bound here; a known one is offline and gets store-and-forward
      if (this.known.has(to!)) return this.hold(to!, m);
      return void this.emit.push({ send: { type: "error", to: m["from"]!, reason: "transport.unknown-recipient", in_reply_to: m["id"]! } });
    }
    if (type === "introduction") {
      // §19.4: accepted without a routing response whether or not the recipient is known
      const devices = this.devicesOf(to!);
      if (!devices.length) return this.hold(to!, m);
      for (const leg of devices) this.emit.push({ deliver: { leg, type } });
      return;
    }
    const session = m["session"] as string;
    const a = this.attempts.get(session);
    const from = m["from"] as string;
    if (a && type === "cancel" && from === a.from) return this.cancel(session, a, m);
    if (type === "cancel" && this.queue.some((q) => q.msg["type"] === "invite" && q.msg["id"] === session)) {
      // §13.3: a withdrawn invite that was never delivered is dropped from the queue, and so is its cancel
      this.queue = this.queue.filter((q) => {
        if (q.msg["id"] !== session) return true;
        this.emit.push({ dequeue: { to: q.to, type: "invite", why: "cancelled" } });
        return false;
      });
      return;
    }
    if (a && a.legs.has(from) && !("in_reply_to" in m) && ["progress", "answer", "reject"].includes(type)) {
      return this.fromLeg(session, a, m);
    }
    if (to === undefined) return void this.emit.push({ drop: "unroutable" });
    // Post-answer traffic is not attempt-scoped: routed by `to`.
    if (this.bound.has(to)) return void this.emit.push({ deliver: { leg: to, type, id: m["id"]! } });
    this.hold(to, m);
  }

  private fromLeg(session: string, a: Attempt, m: JsonObject): void {
    const type = m["type"] as string;
    const leg = m["from"] as string;
    const state = a.legs.get(leg)!;
    if (type === "answer") {
      if (state !== "delivered") return void this.emit.push({ drop: "leg-terminated" });
      a.legs.set(leg, "answered");
      a.outcome ??= "answered";
      // A late answer is still forwarded: only the initiator can end that leg (§12.7 rule 4).
      return void this.emit.push({ forward: { type, from: leg } });
    }
    if (state !== "delivered") return void this.emit.push({ drop: "leg-terminated" });
    if (type === "progress") return void this.emit.push({ forward: { type, status: m["status"]!, from: leg } });
    a.rejections.push({ leg, reason: m["reason"] as string });
    this.legEnded(session, leg, "rejected");
  }

  /** §12.7 rule 6: when the last outstanding leg ends without an answer, signal the attempt outcome. */
  private legEnded(session: string, leg: string, state: LegState): void {
    const a = this.attempts.get(session);
    if (!a || a.legs.get(leg) !== "delivered") return;
    a.legs.set(leg, state);
    if (a.outcome !== null || [...a.legs.values()].some((s) => s === "delivered")) return;
    const rank = (r: string): number => (INFORMATIVE.includes(r) ? INFORMATIVE.indexOf(r) : INFORMATIVE.length);
    const best = [...a.rejections].sort((x, y) => rank(x.reason) - rank(y.reason))[0];
    if (best) {
      a.outcome = "rejected";
      return void this.emit.push({ forward: { type: "reject", reason: best.reason, from: best.leg } });
    }
    // spec-gap 76: no leg said anything, so there is no reject to forward and the relay may not invent
    // one in a leg's name (§15.2) — it speaks for itself, in its own signed error
    a.outcome = "no-response";
    this.emit.push({ send: { type: "error", to: a.from, session, reason: "transport.no-response", in_reply_to: session } });
  }

  /** §12.7 rule 3: deliver the cancel per-leg to every leg that has not terminated. */
  private cancel(session: string, a: Attempt, m: JsonObject): void {
    const target = m["to"] as string | undefined;
    for (const [leg, state] of a.legs) {
      if (state !== "delivered" || (target !== undefined && target !== a.to && target !== leg)) continue;
      a.legs.set(leg, "cancelled");
      this.emit.push({ deliver: { leg, type: "cancel", reason: m["reason"]! } });
    }
    // The initiator withdrew before any answer: the attempt is over.
    if (a.outcome === null && ![...a.legs.values()].includes("delivered")) a.outcome = "cancelled";
  }
}
