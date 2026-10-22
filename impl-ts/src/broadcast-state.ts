/**
 * The two stateful sides of the subscription protocol: the authority that holds publication
 * records and presence for its targets, and the subscriber.
 *
 * Spec: §9.3 (subscribe/notify, soft state, seq-ordered notifies, anti-enumeration), §22.1
 * (publication records: publisher binding, stream-id namespace, newer ULID replaces), §22.3
 * (provenance statements attach to a record and never replace its publisher); Presence Profile P§3 (a device's
 * signed record published to its authority: refusals in order, the body with `records`, expiry, the unbind grace,
 * notifying on body changes), P§4 (`seq` per `(subject, device)`), P§8 (lifetime bounds, T-Presence-Grace, the
 * publish interval).
 */
import type { Json, JsonObject } from "./did.js";
import { byCodePoint } from "./recording/recording.js";

interface Publication {
  id: string;
  publisher: string;
  state: string;
  variants: string[];
  expires?: number;
  provenance: string[];
}

/** A device's current presence record, as the authority holds it. Spec: P§3 */
interface PresenceRecord {
  id: string;
  state: string;
  seq: number;
  expires_at: number;
  /** Set while the device is unbound: when its grace runs out. Spec: P§3, P§8 */
  grace_until?: number;
}

/** Spec: P§8 — T-Presence-Grace default, seconds. */
export const PRESENCE_GRACE_DEFAULT_S = 60;
/** Spec: P§8 — record lifetime bounds (`expires_at − issued_at`), seconds. */
export const PRESENCE_LIFETIME_MIN_S = 60;
/** Spec: P§8 — record lifetime upper bound, seconds. */
export const PRESENCE_LIFETIME_MAX_S = 3600;
/** Spec: P§8 — least interval between two accepted records of one device, seconds. */
export const PRESENCE_PUBLISH_INTERVAL_S = 5;

interface Subscription {
  id: string;
  device: string;
  subscriber: string;
  target: string;
  events: string[];
  seq: number;
  expires_at: number;
}

/** Trace context shared by both components. */
export interface BroadcastContext {
  start: number;
  identities?: Record<string, string>;
  /** T-Presence-Grace, seconds (default 60). Spec: P§8 */
  presence_grace?: number;
}

/** A target's authority: its relay or domain endpoint. */
export class Authority {
  private now: number;
  private emit: Json[] = [];
  private readonly policy = new Map<string, { mode: string; allow: string[] }>();
  private readonly capabilities = new Map<string, string>(); // token → target
  private readonly publications = new Map<string, Publication>();
  private subscriptions: Subscription[] = [];
  private readonly bound = new Map<string, string>(); // device → identity
  private readonly records = new Map<string, Map<string, PresenceRecord>>(); // subject → device → record
  private readonly lastAccepted = new Map<string, number>(); // device → when its last record was accepted

  constructor(private readonly ctx: BroadcastContext) {
    this.now = ctx.start;
  }

  /** Apply one trace event; returns the ordered emissions. */
  step(e: JsonObject): Json[] {
    this.emit = [];
    if ("advance" in e) this.advance(e["advance"] as number);
    else if ("recv" in e) this.recv(e["recv"] as JsonObject);
    else if (e["local"] === "policy") this.policy.set(e["target"] as string, { mode: e["mode"] as string, allow: (e["allow"] ?? []) as string[] });
    else if (e["local"] === "issue_capability") this.capabilities.set(e["token"] as string, e["target"] as string);
    else if (e["relay"] === "bind" || e["relay"] === "unbind") this.bindingChange(e);
    else throw new Error(`unknown authority event ${JSON.stringify(e)}`);
    return this.emit;
  }

  /** The snapshot members a step's `expect` names, in full. */
  snapshot(expect: JsonObject): JsonObject {
    const out: JsonObject = {};
    if ("publications" in expect) {
      out["publications"] = Object.fromEntries(
        [...this.publications].map(([stream, p]) => [stream, { publication: p.id, publisher: p.publisher, state: p.state }]),
      );
    }
    if ("subscriptions" in expect) {
      out["subscriptions"] = Object.fromEntries(
        this.subscriptions.map((s) => [s.id, { subscriber: s.subscriber, target: s.target, events: s.events, seq: s.seq, expires_at: s.expires_at }]),
      );
    }
    if ("presence" in expect) {
      const presence: JsonObject = {};
      for (const [subject, held] of this.records) {
        if (held.size === 0) continue;
        presence[subject] = Object.fromEntries(
          [...held].map(([device, r]) => [device, {
            seq: r.seq, state: r.state, expires_at: r.expires_at,
            ...(r.grace_until !== undefined ? { grace_until: r.grace_until } : {}),
          }]),
        );
      }
      out["presence"] = presence;
    }
    return out;
  }

  private identityOf(did: string): string {
    return this.ctx.identities?.[did] ?? did;
  }

  private body(target: string, event: string): JsonObject {
    if (event === "presence") return this.presenceBody(target);
    const p = this.publications.get(target)!;
    return { event, state: p.state, publication: p.id, ...(p.provenance.length ? { provenance: p.provenance } : {}) };
  }

  /** §9.3: notifies are seq-ordered per subscription. */
  private notify(s: Subscription, event: string, terminal?: string): void {
    s.seq += 1;
    this.emit.push({
      send: {
        type: "notify", to: s.device, subscription: s.id, seq: s.seq,
        state: terminal ? "terminated" : "active", ...(terminal ? { reason: terminal } : {}),
        body: this.body(s.target, event),
      },
    });
  }

  /**
   * The presence body for a subject. Spec: §9.3, P§3 — the state is the authority's assertion over the
   * subject's bound devices that hold no record; `records`, ordered by `device`, when any is held.
   * Impl: `device` order is code-point order of the DID strings; a record is carried as the vectors README's
   * `{id, device, state, seq, expires_at}` summary of the signed envelope.
   */
  private presenceBody(subject: string): JsonObject {
    const held = this.records.get(subject) ?? new Map<string, PresenceRecord>();
    const asserted = [...this.bound].some(([device, identity]) => identity === subject && !held.has(device));
    const body: JsonObject = { event: "presence", state: asserted ? "available" : "offline" };
    if (held.size > 0) {
      body["records"] = [...held.keys()].sort(byCodePoint).map((device) => {
        const r = held.get(device)!;
        return { id: r.id, device, state: r.state, seq: r.seq, expires_at: r.expires_at };
      });
    }
    return body;
  }

  /** The presence bodies of every subject, before an event that may change them. */
  private presenceBodies(): Map<string, string> {
    const subjects = new Set<string>([...this.bound.values(), ...this.records.keys()]);
    for (const s of this.subscriptions) if (s.events.includes("presence")) subjects.add(s.target);
    return new Map([...subjects].map((subject) => [subject, JSON.stringify(this.presenceBody(subject))]));
  }

  /** Spec: P§3 — a subscription is notified when an event changes its body; subjects in order. */
  private notifyChanged(before: Map<string, string>): void {
    for (const subject of [...before.keys()].sort(byCodePoint)) {
      if (before.get(subject) !== JSON.stringify(this.presenceBody(subject))) this.notifyAll(subject, "presence");
    }
  }

  private notifyAll(target: string, event: string): void {
    for (const s of this.subscriptions) if (s.target === target && s.events.includes(event)) this.notify(s, event);
  }

  private setState(stream: string, p: Publication, state: string): void {
    p.state = state;
    this.emit.push({ publication: { stream, state } });
    this.notifyAll(stream, "publication");
  }

  private advance(seconds: number): void {
    this.now += seconds;
    for (const [stream, p] of this.publications) {
      // §8.3 / §22.1: a record past expiration is invalid — subscribers are told
      if (p.state === "live" && p.expires !== undefined && p.expires <= this.now) this.setState(stream, p, "expired");
    }
    for (const s of [...this.subscriptions]) {
      if (s.expires_at > this.now) continue;
      // §9.3: subscriptions are soft state; a lapsed one ends with a terminal notify
      this.notify(s, s.events[0]!, "session.expired");
      this.subscriptions = this.subscriptions.filter((x) => x !== s);
    }
    // P§3: a record past its expires_at, or whose unbind grace has run out, is dropped and its seq
    // forgotten; each subject that lost one is notified once, subjects in order.
    const before = this.presenceBodies();
    for (const held of this.records.values()) {
      for (const [device, r] of held) {
        if (r.expires_at <= this.now || (r.grace_until !== undefined && r.grace_until <= this.now)) held.delete(device);
      }
    }
    this.notifyChanged(before);
  }

  /**
   * A device binds to or unbinds from this relay, the source of the authority's assertion (§9.3).
   * Spec: P§3 — an unbound device keeps its record for T-Presence-Grace (0 drops it at the unbind), counted
   * from the first unbind; a bind within the grace keeps it as if the device had never left. Subscribers hear only a changed body.
   */
  private bindingChange(e: JsonObject): void {
    const identity = e["identity"] as string;
    const device = e["device"] as string;
    const before = this.presenceBodies();
    const record = this.records.get(identity)?.get(device);
    if (e["relay"] === "bind") {
      this.bound.set(device, identity);
      if (record) delete record.grace_until;
    } else {
      this.bound.delete(device);
      // P§3: the grace runs from the first unbind; a further unbind while it runs changes nothing.
      if (record && record.grace_until === undefined) {
        const grace = this.ctx.presence_grace ?? PRESENCE_GRACE_DEFAULT_S;
        if (grace === 0) this.records.get(identity)!.delete(device);
        else record.grace_until = this.now + grace;
      }
    }
    this.notifyChanged(before);
  }

  /**
   * A device publishes its record. Spec: P§3 — refused with `error`, the first that applies:
   * `presence.signer-mismatch` → `presence.lifetime` → `presence.stale` → `policy.rate-limited`; otherwise
   * it replaces the device's record, unacknowledged, and every subscription to the subject is notified.
   * Spec: P§3 rule 4 — the publish interval runs from the device's last accepted record, whether or not that
   * record is still held.
   */
  private presence(m: JsonObject): void {
    const from = m["from"] as string;
    const subject = m["subject"] as string;
    const refuse = (reason: string, extra: JsonObject = {}): void =>
      void this.emit.push({ send: { type: "error", to: from, in_reply_to: m["id"]!, reason, ...extra } });
    // P§3 rule 1: the record names its signing device, for the identity that device is delegated by
    // (`context.identities`, the identity its delegation names).
    if (typeof m["device"] !== "string" || m["device"] !== from || subject !== this.identityOf(from)) {
      return refuse("presence.signer-mismatch");
    }
    // P§3 rule 2, P§8: lifetime 60–3,600 s.
    const lifetime = (m["expires_at"] as number) - (m["issued_at"] as number);
    if (lifetime < PRESENCE_LIFETIME_MIN_S || lifetime > PRESENCE_LIFETIME_MAX_S) return refuse("presence.lifetime");
    // P§3 rule 3, P§4: seq is ordered per (subject, device).
    const held = this.records.get(subject) ?? new Map<string, PresenceRecord>();
    const current = held.get(from);
    if (current && current.seq >= (m["seq"] as number)) return refuse("presence.stale");
    // P§3 rule 4, P§8: at most one accepted record per device every 5 s; retry_after is the whole seconds left.
    const last = this.lastAccepted.get(from);
    if (last !== undefined && this.now - last < PRESENCE_PUBLISH_INTERVAL_S) {
      return refuse("policy.rate-limited", { retry_after: PRESENCE_PUBLISH_INTERVAL_S - (this.now - last) });
    }
    const record: PresenceRecord = {
      id: m["id"] as string, state: m["state"] as string, seq: m["seq"] as number, expires_at: m["expires_at"] as number,
    };
    // P§3: a record accepted from a device in its grace keeps the grace running.
    if (current?.grace_until !== undefined && !this.bound.has(from)) record.grace_until = current.grace_until;
    held.set(from, record);
    this.records.set(subject, held);
    this.lastAccepted.set(from, this.now);
    this.notifyAll(subject, "presence");
  }

  private recv(m: JsonObject): void {
    const sender = this.identityOf(m["from"] as string);
    switch (m["type"]) {
      case "publish": {
        const stream = m["stream_id"] as string;
        // §22.1: `publisher` MUST equal the verified identity; stream ids live under the publisher's DID
        if (m["publisher"] !== sender) return void this.emit.push({ drop: "publisher-mismatch" });
        if (!stream.startsWith(`${sender}:`)) return void this.emit.push({ drop: "stream-id-namespace" });
        const current = this.publications.get(stream);
        if (current && (m["id"] as string) <= current.id) return void this.emit.push({ drop: "stale-publication" });
        const record: Publication = {
          id: m["id"] as string, publisher: sender, state: "", provenance: [],
          variants: ((m["variants"] ?? []) as JsonObject[]).map((v) => v["id"] as string),
          expires: m["expires_at"] as number | undefined,
        };
        this.publications.set(stream, record);
        return this.setState(stream, record, m["state"] as string);
      }
      case "unpublish": {
        const stream = m["stream_id"] as string;
        const p = this.publications.get(stream);
        if (m["publisher"] !== sender || (p && p.publisher !== sender)) return void this.emit.push({ drop: "publisher-mismatch" });
        if (!p || p.id !== m["publication"]) return void this.emit.push({ drop: "unknown-publication" });
        return this.setState(stream, p, "withdrawn");
      }
      case "provenance": {
        const stream = m["original_stream"] as string;
        const found = [...this.publications].find(([, p]) => p.id === m["original_publication"]);
        if (!found) return void this.emit.push({ drop: "provenance-unknown-publication" });
        const [recordStream, p] = found;
        if (recordStream !== stream) return void this.emit.push({ drop: "provenance-stream-mismatch" });
        if (m["processor"] !== sender) return void this.emit.push({ drop: "provenance-processor-mismatch" });
        // §22.3: `input_variant` MUST be one the publication advertises (the output is the processor's own)
        for (const k of ["input_variant"]) {
          if (k in m && !p.variants.includes(m[k] as string)) return void this.emit.push({ drop: "provenance-variant-unknown" });
        }
        // §22.3: the statement is attached; the publisher stays the publisher
        p.provenance.push(sender);
        this.emit.push({ provenance: { stream, processor: sender } });
        return this.notifyAll(stream, "publication");
      }
      case "subscribe":
        return this.subscribe(m, sender);
      case "presence":
        return this.presence(m);
      default:
        throw new Error(`authority cannot receive ${String(m["type"])}`);
    }
  }

  private subscribe(m: JsonObject, subscriber: string): void {
    const target = m["target"] as string;
    const events = m["events"] as string[];
    const same = (s: Subscription): boolean =>
      s.subscriber === subscriber && s.target === target && JSON.stringify(s.events) === JSON.stringify(events);
    const prior = this.subscriptions.find(same);
    if (m["expires_in"] === 0) {
      // §9.3: `expires_in: 0` terminates a matching subscription
      if (!prior) return void this.emit.push({ drop: "no-matching-subscription" });
      this.subscriptions = this.subscriptions.filter((s) => s !== prior);
      return void this.emit.push({ subscription: { id: prior.id, state: "terminated" } });
    }
    const policy = this.policy.get(target);
    const exists = policy !== undefined && (!events.includes("publication") || this.publications.has(target));
    const authorized =
      policy !== undefined &&
      (policy.mode === "public" || policy.allow.includes(subscriber) || this.capabilities.get(m["capability"] as string) === target);
    if (!exists || !authorized) {
      // §9.3 anti-enumeration: unauthorized and nonexistent get the identical response
      return void this.emit.push({ send: { type: "reject", to: m["from"]!, session: m["id"]!, reason: "policy.blocked" } });
    }
    if (prior) {
      // §9.3: a fresh subscribe for the same target+events replaces the prior subscription
      this.subscriptions = this.subscriptions.filter((s) => s !== prior);
      this.emit.push({ subscription: { id: prior.id, state: "replaced" } });
    }
    const s: Subscription = {
      id: m["id"] as string, device: m["from"] as string, subscriber, target, events, seq: 0,
      expires_at: this.now + (m["expires_in"] as number),
    };
    this.subscriptions.push(s);
    // §9.3: the first notify carries current state
    for (const event of events) this.notify(s, event);
  }
}

interface Held {
  target: string;
  state: "pending" | "active" | "rejected" | "terminated" | "lapsed";
  seq: number;
  expires_at: number;
}

/** The subscribing side. */
export class Subscriber {
  private now: number;
  private emit: Json[] = [];
  private readonly held = new Map<string, Held>();

  constructor(ctx: BroadcastContext) {
    this.now = ctx.start;
  }

  /** Apply one trace event; returns the ordered emissions. */
  step(e: JsonObject): Json[] {
    this.emit = [];
    if ("advance" in e) {
      this.now += e["advance"] as number;
      for (const [id, s] of this.held) {
        // §9.3: soft state — not renewed means lapsed, without waiting to be told
        if ((s.state === "active" || s.state === "pending") && s.expires_at <= this.now) {
          s.state = "lapsed";
          this.emit.push({ ui: "subscription_lapsed", subscription: id });
        }
      }
    } else if (e["local"] === "subscribe") {
      const { id, to, target, events, expires_in } = e;
      this.held.set(id as string, { target: target as string, state: "pending", seq: 0, expires_at: this.now + (expires_in as number) });
      this.emit.push({ send: { type: "subscribe", to: to!, id: id!, target: target!, events: events!, expires_in: expires_in! } });
    } else {
      this.recv(e["recv"] as JsonObject);
    }
    return this.emit;
  }

  /** The snapshot members a step's `expect` names, in full. */
  snapshot(expect: JsonObject): JsonObject {
    if (!("subscriptions" in expect)) return {};
    return {
      subscriptions: Object.fromEntries([...this.held].map(([id, s]) => [id, { target: s.target, state: s.state, seq: s.seq }])),
    };
  }

  private recv(m: JsonObject): void {
    if (m["type"] === "reject") {
      const s = this.held.get(m["session"] as string);
      if (!s) return void this.emit.push({ drop: "unknown-subscription" });
      s.state = "rejected";
      return void this.emit.push({ ui: "subscription_rejected", reason: m["reason"]! });
    }
    const s = this.held.get(m["subscription"] as string);
    if (!s) return void this.emit.push({ drop: "unknown-subscription" });
    // §9.3: a terminated notify is final
    if (s.state === "terminated") return void this.emit.push({ drop: "terminated-subscription" });
    const seq = m["seq"] as number;
    if (seq <= s.seq) return void this.emit.push({ drop: "stale-seq" });
    s.seq = seq;
    if (m["state"] === "terminated") {
      s.state = "terminated";
      return void this.emit.push({ ui: "subscription_terminated", reason: m["reason"] ?? null });
    }
    s.state = "active";
    const body = m["body"] as JsonObject;
    this.emit.push({ ui: "notify", event: body["event"]!, state: body["state"]! });
  }
}
