/**
 * The mailbox service: an identity's store for what arrives while its devices are away.
 *
 * Spec: M§4.4 (modes and retention), M§5.2 (forwarding, spec-gap 45), M§5.4 (sync, cursors, acks),
 * M§5.5 (KeyPackages), M§5.7 (configuration, revocation — spec-gap 57), M§6.6 (group registration,
 * redelivery and restarts — spec-gap 59), M§7.4 (following a hub move — spec-gaps 60 and 71), M§9.4
 * (`mailbox.hub-unreachable`, spec-gap 72), M§11.2 (ephemeral is pushed, never stored), M§12.2
 * (archive: first wins), M§14.1 / §19.4 (introductions and grants held for the owner — spec-gap 54),
 * M§14.2 (authorization of welcomes and KeyPackage fetches — spec-gap 46).
 *
 * Envelope verification has already happened; a trace presents grants and origins as verified facts.
 */
import type { Json, JsonObject } from "../did.js";
import type { Machine, Step } from "./device.js";

/** Spec: M§14.2 — `origin` is within 300 s of the hub deposit. */
const ORIGIN_SKEW_S = 300;
/** Spec: M§7.4 (spec-gap 71) — RECOMMENDED; the mailbox's own choice. */
const HANDOVER_WAIT_S = 300;
/** Spec: M§5.5 — one-time KeyPackages kept per device. */
const MAX_KEY_PACKAGES = 100;
const MODES = ["sync", "queue"];

interface Item {
  cursor: string;
  class: string;
  group?: string;
  seq?: number;
  until?: number;
  depositor?: string;
  /** A welcome's MLS bytes, for recognising the hub's retry of it (spec-gap 66). */
  digest?: string;
}

interface Registration {
  hub: string;
  state: "pending" | "joined";
  since: number;
  count: number;
  high: number;
  seen: Map<number, string>;
  previous?: { hub: string; handover_seq: number; since: number; released: boolean };
}

interface Grant {
  id: string;
  from: string;
  to: string;
  scope: string[];
  valid_until: number;
}

/** Trace context for a mailbox. */
export interface MailboxContext {
  mailbox: string;
  owner: string;
  serves: string[];
  devices: string[];
  now: number;
  mode: string;
  admit: string;
  pending_group_ttl: number;
  pending_group_max_items: number;
  groups: Record<string, { hub: string; state: "pending" | "joined" }>;
  key_packages: Record<string, { one_time: number; last_resort: boolean }>;
  intro_limit?: number;
  intro_window?: number;
  inbox_cap?: number;
  handover_wait?: number;
}

/** One owner's mailbox. */
export class Mailbox implements Machine {
  private now: number;
  private mode: string;
  private counter = 0;
  private items: Item[] = [];
  private readonly groups = new Map<string, Registration>();
  private readonly keyPackages: Record<string, { one_time: number; last_resort: boolean }>;
  private devices: string[];
  private live = new Set<string>();
  private readonly acks = new Map<string, string>();
  private readonly archive = new Map<string, string>();
  private readonly revokedGrants = new Set<string>();
  /** Introductions the owner sent and has not yet been answered for (mailbox-config `introductions_sent`). */
  private readonly introductionsSent = new Set<string>();
  private readonly introTimes: { sender: string; recipient: string; at: number }[] = [];
  private emit: Json[] = [];

  constructor(private readonly ctx: MailboxContext) {
    this.now = ctx.now;
    this.mode = ctx.mode;
    this.devices = [...ctx.devices];
    this.keyPackages = {};
    for (const [d, k] of Object.entries(ctx.key_packages)) this.keyPackages[d] = { one_time: k.one_time, last_resort: k.last_resort === true };
    for (const [g, r] of Object.entries(ctx.groups)) {
      this.groups.set(g, { hub: r.hub, state: r.state, since: ctx.now, count: 0, high: 0, seen: new Map() });
    }
  }

  step(e: JsonObject): Step {
    this.emit = [];
    const [kind] = Object.keys(e) as [string];
    const body = e[kind] as JsonObject;
    switch (kind) {
      case "advance": this.advance(e["advance"] as number); break;
      case "restart": this.live = new Set(); break; // spec-gap 59: everything answered from is durable; live bindings are not
      case "unbind": this.live.delete(body["device"] as string); break;
      case "hub_deposit": this.hubDeposit(body); break;
      case "welcome": this.welcome(body); break;
      case "first_contact": this.firstContact(body); break;
      case "sync": this.sync(body); break;
      case "config": this.config(body); break;
      case "archive": this.archiveDeposit(body); break;
      case "kp_upload": this.kpUpload(body); break;
      case "kp_fetch": this.kpFetch(body); break;
      case "forward": this.forward(body); break;
      case "forward_failed":
        // M§9.4 (spec-gap 72): the device keeps the deposit pending
        this.error(body["device"] as string, body["id"] as string, "mailbox.hub-unreachable");
        break;
      default: throw new Error(`unknown mailbox event ${kind}`);
    }
    const groups: JsonObject = {};
    for (const [g, r] of this.groups) groups[g] = r.state;
    return { emit: this.emit, state: { items: this.items.map((i) => i.cursor), groups, key_packages: structuredClone(this.keyPackages) as unknown as JsonObject } };
  }

  // ---- helpers

  private error(to: string, inReplyTo: string, reason: string, extra: JsonObject = {}): void {
    this.emit.push({ error: { to, in_reply_to: inReplyTo, reason, ...extra } });
  }

  private accepted(to: string, inReplyTo: string, extra: JsonObject = {}): void {
    this.emit.push({ accepted: { to, in_reply_to: inReplyTo, ...extra } });
  }

  /** Cursors are `c:` + 16 lowercase hex digits (Impl, vectors README). */
  private store(item: Omit<Item, "cursor">): string {
    const cursor = `c:${(++this.counter).toString(16).padStart(16, "0")}`;
    this.items.push({ cursor, ...item });
    return cursor;
  }

  /** M§5.4 `live`: push a new item to the bound devices, in device order, other than the one that deposited it. */
  private push(cursor: string, except?: string): void {
    for (const device of [...this.devices].sort()) if (this.live.has(device) && device !== except) this.emit.push({ push: { to: device, cursor } });
  }

  private advance(seconds: number): void {
    this.now += seconds;
    // held introductions and grants are kept only until their envelope expires
    this.items = this.items.filter((i) => i.until === undefined || this.now <= i.until);
    for (const [g, r] of this.groups) {
      // M§6.6: an unconfirmed pending group is dropped, with its items, after pending_group_ttl — the hub deposits it
      // admitted; an archive record that references the group is the owner's history (M§12.2), kept whatever the
      // group's registration, so it stays
      if (r.state === "pending" && this.now - r.since > this.ctx.pending_group_ttl) {
        this.groups.delete(g);
        this.items = this.items.filter((i) => i.group !== g || i.class === "archive");
      }
    }
  }

  // ---- M§6.6 / M§7.4 hub fan-out

  private hubDeposit(d: JsonObject): void {
    const [id, from, group, cls] = [d["id"] as string, d["from"] as string, d["group"] as string, d["class"] as string];
    const r = this.groups.get(group);
    if (!r) return this.error(from, id, "mailbox.unknown-group");
    const seq = d["seq"] as number | null;
    const prev = r.previous;
    if (from !== r.hub) {
      // M§7.4: the old hub is still admitted through handover_seq, so its queue drains
      if (!prev || from !== prev.hub || seq === null || seq > prev.handover_seq) return this.error(from, id, "mailbox.unknown-group");
    } else if (prev) {
      if (!prev.released) {
        const missing = this.missing(r, prev.handover_seq);
        if (missing.length > 0) {
          // held off until the old hub's items are stored, for at most handover_wait (spec-gap 71)
          if (this.now - prev.since < (this.ctx.handover_wait ?? HANDOVER_WAIT_S)) return this.error(from, id, "mailbox.unknown-group");
          this.emit.push({ handover_expired: { group, hub: prev.hub, missing } });
          // only an expired wait makes the old hub's later items below the highest stored fills rather than
          // redeliveries; a move with nothing missing leaves the redelivery rule as it is (spec-gap 93)
          prev.released = true;
        }
      }
      // the new hub's numbering continues past handover_seq, or it is a wrong handover
      if (seq !== null && seq <= prev.handover_seq) return this.error(from, id, "policy.blocked");
    }
    if (cls === "ephemeral") {
      // M§11.2: pushed to bound devices, never stored, dropped at the originating expires_at
      if (typeof d["expires_at"] === "number" && d["expires_at"] < this.now) return;
      for (const device of [...this.devices].sort()) if (this.live.has(device)) this.emit.push({ push: { to: device, class: "ephemeral" } });
      return;
    }
    if (seq !== null) {
      // spec-gap 59: at or below the highest stored is a redelivery — except the old hub's late
      // items after the wait ran out, which fill the gap (spec-gap 71)
      const known = r.seen.get(seq);
      const late = prev?.released === true && from === prev.hub;
      if (known !== undefined || (seq <= r.high && !late)) {
        // the original cursor while the item is still retained — by group and seq, so also across a registration the
        // owner left and made again (spec-gap 92)
        const retained = this.items.find((i) => i.group === group && i.seq === seq && i.class !== "archive")?.cursor;
        return this.accepted(from, id, { ...(retained !== undefined ? { cursor: retained } : {}), duplicate: true });
      }
    }
    if (r.state === "pending" && r.count >= this.ctx.pending_group_max_items) return this.error(from, id, "mailbox.quota-exceeded");
    // a mailbox keeps only the latest GroupInfo per group
    if (cls === "group-info") this.items = this.items.filter((i) => !(i.class === "group-info" && i.group === group));
    const cursor = this.store({ class: cls, group, ...(seq !== null ? { seq } : {}) });
    r.count += 1;
    if (seq !== null) {
      r.seen.set(seq, cursor);
      r.high = Math.max(r.high, seq);
    }
    this.accepted(from, id, { cursor });
    this.push(cursor);
  }

  /** The seqs through `handover` the old hub has not delivered, counted from where this mailbox started. */
  /**
   * What the old hub still owes through `handover_seq`, judged by the highest seq stored: the hub delivers in
   * order (M§6.5 rule 5), so a stored seq says every lower one was delivered before it (spec-gap 95).
   */
  private missing(r: Registration, handover: number): number[] {
    const out: number[] = [];
    for (let s = r.high + 1; s <= handover; s++) out.push(s);
    return out;
  }

  // ---- M§14.2 authorization

  private authorized(requester: string, grant: Grant | null, successorOf?: string): boolean {
    if (this.ctx.admit === "open" || requester === this.ctx.owner) return true;
    if (successorOf !== undefined && this.groups.has(successorOf)) return true; // M§7.5
    return (
      grant !== null && grant.from === this.ctx.owner && grant.to === requester &&
      grant.scope.some((s) => s === "dsip.message" || s === "dsip.invite") &&
      grant.valid_until > this.now && !this.revokedGrants.has(grant.id)
    );
  }

  private welcome(w: JsonObject): void {
    const [id, from, group] = [w["id"] as string, w["from"] as string, w["group"] as string];
    if (!this.ctx.serves.includes(w["recipient"] as string)) return this.error(from, id, "transport.unknown-recipient");
    let adder = w["adder_identity"] as string | undefined;
    if (w["via_hub"] === true) {
      // spec-gap 46: only `origin` — the adder's own signed handshake deposit — names the adder
      const origin = w["origin"] as JsonObject | undefined;
      const fresh = origin && Math.abs((origin["issued_at"] as number) - (w["issued_at"] as number)) <= ORIGIN_SKEW_S;
      if (!origin || origin["group"] !== group || !fresh) return this.error(from, id, "policy.blocked");
      adder = origin["identity"] as string;
    }
    if (!this.authorized(adder!, w["grant"] as Grant | null, w["successor_of"] as string | undefined)) {
      return this.error(from, id, "policy.first-contact-required");
    }
    // spec-gap 66: the same Welcome bytes again are a redelivery; another welcome for the group is a new invitation.
    // Judged among the welcomes still held for that group: one dropped with an expired pending registration is held
    // no more, and the same bytes for another group are not this group's welcome (spec-gap 94).
    const digest = w["digest"] as string | undefined;
    const known = digest !== undefined ? this.items.find((i) => i.class === "welcome" && i.group === group && i.digest === digest) : undefined;
    if (known !== undefined) return this.accepted(from, id, { cursor: known.cursor, duplicate: true });
    const cursor = this.store({ class: "welcome", group, ...(digest !== undefined ? { digest } : {}) });
    if (!this.groups.has(group)) {
      this.groups.set(group, { hub: w["hub"] as string, state: "pending", since: this.now, count: 0, high: 0, seen: new Map() });
    }
    this.accepted(from, id, { cursor });
    this.push(cursor);
  }

  /** Spec: M§14.1 (spec-gap 54) — §19.4's relay rules, applied by the mailbox. */
  private firstContact(f: JsonObject): void {
    const [id, from, sender] = [f["id"] as string, f["from"] as string, f["sender_identity"] as string];
    const window = this.ctx.intro_window ?? 3600;
    const recent = this.introTimes.filter((t) => this.now - t.at < window);
    const limit = this.ctx.intro_limit ?? Infinity;
    // M§14.1 (spec-gap 81): a grant answering an introduction the owner sent is the reply it asked for —
    // not metered, and the entry is consumed: one introduction, one answer
    const solicited = f["kind"] === "grant" && typeof f["session"] === "string" && this.introductionsSent.delete(f["session"]);
    if (!solicited) {
      // rate limits are mandatory, per sender identity and per recipient inbox; an unsolicited grant
      // is an unmetered write into someone's mailbox otherwise, so it takes the introduction budget
      const bySender = recent.filter((t) => t.sender === sender);
      const byInbox = recent.filter((t) => t.recipient === f["recipient"]);
      const over = bySender.length >= limit ? bySender : byInbox.length >= limit ? byInbox : null;
      if (over) return this.error(from, id, "policy.rate-limited", { retry_after: over[0]!.at + window - this.now });
      this.introTimes.push({ sender, recipient: f["recipient"] as string, at: this.now });
    }
    // anti-enumeration: an unserved recipient, or a full inbox, is accepted exactly like a held one, then dropped
    const held = this.items.filter((i) => i.class === "introduction").length;
    if (!this.ctx.serves.includes(f["recipient"] as string) || (f["kind"] === "introduction" && held >= (this.ctx.inbox_cap ?? Infinity))) {
      return this.accepted(from, id);
    }
    const cursor = this.store({ class: f["kind"] as string, until: f["expires_at"] as number });
    this.accepted(from, id, { cursor });
    this.push(cursor);
  }

  // ---- M§5.4 sync

  private sync(s: JsonObject): void {
    const [id, device] = [s["id"] as string, s["device"] as string];
    const since = s["since"] as string | null;
    if (since !== null && !this.known(since)) return this.error(device, id, "mailbox.cursor-invalid");
    if (typeof s["ack_through"] === "string") {
      this.acks.set(device, s["ack_through"]);
      // M§4.4 queue mode: an item is deleted once every registered device has acknowledged it
      if (this.mode === "queue") {
        this.items = this.items.filter((i) => !this.devices.every((d) => (this.acks.get(d) ?? "") >= i.cursor));
      }
    }
    if (s["live"] === true) this.live.add(device);
    const after = this.items.filter((i) => since === null || i.cursor > since);
    const limit = (s["limit"] as number | undefined) ?? after.length;
    const page = after.slice(0, limit);
    this.emit.push({
      items: { to: device, in_reply_to: id, cursors: page.map((i) => i.cursor), next: after.length > page.length ? page.at(-1)!.cursor : null },
    });
  }

  private known(cursor: string): boolean {
    const n = /^c:[0-9a-f]{16}$/.test(cursor) ? parseInt(cursor.slice(2), 16) : NaN;
    return n >= 1 && n <= this.counter;
  }

  // ---- M§5.7 configuration

  private config(c: JsonObject): void {
    const [id, device] = [c["id"] as string, c["device"] as string];
    // nothing is changed by a config naming an unregistered mode
    if ("mode" in c && !MODES.includes(c["mode"] as string)) return this.error(device, id, "mailbox.unsupported-mode");
    if ("mode" in c) this.mode = c["mode"] as string;
    for (const g of (c["groups"] ?? []) as JsonObject[]) {
      const group = g["group"] as string;
      const r = this.groups.get(group);
      if (g["state"] === "left") this.groups.delete(group);
      else if (r) {
        r.state = "joined";
        // M§7.4: the owner's device names the new hub and the moving commit's seq
        if (typeof g["hub"] === "string" && g["hub"] !== r.hub) {
          r.previous = { hub: r.hub, handover_seq: g["handover_seq"] as number, since: this.now, released: false };
          r.hub = g["hub"];
        }
      } else if (typeof g["hub"] === "string") {
        this.groups.set(group, { hub: g["hub"], state: "joined", since: this.now, count: 0, high: 0, seen: new Map() });
      }
    }
    for (const grant of (c["revoked_grants"] ?? []) as string[]) this.revokedGrants.add(grant);
    for (const intro of (c["introductions_sent"] ?? []) as string[]) this.introductionsSent.add(intro);
    this.accepted(device, id);
    for (const revoked of (c["revoked_devices"] ?? []) as string[]) {
      // spec-gap 57: refuse the device from then on, forget its registration and KeyPackages, close its binding
      this.devices = this.devices.filter((d) => d !== revoked);
      delete this.keyPackages[revoked];
      this.acks.delete(revoked);
      this.live.delete(revoked);
      this.emit.push({ close: { device: revoked, reason: "delegation-revoked" } });
    }
  }

  // ---- M§12.2 archive

  private archiveDeposit(a: JsonObject): void {
    const [id, device] = [a["id"] as string, a["device"] as string];
    if (this.mode !== "sync") return this.error(device, id, "mailbox.unsupported-class"); // queue mode keeps no history
    const key = `${String(a["ref_group"])}/${String(a["ref_seq"])}`;
    const first = this.archive.get(key);
    // every device may try; exactly one record is kept
    if (first !== undefined) return this.accepted(device, id, { cursor: first, duplicate: true });
    const cursor = this.store({ class: "archive", group: a["ref_group"] as string, seq: a["ref_seq"] as number });
    this.archive.set(key, cursor);
    this.accepted(device, id, { cursor });
    this.push(cursor, device);
  }

  // ---- M§5.5 KeyPackages

  private kpUpload(u: JsonObject): void {
    const device = u["device"] as string;
    const held = (this.keyPackages[device] ??= { one_time: 0, last_resort: false });
    held.one_time = Math.min(held.one_time + (u["count"] as number), MAX_KEY_PACKAGES);
    if (u["last_resort"] === true) held.last_resort = true;
    this.accepted(device, u["id"] as string);
  }

  private kpFetch(f: JsonObject): void {
    const [id, from] = [f["id"] as string, f["from"] as string];
    if (!this.authorized(f["from_identity"] as string, f["grant"] as Grant | null, f["successor_of"] as string | undefined)) {
      return this.error(from, id, "policy.first-contact-required");
    }
    const devices: Record<string, string> = {};
    for (const [device, held] of Object.entries(this.keyPackages)) {
      // a one-time KeyPackage is consumed; the last resort is reused
      if (held.one_time > 0) {
        held.one_time -= 1;
        devices[device] = "one-time";
      } else if (held.last_resort) devices[device] = "last-resort";
    }
    if (Object.keys(devices).length === 0) return this.error(from, id, "mailbox.no-key-packages");
    this.emit.push({ key_packages: { to: from, in_reply_to: id, devices } });
  }

  // ---- M§5.2 forwarding (spec-gap 45)

  private forward(f: JsonObject): void {
    const [id, device] = [f["id"] as string, f["device"] as string];
    if (f["identity"] !== this.ctx.owner) return this.error(device, id, "policy.blocked"); // not an open relay
    const r = this.groups.get(f["group"] as string);
    // only to the hub registered for the group: a mailbox cannot tell a hub from any other service
    if (!r || r.hub !== f["to"]) return this.error(device, id, "mailbox.unknown-group");
    this.emit.push({ forward: { to: r.hub, id } });
  }
}
