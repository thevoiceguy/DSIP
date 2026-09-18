/**
 * The client's rendering state for one conversation: timeline, receipts, read watermarks, activity —
 * and the receipts and activity it sends itself.
 *
 * Spec: M§8.5 (deduplication, seq order), M§10.2 (delivered: identity-level, decided per batch,
 * collapsed), M§10.3 (read: a monotone watermark, one per 5 s), M§10.4 (played: media only, once),
 * M§10.5 (privacy: an undisclosed read goes to the personal group), M§11.2 (activity lifetime and
 * refresh), M§12.2 (which receipts are archived, restoring — spec-gap 64).
 */
import type { Json, JsonObject } from "../did.js";
import type { Machine, Step } from "./device.js";

/** Spec: M§10.3, M§11.2 — at most one watermark, and one activity refresh, per 5 s. */
const INTERVAL_S = 5;
/** Spec: M§10.2 — no `delivered` in groups with more than 32 member identities. */
const MAX_DELIVERED_GROUP = 32;
const MEDIA = ["audio", "video"];

/** Trace context for a client. */
export interface ClientContext {
  me: string;
  now: number;
  member_identities: number;
  policy: { delivered: boolean; read: boolean; played: boolean; activity: boolean };
}

/** One conversation at one device. */
export class Client implements Machine {
  private now: number;
  private readonly content = new Map<string, { seq: number; sender: string; kind: string }>();
  private readonly delivered: Record<string, Record<string, number>> = {};
  private readonly played: Record<string, Record<string, number>> = {};
  private readonly readThrough: Record<string, string> = {};
  private readonly activity: Record<string, Record<string, number>> = {};
  private readonly playedSent = new Set<string>();
  private lastReadSent: number | null = null;
  private readPending = false;
  private readonly lastActivitySent = new Map<string, number>();

  constructor(private readonly ctx: ClientContext) {
    this.now = ctx.now;
  }

  step(e: JsonObject): Step {
    const emit: Json[] = [];
    if ("advance" in e) {
      this.now += e["advance"] as number;
      // M§11.2: clear an indicator when no refresh arrived before the last one's expires_at
      for (const [sender, shown] of Object.entries(this.activity)) {
        for (const [name, until] of Object.entries(shown)) if (this.now > until) delete shown[name];
        if (Object.keys(shown).length === 0) delete this.activity[sender];
      }
      // M§10.3: when the interval passes, the latest watermark is sent once
      if (this.readPending && this.now - this.lastReadSent! >= INTERVAL_S) this.sendRead(emit);
    } else if ("sync" in e || "restore" in e) {
      this.batch(((e["sync"] ?? e["restore"]) as { items: { seq: number; object: JsonObject }[] }).items, "restore" in e, emit);
    } else if ("read" in e) {
      const through = (e["read"] as JsonObject)["through"] as string;
      // at or below the identity's current watermark (a sibling may have set it): nothing
      if (this.advances(this.ctx.me, through)) {
        this.readThrough[this.ctx.me] = through;
        if (this.lastReadSent !== null && this.now - this.lastReadSent < INTERVAL_S) this.readPending = true;
        else this.sendRead(emit);
      }
    } else if ("play" in e) {
      const id = (e["play"] as JsonObject)["id"] as string;
      const item = this.content.get(id);
      const already = this.playedSent.has(id) || this.played[id]?.[this.ctx.me] !== undefined;
      if (this.ctx.policy.played && item && MEDIA.includes(item.kind) && !already) {
        this.playedSent.add(id);
        emit.push({ send: { to: "conversation", receipt: "played", targets: [id] } });
      }
    } else if ("activity" in e) {
      const { activity, state } = e["activity"] as { activity: string; state: string };
      const last = this.lastActivitySent.get(activity);
      // `stopped` is always sent and resets the interval; an `active` within 5 s of the last is not sent
      if (this.ctx.policy.activity && (state === "stopped" || last === undefined || this.now - last >= INTERVAL_S)) {
        if (state === "stopped") this.lastActivitySent.delete(activity);
        else this.lastActivitySent.set(activity, this.now);
        emit.push({ send: { to: "conversation", activity, state } });
      }
    } else {
      const a = e["activity_in"] as { sender: string; activity: string; state: string; expires_at: number };
      if (a.state === "stopped") {
        delete this.activity[a.sender]?.[a.activity];
        if (this.activity[a.sender] && Object.keys(this.activity[a.sender]!).length === 0) delete this.activity[a.sender];
      } else if (this.now <= a.expires_at) {
        (this.activity[a.sender] ??= {})[a.activity] = a.expires_at; // an activity that arrives already expired is ignored
      }
    }
    const timeline = [...this.content].sort((a, b) => a[1].seq - b[1].seq).map(([id]) => id);
    return {
      emit,
      state: structuredClone({ timeline, delivered: this.delivered, played: this.played, read_through: this.readThrough, activity: this.activity }) as JsonObject,
    };
  }

  private sendRead(emit: Json[]): void {
    this.lastReadSent = this.now;
    this.readPending = false;
    // M§10.5: without opt-in the watermark still syncs, to the personal group only
    emit.push({ send: { to: this.ctx.policy.read ? "conversation" : "personal", receipt: "read", through: this.readThrough[this.ctx.me]! } });
  }

  /** M§10.3: a watermark only advances, and only over content the device holds. */
  private advances(identity: string, through: string): boolean {
    const target = this.content.get(through);
    if (!target) return false;
    const current = this.readThrough[identity];
    return current === undefined || target.seq > this.content.get(current)!.seq;
  }

  private batch(items: { seq: number; object: JsonObject }[], restoring: boolean, emit: Json[]): void {
    const fresh: string[] = [];
    for (const { seq, object } of items) {
      const sender = object["sender"] as string;
      if (object["object"] === "content") {
        const id = object["id"] as string;
        if (this.content.has(id)) continue; // M§8.5: collapsed, keeps its first place
        this.content.set(id, { seq, sender, kind: object["kind"] as string });
        if (sender !== this.ctx.me) fresh.push(id);
      } else if (object["object"] === "receipt") {
        // M§12.2 (spec-gap 64): archived only when it changes what is rendered; never while restoring
        if (this.receipt(object, sender) && !restoring) emit.push({ archive: { seq } });
      }
    }
    // M§10.2: decided after the whole batch, so a sibling's receipt later in it suppresses ours
    const targets = fresh.filter((id) => this.delivered[id]?.[this.ctx.me] === undefined);
    const allowed = this.ctx.policy.delivered && this.ctx.member_identities <= MAX_DELIVERED_GROUP;
    if (!restoring && allowed && targets.length) emit.push({ send: { to: "conversation", receipt: "delivered", targets } });
  }

  /** Apply a receipt; true when it changed rendering. */
  private receipt(r: JsonObject, sender: string): boolean {
    const at = (r["sent_at"] as number | undefined) ?? this.now;
    if (r["kind"] === "read") {
      const through = r["through"] as string;
      if (this.content.get(through)?.sender === sender || !this.advances(sender, through)) return false;
      this.readThrough[sender] = through;
      return true;
    }
    const table = r["kind"] === "delivered" ? this.delivered : r["kind"] === "played" ? this.played : null;
    if (!table) return false;
    let changed = false;
    for (const id of (r["targets"] ?? []) as string[]) {
      const item = this.content.get(id);
      // unknown content, a receipt from the content's own sender, or `played` on non-media: ignored
      if (!item || item.sender === sender || (r["kind"] === "played" && !MEDIA.includes(item.kind))) continue;
      if (table[id]?.[sender] !== undefined) continue; // collapsed: the first by seq keeps its timestamp
      (table[id] ??= {})[sender] = at;
      changed = true;
    }
    return changed;
  }
}
