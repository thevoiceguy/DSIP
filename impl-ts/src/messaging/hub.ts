/**
 * The hub: one ordering authority per group.
 *
 * Spec: M§6.5 (authenticate depositors, order commits, bound staleness, sequence, fan out in
 * order, welcomes queued — spec-gaps 34, 50, 59, 66), M§6.8 (external joins, spec-gap 62), M§7.3
 * (device-ownership rule on the public commit), M§7.4 (moving the group, spec-gap 60), M§9.3
 * (idempotent re-deposits), M§11.2 (ephemeral is forwarded, never stored).
 *
 * MLS is abstracted as the traces abstract it: the hub sees an epoch, a commit's adds and removes,
 * whether it validated, and a digest of the MLS bytes.
 */
import type { Json, JsonObject } from "../did.js";
import type { Machine, Step } from "./device.js";
import { externalJoin } from "./rules.js";

interface Leaf {
  identity: string;
  device: string;
  delegation_valid?: boolean;
}

interface Commit {
  adds: Leaf[];
  removes: Leaf[];
  valid?: boolean;
  external?: boolean;
  moves_to?: string;
}

interface Deposit {
  id: string;
  device: string;
  identity: string;
  class: string;
  epoch?: number;
  digest: string;
  commit?: Commit;
  expires_at?: number;
}

/** Trace context for a hub. */
export interface HubContext {
  now: number;
  kind: string;
  epoch: number;
  roster: Record<string, string[]>;
  owner?: string;
  /** A new hub continues after the moving commit's seq (`handover_seq` + 1). */
  next_seq?: number;
}

/** One group at its hub. */
export class Hub implements Machine {
  private epoch: number;
  private nextSeq: number;
  private readonly roster: Record<string, string[]>;
  private readonly pending: Record<string, number[]> = {};
  private readonly welcomes: Record<string, number[]> = {};
  private readonly classes = new Map<number, string>();
  private readonly digests = new Map<string, number>();
  private sent = new Set<string>();
  /** Identities whose mailbox has no registration yet: nothing but the welcome goes to them. */
  private readonly unregistered = new Set<string>();
  private groupInfo = false;
  private movedTo: string | null = null;
  private emit: Json[] = [];

  constructor(private readonly ctx: HubContext) {
    this.epoch = ctx.epoch;
    this.nextSeq = ctx.next_seq ?? 1;
    this.roster = structuredClone(ctx.roster);
  }

  step(e: JsonObject): Step {
    this.emit = [];
    if ("deposit" in e) this.deposit(e["deposit"] as unknown as Deposit);
    else if ("ack" in e) this.ack(e["ack"] as { identity: string; seq: number; class?: string });
    else if ("restart" in e) {
      // spec-gap 59: state survives; the head of every unacknowledged queue is re-sent, welcomes included
      this.sent = new Set();
      this.flush();
    }
    return {
      emit: this.emit,
      state: structuredClone({
        epoch: this.epoch, next_seq: this.nextSeq, roster: this.roster, pending: this.pending,
        group_info: this.groupInfo, moved_to: this.movedTo, welcomes: this.welcomes,
      }) as JsonObject,
    };
  }

  private refuse(d: Deposit, reason: string): void {
    this.emit.push({ error: { to: d.device, in_reply_to: d.id, reason } });
  }

  private deposit(d: Deposit): void {
    // M§7.4: a group that has moved is refused here, whatever the deposit
    if (this.movedTo !== null) return this.refuse(d, "mailbox.unknown-group");
    // rule 1: a hub orders handshake and application, forwards ephemeral, keeps group-info; nothing else
    if (!["handshake", "application", "ephemeral", "group-info"].includes(d.class)) return this.refuse(d, "mailbox.unsupported-class");
    // M§11.2: activity past its expires_at is dropped silently, whoever sent it
    if (d.class === "ephemeral" && d.expires_at !== undefined && d.expires_at < this.ctx.now) return;
    // M§9.3: the same MLS bytes again get the original seq and fan out nothing. A sequenced item is
    // recognised before anything else is asked of it: its bytes were authenticated when first accepted.
    const known = d.class === "handshake" || d.class === "application" ? this.digests.get(d.digest) : undefined;
    if (known !== undefined) return void this.emit.push({ accepted: { to: d.device, in_reply_to: d.id, seq: known, duplicate: true } });
    const external = d.class === "handshake" && d.commit?.external === true;
    // rule 1: only a device whose identity has a leaf in the group — or an authorized external joiner (M§6.8)
    if (external ? !this.authorized(d, d.commit!) : !(d.identity in this.roster)) return this.refuse(d, "policy.blocked");
    if (d.class === "ephemeral") {
      // forwarded to the other member identities; no seq, no `accepted`, nothing queued
      for (const to of Object.keys(this.roster).sort()) if (to !== d.identity) this.emit.push({ forward: { to, class: "ephemeral" } });
      return;
    }
    if (d.class === "group-info") {
      // state, not conversation: stored as the latest and forwarded without a seq
      this.groupInfo = true;
      this.emit.push({ accepted: { to: d.device, in_reply_to: d.id } });
      for (const to of Object.keys(this.roster).sort()) this.emit.push({ fanout: { to, class: "group-info" } });
      return;
    }

    const recipients = Object.keys(this.roster);
    const welcomed: string[] = [];
    if (d.class === "application") {
      // rule 3: epoch e or e − 1
      if (d.epoch !== this.epoch && d.epoch !== this.epoch - 1) return this.refuse(d, "mailbox.stale-epoch");
    } else if (!d.commit) {
      // a standalone proposal for the current epoch is sequenced without advancing it
      if (d.epoch !== this.epoch) return this.refuse(d, "mailbox.stale-epoch");
    } else {
      // rule 2: the first valid commit for the epoch wins; a later one arrives an epoch late
      if (d.epoch === this.epoch - 1) return this.refuse(d, "mailbox.commit-conflict");
      if (d.epoch !== this.epoch) return this.refuse(d, "mailbox.stale-epoch");
      if (!this.authorized(d, d.commit)) return this.refuse(d, "policy.blocked");
      for (const leaf of d.commit.removes) {
        this.roster[leaf.identity] = (this.roster[leaf.identity] ?? []).filter((x) => x !== leaf.device);
        if (this.roster[leaf.identity]!.length === 0) delete this.roster[leaf.identity];
      }
      for (const leaf of d.commit.adds) {
        const devices = (this.roster[leaf.identity] ??= []);
        if (devices.includes(leaf.device)) continue;
        devices.push(leaf.device);
        devices.sort();
        // spec-gap 50: every identity that gains a device the group did not have gets a welcome —
        // except by external commit, where the joiner joined by its own commit
        if (!d.commit.external && !welcomed.includes(leaf.identity)) welcomed.push(leaf.identity);
        if (!recipients.includes(leaf.identity) && !d.commit.external) this.unregistered.add(leaf.identity);
      }
      // rule 5: the members as they were, so a removed identity still receives the commit
      this.epoch += 1;
      if (d.commit.moves_to !== undefined) this.movedTo = d.commit.moves_to;
    }

    const seq = this.nextSeq++;
    this.digests.set(d.digest, seq);
    this.classes.set(seq, d.class);
    this.emit.push({ accepted: { to: d.device, in_reply_to: d.id, seq } });
    for (const to of recipients) (this.pending[to] ??= []).push(seq);
    for (const to of welcomed) (this.welcomes[to] ??= []).push(seq);
    this.flush();
  }

  /** M§7.3 device-ownership rule and M§6.8, on the public commit; MLS validity is the trace's `valid`. */
  private authorized(d: Deposit, c: Commit): boolean {
    if (c.valid === false) return false;
    if (c.external) {
      const verdict = externalJoin({
        kind: this.ctx.kind, owner: this.ctx.owner, roster: Object.keys(this.roster),
        joiner: { identity: d.identity, device: d.device }, adds: c.adds, removes: c.removes,
      });
      return verdict.verdict === "accept";
    }
    // adding a device to another member identity is reserved to that identity's own devices
    if (c.adds.some((leaf) => leaf.identity !== d.identity && leaf.identity in this.roster)) return false;
    const others = new Set(c.removes.filter((leaf) => leaf.identity !== d.identity).map((leaf) => leaf.identity));
    for (const identity of others) {
      const removed = c.removes.filter((leaf) => leaf.identity === identity);
      const left = (this.roster[identity] ?? []).filter((device) => !removed.some((leaf) => leaf.device === device));
      // another identity goes entirely, or only leaves whose delegation no longer verifies
      if (left.length > 0 && !removed.every((leaf) => leaf.delegation_valid === false)) return false;
    }
    return true;
  }

  private ack(a: { identity: string; seq: number; class?: string }): void {
    const queue = a.class === "welcome" ? this.welcomes : this.pending;
    // delivery is in seq order, so only the head of a queue can have been delivered — and acknowledged
    if (queue[a.identity]?.[0] !== a.seq) return;
    const list = queue[a.identity]!.slice(1);
    if (list.length) queue[a.identity] = list;
    else delete queue[a.identity];
    if (a.class === "welcome" && !this.welcomes[a.identity]) this.unregistered.delete(a.identity);
    this.flush();
  }

  /** Rule 5: per mailbox in seq order — the head of each queue, once; welcomes in their own queue. */
  private flush(): void {
    for (const to of Object.keys(this.pending).sort()) {
      const head = this.pending[to]![0]!;
      if (this.unregistered.has(to) || this.sent.has(`${to}/${head}`)) continue;
      this.sent.add(`${to}/${head}`);
      this.emit.push({ fanout: { to, seq: head, class: this.classes.get(head)! } });
    }
    for (const to of Object.keys(this.welcomes).sort()) {
      const head = this.welcomes[to]![0]!;
      if (this.sent.has(`${to}/w${head}`)) continue;
      this.sent.add(`${to}/w${head}`);
      this.emit.push({ fanout: { to, seq: head, class: "welcome" } });
    }
  }
}
