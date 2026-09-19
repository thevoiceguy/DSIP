/**
 * The small machines a messaging device runs beside MLS: ordering gaps, commit retries, and the
 * outbox while the hub cannot be reached.
 *
 * Spec: M§6.5 (seq gaps and re-joining, spec-gap 69; commit conflicts, spec-gap 58; hub moves,
 * spec-gap 60), M§9.4 (hub unavailable, spec-gap 72), §13.2 (backoff), §15.3 (category fallback).
 */
import type { Json, JsonObject } from "../did.js";
import { isRegisteredReason } from "../registry.js";

/** One step's result in a messaging trace. */
export interface Step {
  emit: Json[];
  state: JsonObject;
}

/** A component a messaging trace drives. */
export interface Machine {
  step(event: JsonObject): Step;
}

// ---- M§6.5 gaps

/** Spec: M§6.5 — RECOMMENDED; the timeout is the device's own (spec-gap 69). */
const GAP_TIMEOUT_S = 300;

/** Tracks one group's `seq` order at a device. Spec: M§6.5 (spec-gap 69) */
export class GapTracker implements Machine {
  private now: number;
  private contiguous: number;
  private readonly timeout: number;
  private held: number[] = [];
  private readonly seen = new Set<number>(); // processed beyond the contiguous point
  private firstHeldAt: number | null = null;

  constructor(ctx: { now: number; contiguous: number; gap_timeout?: number }) {
    this.now = ctx.now;
    this.contiguous = ctx.contiguous;
    this.timeout = ctx.gap_timeout ?? GAP_TIMEOUT_S;
  }

  step(e: JsonObject): Step {
    const emit: Json[] = [];
    if ("advance" in e) {
      this.now += e["advance"] as number;
      if (this.firstHeldAt !== null && this.now - this.firstHeldAt >= this.timeout) {
        // re-join by external commit: every seq up to the highest seen is passed
        emit.push({ rejoin: { held: [...this.held] } });
        this.contiguous = Math.max(this.contiguous, ...this.held, ...this.seen);
        this.held = [];
        this.seen.clear();
        this.firstHeldAt = null;
      }
    } else {
      const { seq, class: cls } = e["item"] as { seq: number; class: string };
      if (seq <= this.contiguous || this.seen.has(seq) || this.held.includes(seq)) {
        emit.push({ duplicate: seq });
      } else if (seq === this.contiguous + 1) {
        emit.push({ process: seq });
        this.contiguous = seq;
        this.drain(emit);
      } else if (cls === "handshake" || this.held.some((h) => h < seq)) {
        // a handshake beyond a gap is held, and so is everything after a held item
        this.held.push(seq);
        this.held.sort((a, b) => a - b);
        this.firstHeldAt ??= this.now;
        emit.push({ hold: seq });
      } else {
        emit.push({ process: seq }); // application items stay decryptable within an epoch
        this.seen.add(seq);
      }
    }
    return { emit, state: { contiguous: this.contiguous, held: [...this.held] } };
  }

  private drain(emit: Json[]): void {
    for (;;) {
      const next = this.contiguous + 1;
      if (this.seen.delete(next)) this.contiguous = next;
      else if (this.held.includes(next)) {
        this.held = this.held.filter((h) => h !== next);
        emit.push({ process: next });
        this.contiguous = next;
      } else break;
    }
    if (this.held.length === 0) this.firstHeldAt = null;
  }
}

// ---- M§6.5 commit retries

/** Spec: M§6.5 (spec-gap 58) — at most three proposals for one operation. */
const MAX_PROPOSALS = 3;
const ORDERING = ["mailbox.commit-conflict", "mailbox.stale-epoch"];

/** What a committing device does with the hub's answer. Spec: M§6.5 (spec-gaps 58, 60) */
export class CommitRetry implements Machine {
  private attempt = 1;
  private state = "pending";
  private refusal = "";
  private fallbackRetried = false;
  private readonly max: number;

  constructor(ctx: { max_attempts?: number }) {
    this.max = ctx.max_attempts ?? MAX_PROPOSALS;
  }

  step(e: JsonObject): Step {
    const emit: Json[] = [];
    if ("answer" in e) {
      const reason = (e["answer"] as JsonObject)["reason"] as string | undefined;
      if (reason === undefined) {
        // a member MUST NOT apply its own commit until it holds the hub's `accepted`
        emit.push({ merge: {} });
        this.state = "merged";
      } else {
        emit.push({ discard: {} });
        this.refusal = reason;
        // ordering refusals are retried up to the bound; an unregistered mailbox.* condition takes the
        // category fallback (§15.3): re-sync, retry once; unknown-group is retried only if the hub moved
        const unknownMailbox = reason.startsWith("mailbox.") && !isRegisteredReason(reason);
        const retry =
          (ORDERING.includes(reason) && this.attempt < this.max) ||
          (unknownMailbox && !this.fallbackRetried && this.attempt < this.max) ||
          (reason === "mailbox.unknown-group" && this.attempt < this.max);
        if (retry) {
          if (unknownMailbox) this.fallbackRetried = true; // the fallback's one retry is its own, inside the bound
          emit.push({ sync: {} });
          this.state = "syncing";
        } else {
          emit.push({ surface: reason });
          this.state = "surfaced";
        }
      }
    } else {
      const synced = e["synced"] as { still_needed: boolean; hub_moved?: boolean };
      if (this.refusal === "mailbox.unknown-group" && synced.hub_moved !== true) {
        emit.push({ surface: this.refusal }); // no move: the refusal is final
        this.state = "surfaced";
      } else if (!synced.still_needed) {
        emit.push({ done: "no-longer-needed" }); // another commit already did it
        this.state = "done";
      } else {
        this.attempt += 1;
        emit.push({ repropose: { attempt: this.attempt } });
        this.state = "pending";
      }
    }
    return { emit, state: { attempt: this.attempt, state: this.state } };
  }
}

// ---- M§9.4 hub outage

/** Spec: M§9.4 — RECOMMENDED threshold, the client's own. */
const HUB_TIMEOUT_S = 86400;
/** Spec: §13.2 — reconnect backoff: 1 s doubling to a 60 s ceiling. */
const BACKOFF_CEILING_S = 60;

/** A group's outbox at a device. Spec: M§9.4 (spec-gap 72) */
export class HubOutage implements Machine {
  private now: number;
  private readonly timeout: number;
  private state: "up" | "down" | "abandoned" = "up";
  private pending: string[] = [];
  private attempt = 0;
  private downSince: number | null = null;
  private retryAt: number | null = null;
  /** Failed hand-overs to the successor since abandonment, and when the next one is due (spec-gap 72). */
  private handoverAttempt = 0;
  private handoverAt: number | null = null;

  constructor(ctx: { now: number; hub_timeout?: number }) {
    this.now = ctx.now;
    this.timeout = ctx.hub_timeout ?? HUB_TIMEOUT_S;
  }

  step(e: JsonObject): Step {
    const emit: Json[] = [];
    if ("advance" in e) {
      this.now += e["advance"] as number;
      if (this.state === "abandoned" && this.handoverAt !== null && this.now >= this.handoverAt) {
        emit.push({ handover: "retry" }); // once: the next failure schedules the next
        this.handoverAt = null;
      } else if (this.state === "down" && this.now - this.downSince! >= this.timeout) {
        // the M§7.5 trigger: the successor takes the pending items; the dead group's outbox is abandoned
        emit.push({ successor: { pending: [...this.pending] } });
        this.pending = [];
        this.state = "abandoned";
        this.retryAt = null;
      } else if (this.state === "down" && this.retryAt !== null && this.now >= this.retryAt && this.pending.length > 0) {
        emit.push({ forward: this.pending[0]! }); // the same bytes (M§9.3)
        this.retryAt = null;
      }
    } else if ("handover_failed" in e) {
      // spec-gap 72: only an abandoned outbox has a hand-over; every failure counts, §13.2 started afresh
      if (this.state === "abandoned") {
        this.handoverAttempt += 1;
        const wait = Math.min(2 ** (this.handoverAttempt - 1), BACKOFF_CEILING_S);
        this.handoverAt = this.now + wait;
        emit.push({ handover_retry_in: wait });
      }
    } else if ("deposit" in e) {
      const id = (e["deposit"] as JsonObject)["id"] as string;
      if (this.state === "abandoned") emit.push({ refuse: "group-abandoned" });
      else {
        this.pending.push(id);
        // new content is encrypted at once and queued behind the pending items
        emit.push(this.state === "up" ? { forward: id } : { queued: id });
      }
    } else {
      const answer = (e["answer"] ?? e["no_answer"]) as { id: string; reason?: string };
      const outage = "no_answer" in e || answer.reason === "mailbox.hub-unreachable";
      if (!this.pending.includes(answer.id) || this.state === "abandoned") {
        // nothing to do: an answer for something no longer in the outbox
      } else if (outage) {
        if (this.state === "up") [this.state, this.downSince] = ["down", this.now];
        this.attempt += 1;
        const wait = Math.min(2 ** (this.attempt - 1), BACKOFF_CEILING_S);
        this.retryAt = this.now + wait;
        emit.push({ retry_in: wait });
      } else {
        this.pending = this.pending.filter((p) => p !== answer.id);
        if (answer.reason !== undefined) {
          emit.push({ refused: { id: answer.id, reason: answer.reason } }); // not an outage: handled elsewhere
        } else {
          emit.push({ sent: answer.id });
          if (this.state === "down") {
            // an accepted ends the outage, flushes the queue in order, and resets the backoff
            [this.state, this.downSince, this.retryAt, this.attempt] = ["up", null, null, 0];
            for (const id of this.pending) emit.push({ forward: id });
          }
        }
      }
    }
    const downFor = this.downSince === null ? null : this.now - this.downSince;
    return {
      emit,
      state: { state: this.state, pending: [...this.pending], attempt: this.attempt, down_for: downFor, handover_attempt: this.handoverAttempt },
    };
  }
}
