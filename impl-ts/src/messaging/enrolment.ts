/**
 * The mailbox's view of whom it serves: configured identities, identities that enrol within the
 * operator's bound, and how an enrolment ends (release, or idle expiry at the operator's choice).
 *
 * Spec: M§4.1 ("Whom a mailbox serves", "When an enrolment ends"), M§4.4 (registered device,
 * `mls_retention_s`), M§5.7 (`release`), M§15.5, M§16 (`mailbox.not-served`,
 * `mailbox.not-enrolled`) — spec-gaps 115, 130.
 */
import type { Json, JsonObject } from "../did.js";
import type { Machine, Step } from "./device.js";

/** Spec: M§4.4 — RECOMMENDED `mls_retention_s`, 2,592,000 s (30 days). */
const MLS_RETENTION_S = 2_592_000;

/** The trace context of an {@link Enrolment}. Spec: M§4.1, M§4.4 */
export interface EnrolmentContext {
  /** The trace's start time (seconds). */
  now: number;
  /** Identities the operator configures. */
  configured?: string[];
  /** The operator's bound on enrolled identities; 0 closes enrolment. */
  serve_any?: number;
  /** Whether the mailbox ends idle enrolments (a MAY). */
  expire_idle?: boolean;
  /** How long a device stays registered after its last verified `hello`. */
  mls_retention_s?: number;
}

/** One owner operation, or a release, from a device of an identity. */
interface OwnerOp {
  identity: string;
  device: string;
  id: string;
}

/**
 * The enrolment machine. Owner operations (`sync`, `key-packages`, `mailbox-config` without
 * `release`) on a verified binding enrol an unserved identity while the bound has room, else are
 * refused `mailbox.not-served`; `release: true` ends an enrolment; with idle expiry, an enrolled
 * identity with no registered device is released.
 *
 * Spec: M§4.1, M§4.4, M§5.7, M§16 (spec-gap 130)
 *
 * Impl: the enrolling owner operation counts as the identity's last verified `hello` (its device is
 * bound by one), and only a `hello` refreshes it; expiry is evaluated when time advances, every
 * expired identity released in enrolment order.
 */
export class Enrolment implements Machine {
  private now: number;
  private readonly configured: Set<string>;
  private readonly bound: number;
  private readonly expireIdle: boolean;
  private readonly retention: number;
  /** Enrolled identity → time of its last verified `hello`, in enrolment order. */
  private readonly enrolled = new Map<string, number>();

  constructor(ctx: EnrolmentContext) {
    this.now = ctx.now;
    this.configured = new Set(ctx.configured ?? []);
    this.bound = ctx.serve_any ?? 0;
    this.expireIdle = ctx.expire_idle ?? false;
    this.retention = ctx.mls_retention_s ?? MLS_RETENTION_S;
  }

  step(e: JsonObject): Step {
    const emit: Json[] = [];
    if ("owner_op" in e) {
      const op = e["owner_op"] as unknown as OwnerOp;
      if (!this.configured.has(op.identity) && !this.enrolled.has(op.identity)) {
        if (this.enrolled.size < this.bound) {
          this.enrolled.set(op.identity, this.now);
          emit.push({ enrolled: { identity: op.identity } });
        } else {
          // Spec: M§4.1 — enrolment closed or the bound reached
          emit.push(this.error(op, "mailbox.not-served"));
        }
      }
    } else if ("release" in e) {
      const op = e["release"] as unknown as OwnerOp;
      if (this.enrolled.has(op.identity)) {
        // Spec: M§5.7 — `accepted`, then the enrolment ends
        emit.push({ accepted: { to: op.device, in_reply_to: op.id } });
        this.enrolled.delete(op.identity);
        emit.push({ released: { identity: op.identity, cause: "owner" } });
      } else if (this.configured.has(op.identity)) {
        // Spec: M§4.1 — a configured identity is ended by its operator only
        emit.push(this.error(op, "mailbox.not-enrolled"));
      } else {
        // Spec: M§4.1 — a release never enrols
        emit.push(this.error(op, "mailbox.not-served"));
      }
    } else if ("hello" in e) {
      const identity = (e["hello"] as JsonObject)["identity"] as string;
      if (this.enrolled.has(identity)) this.enrolled.set(identity, this.now);
    } else if ("advance" in e) {
      this.now += e["advance"] as number;
      if (this.expireIdle) {
        for (const [identity, last] of [...this.enrolled]) {
          // Spec: M§4.4 — registered while within `mls_retention_s`; at exactly the bound it still is
          if (this.now - last > this.retention) {
            this.enrolled.delete(identity);
            emit.push({ released: { identity, cause: "idle" } });
          }
        }
      }
    }
    return { emit, state: { enrolled: [...this.enrolled.keys()], free: this.bound - this.enrolled.size } };
  }

  private error(op: OwnerOp, reason: string): Json {
    return { error: { to: op.device, in_reply_to: op.id, reason } };
  }
}
