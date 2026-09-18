/**
 * A mock clock with named per-session timers, as the state traces drive it.
 *
 * Spec: §12.9 (timers). Impl: expired timers fire in deadline order, ties by start order
 * (vectors README, `advance`).
 */
interface Timer {
  name: string;
  session: string;
  deadline: number;
  order: number;
}

/** Clock plus timer table. */
export class Timers {
  private timers: Timer[] = [];
  private order = 0;

  constructor(public now: number) {}

  /** (Re)start a timer. */
  start(name: string, session: string, seconds: number): void {
    this.stop(name, session);
    this.timers.push({ name, session, deadline: this.now + seconds, order: this.order++ });
  }

  /** Stop a timer; true when it was running. */
  stop(name: string, session: string): boolean {
    const before = this.timers.length;
    this.timers = this.timers.filter((t) => !(t.name === name && t.session === session));
    return this.timers.length < before;
  }

  /** True while the timer is running. */
  running(name: string, session: string): boolean {
    return this.timers.some((t) => t.name === name && t.session === session);
  }

  /** Advance the clock, firing every timer that expires on the way. */
  advance(seconds: number, fire: (name: string, session: string) => void): void {
    const target = this.now + seconds;
    for (;;) {
      const due = this.timers
        .filter((t) => t.deadline <= target)
        .sort((a, b) => a.deadline - b.deadline || a.order - b.order)[0];
      if (!due) break;
      this.now = due.deadline;
      this.timers = this.timers.filter((t) => t !== due);
      fire(due.name, due.session);
    }
    this.now = target;
  }
}
