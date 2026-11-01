/**
 * Wake Profile (draft, `wake/0.1`): the push gateway's checks on an enrolment and on a wake, a
 * waker's checks on a registration, the sealed hint a woken device opens, and the wakes a relay or
 * mailbox sends.
 *
 * Spec: W§3, W§4, W§5, W§6 (`v1.0/dsip-wake-profile-v1.0-draft.md`). Contract:
 * `impl/vectors/README.md`, "Kind: `wake`".
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Json, JsonObject } from "../did.js";
import { b64urlDecode } from "../encoding.js";
import { decodePayload, openCredential } from "../envelope.js";
import { hpkeOpen } from "../hpke.js";
import { byCodePoint } from "../recording/recording.js";
import { SchemaSet } from "../schema.js";
import { reject, type Reject } from "../verdict.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** Compiled `v1.0/dsip-wake-schemas-draft/schemas`. Spec: W§2 (schemas are normative for shape). */
export const wakeSchemas = new SchemaSet(join(REPO, "v1.0", "dsip-wake-schemas-draft", "schemas"));

/** The longest registration. Spec: W§7 (W-Registration). */
export const W_REGISTRATION_S = 2_592_000;
/** A mailbox's minimum gap between message wakes to one device. Spec: W§7 (W-Coalesce). */
export const W_COALESCE_S = 60;
/** How long a call-ended wake is worth delivering. Spec: W§7 (W-Call-Ended). */
export const W_CALL_ENDED_S = 60;
/** How far ahead a registration's `issued_at` may be. Spec: W§4.2 step 3 (the §12.9 window). */
const FUTURE_S = 300;
/** Spec: W§6 — the hint's suite (M§6.9), its info string and its padded length. */
const HINT_ALG = "hpke-base-x25519-sha256-aes128gcm";
const HINT_INFO = Buffer.from("dsip wake hint v1");
const HINT_BYTES = 256;

/** A refusal carrying a W§8.1 token: the code is the token's condition. Spec: W§8.1 */
function refuse(token: string): Reject {
  return reject(token.slice("wake.".length), token);
}

const str = (o: JsonObject, k: string) => o[k] as string;
const num = (o: JsonObject, k: string) => o[k] as number;

/**
 * Verify a registration credential: its signature by a key of `key`, its payload's schema. No
 * replay window: it is presented for its whole lifetime.
 *
 * Spec: W§4.1, W§4.2 step 1, §7.4 (the delegation's form).
 */
export function verifyRegistration(value: Json | undefined): JsonObject | null {
  const opened = openCredential(value, {});
  if ("verdict" in opened) return null;
  const p = opened.payload;
  if (!wakeSchemas.valid("wake-registration", p) || opened.signer !== p["key"]) return null;
  return p;
}

/** The gateway's reading of a verified `wake-enrol`. Spec: W§3 */
export function enrol(input: JsonObject, ctx: JsonObject): Json {
  const p = input["enrol"] as JsonObject;
  if (!wakeSchemas.valid("wake-enrol", p)) return reject("schema-invalid");
  const apps = ctx["apps"] as JsonObject[];
  if (!apps.some((a) => a["provider"] === p["provider"] && a["app"] === p["app"])) return refuse("wake.unsupported-app");
  const out: JsonObject = { key: p["from"]!, provider: p["provider"]!, app: p["app"]!, token: p["token"]! };
  // Spec: W§3 — `environment` is APNs only, `production` by default.
  if (p["provider"] === "apns") out["environment"] = (p["environment"] as string | undefined) ?? "production";
  return { verdict: "accept", enrolment: out };
}

/** A waker's checks on a verified `wake-register`, in the order W§4.2 gives. Spec: W§4.2 */
export function register(input: JsonObject, ctx: JsonObject): Json {
  const p = input["register"] as JsonObject;
  const now = num(ctx, "now");
  if (!wakeSchemas.valid("wake-register", p)) return reject("schema-invalid");
  if (p["remove"] === true) return { verdict: "accept", removed: true };
  const r = verifyRegistration(p["registration"]);
  if (!r) return refuse("wake.registration-invalid");
  if (r["waker"] !== ctx["waker"]) return refuse("wake.waker-mismatch");
  const issued = num(r, "issued_at");
  const expires = num(r, "expires_at");
  if (!(issued < expires && expires <= issued + W_REGISTRATION_S) || expires <= now || issued > now + FUTURE_S) {
    return refuse("wake.registration-invalid");
  }
  const gateways = ctx["gateways"] as string[] | undefined;
  if (gateways && !gateways.includes(str(r, "gateway"))) return refuse("wake.gateway-unknown");
  const out: JsonObject = {
    device: input["device"]!,
    key: r["key"]!,
    gateway: r["gateway"]!,
    handle: r["handle"]!,
    expires_at: expires,
  };
  if (Array.isArray(p["kinds"])) out["kinds"] = [...new Set(p["kinds"] as string[])].sort(byCodePoint);
  if (typeof p["seal_key"] === "string") out["seal_key"] = p["seal_key"];
  return { verdict: "accept", registration: out };
}

/** The gateway's checks on a verified `wake`, and the push it forwards. Spec: W§5.3 */
export function gatewayWake(input: JsonObject, ctx: JsonObject): Json {
  const p = input["wake"] as JsonObject;
  const now = num(ctx, "now");
  const signer = str(input, "signer");
  if (!wakeSchemas.valid("wake", p)) return reject("schema-invalid");
  const handles = ctx["handles"] as Record<string, JsonObject>;
  const r = verifyRegistration(p["registration"]);
  const h = r && Object.prototype.hasOwnProperty.call(handles, str(r, "handle")) ? handles[str(r, "handle")]! : null;
  if (!r || !h || r["key"] !== h["key"] || r["waker"] !== signer || r["gateway"] !== ctx["gateway"] || num(r, "expires_at") <= now) {
    return refuse("wake.not-authorized");
  }
  if (num(p, "deliver_by") <= now) return refuse("wake.expired");
  const data: JsonObject = { kind: p["kind"]!, waker: signer };
  if ("session" in p) data["session"] = p["session"]!;
  if ("sealed" in p) data["sealed"] = p["sealed"]!;
  const kind = str(p, "kind");
  const forward: JsonObject = {
    provider: h["provider"]!,
    app: h["app"]!,
    token: h["token"]!,
    // Spec: W§5.3, W§8.2 — call and call-ended are the call class; any other kind, unknown ones included, is message.
    class: kind === "call" || kind === "call-ended" ? "call" : "message",
    deliver_by: p["deliver_by"]!,
    data: { "dsip-wake": data },
  };
  if (h["provider"] === "apns") forward["environment"] = (h["environment"] as string | undefined) ?? "production";
  return { verdict: "accept", forward };
}

/** A woken device opens a call wake's sealed hint. Spec: W§6 */
export function openHint(input: JsonObject): Json {
  const sealed = input["sealed"] as JsonObject;
  if (sealed["alg"] !== HINT_ALG) return reject("sealed-alg-unsupported");
  const enc = b64urlDecode(str(sealed, "enc"));
  const ct = b64urlDecode(str(sealed, "ct"));
  if (!enc || !ct) return reject("sealed-open-failed");
  const pt = hpkeOpen(enc, Buffer.from(str(input, "secret_hex"), "hex"), HINT_INFO, Buffer.from(str(input, "session"), "utf8"), ct);
  if (!pt) return reject("sealed-open-failed");
  const bad = reject("sealed-plaintext-invalid");
  if (pt.length !== HINT_BYTES) return bad;
  let end = pt.length;
  while (end > 0 && pt[end - 1] === 0x20) end--;
  const decoded = decodePayload(pt.subarray(0, end));
  if (!decoded.ok || !wakeSchemas.valid("wake-hint", decoded.value)) return bad;
  return { verdict: "accept", hint: decoded.value };
}

type Registration = { identity: string; expires_at: number; kinds?: string[] };
type Held = { expires_at: number; devices: Set<string>; woken: Set<string> };

/**
 * A relay's or a mailbox's wake state: registrations, bindings, held invites, and the wakes it sends.
 *
 * Spec: W§4.3 (when a registration ends), W§5.1 (when a waker wakes), §13.3 (a binding flushes what is held).
 */
export class Waker {
  private readonly regs = new Map<string, Registration>();
  private readonly bound = new Set<string>();
  private readonly held = new Map<string, Held>();
  private readonly lastMessage = new Map<string, number>();

  constructor(private readonly component: string) {}

  private live(d: string, t: number): boolean {
    const r = this.regs.get(d);
    return !!r && r.expires_at > t;
  }

  private wants(d: string, kind: string): boolean {
    const k = this.regs.get(d)?.kinds;
    return !k || k.includes(kind);
  }

  private end(d: string, cause: string): Json[] {
    if (!this.regs.delete(d)) return [];
    return [{ ended: { device: d, cause } }];
  }

  /** The invite `session` stops being held at `when`. Spec: W§5.1 (call-ended) */
  private stopHolding(session: string, when: number): Json[] {
    const h = this.held.get(session)!;
    this.held.delete(session);
    return [...h.woken]
      .filter((d) => h.devices.has(d) && this.live(d, when) && this.wants(d, "call-ended"))
      .sort(byCodePoint)
      .map((d) => ({ wake: { device: d, kind: "call-ended", session, deliver_by: when + W_CALL_ENDED_S } }));
  }

  /** The registrations held, by device, in code-point order. */
  registrations(): string[] {
    return [...this.regs.keys()].sort(byCodePoint);
  }

  /** Apply one event; the emissions, in order. */
  step(ev: JsonObject): Json[] {
    const at = num(ev, "at");
    const out: Json[] = [];
    for (const s of [...this.held.keys()].sort(byCodePoint)) {
      const h = this.held.get(s)!;
      if (h.expires_at <= at) out.push(...this.stopHolding(s, h.expires_at));
    }
    for (const d of this.registrations()) {
      // §12.9: `expires_at` is the first instant the registration is no longer valid.
      if (this.regs.get(d)!.expires_at <= at) out.push(...this.end(d, "expired"));
    }
    if ("register" in ev) {
      const r = ev["register"] as JsonObject;
      const reg: Registration = { identity: str(r, "identity"), expires_at: num(r, "expires_at") };
      if (Array.isArray(r["kinds"])) reg.kinds = r["kinds"] as string[];
      this.regs.set(str(r, "device"), reg);
    } else if ("remove" in ev) {
      out.push(...this.end(str(ev, "remove"), "removed"));
    } else if ("revoke" in ev) {
      out.push(...this.end(str(ev, "revoke"), "revoked"));
    } else if ("forget" in ev) {
      out.push(...this.end(str(ev, "forget"), "forgotten"));
    } else if ("bind" in ev) {
      const d = str(ev, "bind");
      this.bound.add(d);
      for (const h of this.held.values()) {
        h.devices.delete(d);
        h.woken.delete(d);
      }
      this.lastMessage.delete(d);
    } else if ("unbind" in ev) {
      this.bound.delete(str(ev, "unbind"));
    } else if ("hold" in ev && this.component === "relay") {
      const x = ev["hold"] as JsonObject;
      const session = str(x, "session");
      if (num(x, "expires_at") > at) {
        let h = this.held.get(session);
        if (!h) {
          h = { expires_at: num(x, "expires_at"), devices: new Set(), woken: new Set() };
          this.held.set(session, h);
        }
        for (const d of [...new Set(x["devices"] as string[])].sort(byCodePoint)) {
          if (this.bound.has(d)) continue;
          h.devices.add(d);
          if (!h.woken.has(d) && this.live(d, at) && this.wants(d, "call")) {
            h.woken.add(d);
            out.push({ wake: { device: d, kind: "call", session, deliver_by: num(x, "expires_at") } });
          }
        }
      }
    } else if ("drop" in ev && this.component === "relay") {
      const s = str(ev, "drop");
      if (this.held.has(s)) out.push(...this.stopHolding(s, at));
    } else if ("store" in ev && this.component === "mailbox") {
      const x = ev["store"] as JsonObject;
      if (x["class"] !== "ephemeral") {
        for (const d of this.registrations()) {
          const r = this.regs.get(d)!;
          if (r.identity !== x["identity"] || this.bound.has(d) || !this.live(d, at) || !this.wants(d, "message")) continue;
          const last = this.lastMessage.get(d);
          if (last !== undefined && at - last < W_COALESCE_S) continue;
          this.lastMessage.set(d, at);
          out.push({ wake: { device: d, kind: "message", deliver_by: at + W_COALESCE_S } });
        }
      }
    } else if ("answer" in ev) {
      const a = ev["answer"] as JsonObject;
      // Spec: W§4.3, W§8.1 — any `wake.*` answer, known or not, ends the registration.
      if (str(a, "reason").startsWith("wake.")) out.push(...this.end(str(a, "device"), "gateway"));
    } else if (!("tick" in ev)) {
      throw new Error(`unknown wake event ${JSON.stringify(ev)}`);
    }
    return out;
  }
}

/** The `wake` vector kind's runner. Spec: none (infrastructure). */
export function runWake(ctx: JsonObject, input: JsonObject): Json | undefined {
  switch (input["check"]) {
    case "schema":
      return wakeSchemas.valid(str(input, "schema"), input["value"]!) ? { verdict: "accept" } : reject("schema-invalid");
    case "enrol":
      return enrol(input, ctx);
    case "register":
      return register(input, ctx);
    case "gateway":
      return gatewayWake(input, ctx);
    case "open-hint":
      return openHint(input);
    case undefined: {
      const w = new Waker(str(ctx, "component"));
      return (input["steps"] as JsonObject[]).map((st) => ({
        emit: w.step(st["event"] as JsonObject),
        registrations: w.registrations(),
      }));
    }
    default:
      return undefined;
  }
}
