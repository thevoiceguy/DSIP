/**
 * SNMPv3 with the User-based Security Model for the Device Events Profile: key localization,
 * and a gateway's USM receiver for traps and informs (RFC 3414 §3.2 order of checks).
 *
 * Spec: E§3 (SNMPv3); RFC 3414 (USM, A.2 password to key), RFC 7860 (HMAC-SHA-2), RFC 3826
 * (AES-128-CFB), RFC 3412 §7.2 (who is authoritative). The exact checks, their order, reason
 * tokens and output shapes are the vectors README's, "Kind: `device-events`", `check: "usm-key"`
 * and "SNMPv3 traces".
 */
import { createDecipheriv, createHash, createHmac } from "node:crypto";
import type { Json, JsonObject } from "../did.js";

/** Authentication protocol: hash name and MAC length. Spec: E§3; RFC 3414, RFC 7860 */
const AUTH: Record<string, { hash: string; mac: number }> = {
  md5: { hash: "md5", mac: 12 },
  sha: { hash: "sha1", mac: 12 },
  sha224: { hash: "sha224", mac: 16 },
  sha256: { hash: "sha256", mac: 24 },
  sha384: { hash: "sha384", mac: 32 },
  sha512: { hash: "sha512", mac: 48 },
};

/**
 * RFC 3414 A.2 password to localized key: `Ku` is the hash of the password repeated and cut to
 * 1,048,576 bytes; the localized key is `H(Ku ‖ engineID ‖ Ku)`. Spec: E§3; RFC 7860 §9.3
 */
export function localizePassword(auth: string, password: Uint8Array, engineId: Uint8Array): Buffer {
  const hash = AUTH[auth]!.hash;
  const total = 1048576;
  const h = createHash(hash);
  const chunk = Buffer.alloc(64 * password.length);
  for (let i = 0; i < chunk.length; i++) chunk[i] = password[i % password.length]!;
  // 1,048,576 is a multiple of 64 × len only by luck; feed whole chunks then the rest
  let done = 0;
  while (done + chunk.length <= total) {
    h.update(chunk);
    done += chunk.length;
  }
  if (done < total) {
    const rest = Buffer.alloc(total - done);
    for (let i = 0; i < rest.length; i++) rest[i] = password[(done + i) % password.length]!;
    h.update(rest);
  }
  const ku = h.digest();
  return createHash(hash).update(Buffer.concat([ku, engineId, ku])).digest();
}

/**
 * `check: "usm-key"`: the localized authentication key and the AES-128 privacy key (its first
 * 16 bytes, RFC 3826 §1.2.1). Spec: E§3
 */
export function usmKey(input: JsonObject): JsonObject {
  const password = input["password"];
  if (typeof password !== "string" || password.length === 0) return { error: "bad-password" };
  const key = localizePassword(input["auth"] as string, Buffer.from(password, "utf8"), Buffer.from(input["engine_id"] as string, "hex"));
  return { auth_key: key.toString("hex"), priv_key: key.subarray(0, 16).toString("hex") };
}

// ---------------------------------------------------------------------------------------------
// BER

/** Any BER or structure failure; the step decides the reason it reports. */
export class Bad extends Error {}

interface Tlv {
  tag: number;
  /** Offset of the content in the buffer. */
  start: number;
  /** Offset just past the content. */
  end: number;
}

/**
 * Read one TLV at `pos`, bounded by `limit`. Spec: E§3; README "SNMPv3 traces", step 1 —
 * one-byte tags, definite lengths (short form, or long form with 1–4 length bytes), content
 * within its parent.
 */
function tlv(b: Uint8Array, pos: number, limit: number): Tlv {
  if (pos >= limit) throw new Bad();
  const tag = b[pos]!;
  if ((tag & 0x1f) === 0x1f) throw new Bad(); // high-tag-number form
  pos++;
  if (pos >= limit) throw new Bad();
  const first = b[pos++]!;
  let len: number;
  if (first < 0x80) {
    len = first;
  } else {
    const n = first & 0x7f;
    if (n < 1 || n > 4) throw new Bad(); // 0x80 is the indefinite length
    if (pos + n > limit) throw new Bad();
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[pos++]!;
  }
  if (pos + len > limit) throw new Bad();
  return { tag, start: pos, end: pos + len };
}

/**
 * The children of a TLV, which must exactly fill it. README step 1: a PDU's constructed bit is
 * not checked, so a primitive tag is read the same way (and is `not-a-notification` at step 9).
 */
function children(b: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = t.start;
  while (p < t.end) {
    const c = tlv(b, p, t.end);
    out.push(c);
    p = c.end;
  }
  return out;
}

/** A SEQUENCE of exactly `n` elements. */
function seq(b: Uint8Array, t: Tlv | undefined, n: number): Tlv[] {
  if (!t || t.tag !== 0x30) throw new Bad();
  const c = children(b, t);
  if (c.length !== n) throw new Bad();
  return c;
}

/** INTEGER content, 1–8 bytes, two's complement. */
function intOf(b: Uint8Array, t: Tlv | undefined): bigint {
  if (!t || t.tag !== 0x02) throw new Bad();
  const n = t.end - t.start;
  if (n < 1 || n > 8) throw new Bad();
  let v = 0n;
  for (let i = t.start; i < t.end; i++) v = (v << 8n) | BigInt(b[i]!);
  if (b[t.start]! & 0x80) v -= 1n << BigInt(8 * n);
  return v;
}

function intIn(b: Uint8Array, t: Tlv | undefined, lo: bigint, hi: bigint): number {
  const v = intOf(b, t);
  if (v < lo || v > hi) throw new Bad();
  return Number(v);
}

function octets(b: Uint8Array, t: Tlv | undefined): Uint8Array {
  if (!t || t.tag !== 0x04) throw new Bad();
  return b.subarray(t.start, t.end);
}

const MAX31 = 2n ** 31n - 1n;
const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");

/** Dotted OID from BER content. README step 1: base-128, no unterminated byte, each ≤ 2^64−1. */
function oidOf(c: Uint8Array): string {
  // README step 1: 1 or more subidentifiers; empty content is malformed
  if (c.length === 0) throw new Bad();
  const subs: bigint[] = [];
  let v = 0n;
  let open = false;
  for (const byte of c) {
    v = (v << 7n) | BigInt(byte & 0x7f);
    if (v > 2n ** 64n - 1n) throw new Bad();
    open = (byte & 0x80) !== 0;
    if (!open) {
      subs.push(v);
      v = 0n;
    }
  }
  if (open) throw new Bad();
  const x = subs[0]!;
  const head = x < 40n ? [0n, x] : x < 80n ? [1n, x - 40n] : [2n, x - 80n];
  return [...head, ...subs.slice(1)].join(".");
}

/** Octet string as text when valid UTF-8 without C0/C1 controls or DEL, else lowercase hex. */
function octetValue(c: Uint8Array): string {
  let s: string;
  try {
    s = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(c);
  } catch {
    return hex(c);
  }
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f-\u009f]/.test(s) ? hex(c) : s;
}

const UNSIGNED: Record<number, string> = { 0x41: "Counter32", 0x42: "Gauge32", 0x43: "TimeTicks", 0x46: "Counter64" };

/** A varbind value as `{type, value}`. README step 1, "Values". */
function value(b: Uint8Array, t: Tlv): { type: string; value: string } {
  const c = b.subarray(t.start, t.end);
  switch (t.tag) {
    case 0x02:
      // README step 1 / RFC 2578: −2^31 to 2^31−1
      return { type: "Integer32", value: String(intIn(b, t, -(2n ** 31n), MAX31)) };
    case 0x04:
      return { type: "OCTET STRING", value: octetValue(c) };
    case 0x05:
      // README step 1 / X.690 §8.8.2: NULL content is empty
      if (c.length !== 0) throw new Bad();
      return { type: "NULL", value: "" };
    case 0x06:
      return { type: "OBJECT IDENTIFIER", value: oidOf(c) };
    case 0x40:
      if (c.length !== 4) throw new Bad();
      return { type: "IpAddress", value: Array.from(c).join(".") };
    case 0x44:
      return { type: "Opaque", value: hex(c) };
    default: {
      const name = UNSIGNED[t.tag];
      if (!name) throw new Bad();
      if (c.length < 1 || c.length > 9 || (c.length === 9 && c[0] !== 0)) throw new Bad();
      let v = 0n;
      for (const x of c) v = (v << 8n) | BigInt(x);
      // README step 1 / RFC 2578: Counter32, Gauge32 and TimeTicks are at most 2^32−1
      if (t.tag !== 0x46 && v > 2n ** 32n - 1n) throw new Bad();
      return { type: name, value: v.toString() };
    }
  }
}

/** A parsed PDU, with the ScopedPDU's contextEngineID. */
export interface Pdu {
  /** The PDU's tag byte. */
  tag: number;
  /** contextEngineID bytes. */
  contextEngineId: Uint8Array;
  /** request-id. */
  requestId: number;
  /** Varbinds as `{oid, type, value}`. */
  varbinds: Json[];
}

/** A ScopedPDU. README step 1, "ScopedPDU" and "PDU". */
function scopedPdu(b: Uint8Array, outer: Tlv | undefined): Pdu {
  const [ctxEngine, ctxName, pduT] = seq(b, outer, 3);
  const contextEngineId = octets(b, ctxEngine);
  octets(b, ctxName);
  const pdu = pduT!;
  const parts = children(b, pdu);
  if (parts.length !== 4) throw new Bad();
  const requestId = intIn(b, parts[0], -(2n ** 31n), MAX31);
  intOf(b, parts[1]);
  intOf(b, parts[2]);
  const list = parts[3]!;
  if (list.tag !== 0x30) throw new Bad();
  const varbinds: Json[] = [];
  for (const vb of children(b, list)) {
    const [o, v] = seq(b, vb, 2);
    if (o!.tag !== 0x06) throw new Bad();
    const oid = oidOf(b.subarray(o!.start, o!.end));
    const tv = value(b, v!);
    varbinds.push({ oid, type: tv.type, value: tv.value });
  }
  return { tag: pdu.tag, contextEngineId, requestId, varbinds };
}

/** A parsed SNMPv3 message (README "SNMPv3 traces", step 1). */
export interface Message {
  /** msgSecurityModel. */
  model: number;
  auth: boolean;
  priv: boolean;
  reportable: boolean;
  engineId: Uint8Array;
  boots: number;
  time: number;
  userName: Uint8Array;
  authParams: Tlv;
  privParams: Uint8Array;
  /** The ScopedPDU, when not encrypted. */
  pdu: Pdu | null;
  /** The encrypted ScopedPDU, when the priv flag is set. */
  encrypted: Uint8Array | null;
}

/**
 * README "SNMPv3 traces", step 1 (`malformed`); throws {@link Bad} on any failure.
 * With `tsm`, README "SNMPv3 over TLS" step 1: `securityParameters` is any OCTET STRING, not
 * read, and `msgData` is always a plaintext ScopedPDU.
 *
 * Spec: E§3; RFC 3412 §6, RFC 3414 §2.4, RFC 5591 §4.2
 */
export function parseMessage(b: Uint8Array, tsm = false): Message {
  const outer = tlv(b, 0, b.length);
  if (outer.end !== b.length) throw new Bad(); // nothing may follow the outer SEQUENCE
  const [ver, global, spT, data] = seq(b, outer, 4);
  if (intOf(b, ver) !== 3n) throw new Bad();
  const [id, max, flagsT, modelT] = seq(b, global, 4);
  intIn(b, id, 0n, MAX31);
  intIn(b, max, 484n, MAX31);
  const flags = octets(b, flagsT);
  if (flags.length !== 1) throw new Bad();
  const auth = (flags[0]! & 1) !== 0;
  const priv = (flags[0]! & 2) !== 0;
  const reportable = (flags[0]! & 4) !== 0;
  if (priv && !auth) throw new Bad();
  const model = intIn(b, modelT, 0n, MAX31);
  const spRaw = octets(b, spT);
  if (tsm) {
    // E§3 SNMPv3 over TLS: securityParameters is ignored; TSM never encrypts in the message
    const pdu = scopedPdu(b, data);
    const none = b.subarray(0, 0);
    return { model, auth, priv, reportable, engineId: none, boots: 0, time: 0, userName: none, authParams: spT!, privParams: spRaw.subarray(0, 0), pdu, encrypted: null };
  }
  const spInner = tlv(b, spT!.start, spT!.end);
  if (spInner.end !== spT!.end) throw new Bad();
  const [eid, bootsT, timeT, userT, authT, privT] = seq(b, spInner, 6);
  const engineId = octets(b, eid);
  if (engineId.length !== 0 && (engineId.length < 5 || engineId.length > 32)) throw new Bad();
  const boots = intIn(b, bootsT, 0n, MAX31);
  const time = intIn(b, timeT, 0n, MAX31);
  const userName = octets(b, userT);
  if (userName.length > 32) throw new Bad();
  octets(b, authT);
  const privParams = octets(b, privT);
  let pdu: Pdu | null = null;
  let encrypted: Uint8Array | null = null;
  if (priv) encrypted = octets(b, data);
  else pdu = scopedPdu(b, data);
  return { model, auth, priv, reportable, engineId, boots, time, userName, authParams: authT!, privParams, pdu, encrypted };
}

// ---------------------------------------------------------------------------------------------
// The receiver

interface User {
  engine_id: string | null;
  user: string;
  auth: string;
  auth_key?: string;
  auth_password?: string;
  priv: string | null;
  priv_key?: string;
  priv_password?: string;
}

interface Engine {
  boots: number;
  time: number;
  latest: number;
  /** `now` when `time` was cached. */
  at: number;
}

const refused = (reason: string, report = false): JsonObject => ({ refused: { reason, report } });

/**
 * A gateway's USM receiver: one `receive` gives exactly one `accepted` or `refused`, and the
 * non-authoritative engine cache is reported after every step.
 *
 * Spec: E§3 — USM only, authNoPriv or authPriv; checks in RFC 3414 §3.2 order, the first
 * failure reported; a trap's authoritative engine is the device, an inform's the gateway
 * (RFC 3412 §7.2); the first authenticated trap from an engine seeds its cache entry.
 * README "SNMPv3 traces": the ten steps, their reasons and `report` flags.
 * README step 4: a userName that is not valid UTF-8 matches no configured user (`unknown-user`).
 */
export class UsmReceiver {
  private now: number;
  private readonly start: number;
  private readonly local: { engine_id: string; boots: number; time: number };
  private readonly users: User[];
  private readonly engines = new Map<string, Engine>();

  /** A receiver at `context.now` with `context.local` and `context.users`. */
  constructor(context: JsonObject) {
    this.now = context["now"] as number;
    this.start = this.now;
    const l = context["local"] as JsonObject;
    this.local = { engine_id: (l["engine_id"] as string).toLowerCase(), boots: l["boots"] as number, time: l["time"] as number };
    this.users = context["users"] as unknown as User[];
  }

  /** Apply one event; return `{emit, engines}`. Spec: E§3 */
  step(event: JsonObject): JsonObject {
    const emit: Json[] = [];
    if ("receive" in event) {
      const r = event["receive"] as JsonObject;
      emit.push(this.receive(Buffer.from(r["datagram"] as string, "hex")));
    } else if ("advance" in event) {
      this.now += event["advance"] as number;
    } else {
      throw new Error(`unknown snmpv3 event ${JSON.stringify(event)}`);
    }
    const engines = [...this.engines.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([engine_id, e]) => ({ engine_id, boots: e.boots, time: e.time + (this.now - e.at), latest: e.latest }));
    return { emit, engines } as unknown as JsonObject;
  }

  private receive(b: Uint8Array): JsonObject {
    // 1. malformed
    let m: Message;
    try {
      m = parseMessage(b);
    } catch (e) {
      if (e instanceof Bad) return refused("malformed");
      throw e;
    }
    // 2. RFC 3412 §7.2 step 4: only USM (3)
    if (m.model !== 3) return refused("unsupported-security-model");
    // 3. RFC 3414 §4: discovery
    if (m.engineId.length === 0) return refused("unknown-engine-id", m.reportable);
    // 4. RFC 3414 §3.2 step 3: engine-specific entry first, then a password user for any engine
    const engineHex = hex(m.engineId);
    let name: string | null;
    try {
      name = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(m.userName);
    } catch {
      name = null;
    }
    const user =
      name === null
        ? undefined
        : (this.users.find((u) => u.engine_id !== null && u.engine_id.toLowerCase() === engineHex && u.user === name) ??
          this.users.find((u) => u.engine_id === null && u.user === name));
    if (!user) return refused("unknown-user");
    // 5. RFC 3414 §3.2 step 5; E§3 refuses noAuthNoPriv
    if (!m.auth || (m.priv && !user.priv)) return refused("unsupported-security-level");
    // 6. RFC 3414 §3.2 step 6 / RFC 7860: HMAC over the received bytes, authParams zeroed
    const proto = AUTH[user.auth];
    if (!proto) return refused("wrong-digest");
    const authKey =
      user.auth_key !== undefined
        ? Buffer.from(user.auth_key, "hex")
        : localizePassword(user.auth, Buffer.from(user.auth_password ?? "", "utf8"), m.engineId);
    const ap = m.authParams;
    if (ap.end - ap.start !== proto.mac) return refused("wrong-digest");
    const zeroed = Buffer.from(b);
    zeroed.fill(0, ap.start, ap.end);
    const mac = createHmac(proto.hash, authKey).update(zeroed).digest().subarray(0, proto.mac);
    if (!mac.equals(Buffer.from(b.subarray(ap.start, ap.end)))) return refused("wrong-digest");
    // 7. RFC 3414 §3.2 step 7
    const authoritative = engineHex === this.local.engine_id;
    if (authoritative) {
      const localTime = this.local.time + (this.now - this.start);
      if (this.local.boots === Number(MAX31) || m.boots !== this.local.boots || Math.abs(m.time - localTime) > 150)
        return refused("not-in-time-window", m.reportable);
    } else {
      const cur = this.engines.get(engineHex);
      if (!cur || m.boots > cur.boots || (m.boots === cur.boots && m.time > cur.latest)) {
        this.engines.set(engineHex, { boots: m.boots, time: m.time, latest: m.time, at: this.now });
      }
      const e = this.engines.get(engineHex)!;
      const cachedNow = e.time + (this.now - e.at);
      if (e.boots === Number(MAX31) || m.boots < e.boots || (m.boots === e.boots && m.time < cachedNow - 150))
        return refused("not-in-time-window");
    }
    // 8. RFC 3414 §3.2 step 8 / RFC 3826 §3.1.4
    let pdu: Pdu;
    if (m.priv) {
      if (m.privParams.length !== 8) return refused("decryption-error");
      const key =
        user.priv_key !== undefined
          ? Buffer.from(user.priv_key, "hex").subarray(0, 16)
          : localizePassword(user.auth, Buffer.from(user.priv_password ?? "", "utf8"), m.engineId).subarray(0, 16);
      if (key.length !== 16) return refused("decryption-error");
      const iv = Buffer.alloc(16);
      iv.writeUInt32BE(m.boots, 0);
      iv.writeUInt32BE(m.time, 4);
      Buffer.from(m.privParams).copy(iv, 8);
      const d = createDecipheriv("aes-128-cfb", key, iv);
      const plain = Buffer.concat([d.update(m.encrypted!), d.final()]);
      try {
        const t = tlv(plain, 0, plain.length);
        if (t.end !== plain.length) throw new Bad(); // exactly a ScopedPDU
        pdu = scopedPdu(plain, t);
      } catch (e) {
        if (e instanceof Bad) return refused("decryption-error");
        throw e;
      }
    } else {
      pdu = m.pdu!;
    }
    // 9. E§3: only notifications
    const inform = pdu.tag === 0xa6;
    if (pdu.tag !== 0xa7 && !inform) return refused("not-a-notification");
    // 10. RFC 3412 §7.2: a trap's engine is the device's, an inform's the gateway's
    if (inform !== authoritative) return refused("engine-id-mismatch");
    const trap: JsonObject = { version: "v3", varbinds: pdu.varbinds };
    if (inform) trap["inform"] = { request_id: pdu.requestId };
    return {
      accepted: {
        trap,
        usm: { engine_id: engineHex, user: user.user, level: m.priv ? "authPriv" : "authNoPriv" },
      },
    };
  }
}

