/**
 * Signed syslog for the Device Events Profile: a gateway's RFC 5848 (syslog-sign) collector.
 * Certificate Blocks establish a signer's reboot session, Signature Blocks list the hashes of the
 * messages they sign, and messages from a configured signer are held until a verified Signature
 * Block lists them or the hold runs out.
 *
 * Spec: E§2 (`syslog-signed` basis and its `signed` object), E§3 ("Signed syslog"); RFC 5848,
 * FIPS 186 (DSA). The exact inputs, outputs and order of checks are the vectors README's,
 * "Signed syslog traces" (`context.component: "syslog-sign"`); messages are parsed as
 * `check: "syslog"` does.
 */
import { createHash } from "node:crypto";
import type { Json, JsonObject } from "../did.js";
import { parseSyslog } from "./syslog.js";

// ---------------------------------------------------------------------------------------------
// Encodings: base64, OpenPGP MPIs, DER

/**
 * Padded base64 (RFC 4648 §4), strictly: the standard alphabet only, a length that is a multiple
 * of 4, `=` only as one or two final padding characters. `null` when it is not.
 *
 * Spec: E§3 ("padded base64").
 * README: non-zero unused bits in the last character are accepted (RFC 4648 §3.5).
 * Impl: the empty string is valid base64 of zero bytes (an `HB` token is checked non-empty apart).
 */
export function b64Strict(s: string): Buffer | null {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) return null;
  return Buffer.from(s, "base64");
}

/**
 * A run of OpenPGP MPIs (RFC 4880 §3.2): each a 2-byte big-endian bit count, then ⌈bits/8⌉
 * bytes. Exactly `n` of them must consume `b`, else `null`.
 *
 * Spec: E§3 — the bit count gives only the length; it is not checked against the value (RFC 5848's
 * own example declares 160 bits for a 159-bit `r`).
 */
export function parseMpis(b: Uint8Array, n: number): bigint[] | null {
  const out: bigint[] = [];
  let p = 0;
  for (let i = 0; i < n; i++) {
    if (p + 2 > b.length) return null;
    const bits = (b[p]! << 8) | b[p + 1]!;
    const len = Math.ceil(bits / 8);
    p += 2;
    if (p + len > b.length) return null;
    out.push(toBig(b.subarray(p, p + len)));
    p += len;
  }
  return p === b.length ? out : null;
}

const toBig = (b: Uint8Array): bigint => (b.length === 0 ? 0n : BigInt("0x" + Buffer.from(b).toString("hex")));

/** One DER TLV: tag, content start and end. Spec: none (infrastructure) */
interface Tlv {
  tag: number;
  start: number;
  end: number;
}

/** Reads one DER TLV at `p` (definite lengths only). Spec: none (infrastructure) */
function tlv(b: Uint8Array, p: number, limit: number): Tlv {
  if (p + 2 > limit) throw new Error("der");
  const tag = b[p]!;
  let len = b[p + 1]!;
  p += 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || p + n > limit) throw new Error("der");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + i]!;
    p += n;
  }
  if (p + len > limit) throw new Error("der");
  return { tag, start: p, end: p + len };
}

/** The children of a constructed DER value. Spec: none (infrastructure) */
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

/** A DSA public key. Spec: E§3; FIPS 186 */
interface DsaKey {
  p: bigint;
  q: bigint;
  g: bigint;
  y: bigint;
}

/**
 * The DSA key a PKIX certificate carries (RFC 5280 SubjectPublicKeyInfo; RFC 3279 §2.3.2:
 * `Dss-Parms` p, q, g, and the public key `y` as an INTEGER in the BIT STRING), or `null`.
 *
 * Spec: E§3 — a `C` signer's key is the certificate's.
 * Impl: the algorithm OID is not checked; a certificate whose key does not read as DSA parameters
 * and an INTEGER yields no key, so every signature fails.
 */
function certDsaKey(der: Uint8Array): DsaKey | null {
  try {
    const cert = tlv(der, 0, der.length);
    const tbs = children(der, cert)[0]!;
    const f = children(der, tbs);
    const i = f[0]!.tag === 0xa0 ? 1 : 0; // [0] version is optional
    const spki = children(der, f[i + 5]!); // serial, signature, issuer, validity, subject, spki
    const alg = children(der, spki[0]!);
    const params = children(der, alg[1]!).map((t) => toBig(der.subarray(t.start, t.end)));
    const bits = spki[1]!;
    const y = tlv(der, bits.start + 1, bits.end); // after the unused-bits byte
    if (params.length !== 3) return null;
    return { p: params[0]!, q: params[1]!, g: params[2]!, y: toBig(der.subarray(y.start, y.end)) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// DSA

/** Modular exponentiation. Spec: none (infrastructure) */
function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

/** Modular inverse (extended Euclid); `m` prime. Spec: none (infrastructure) */
function modInv(a: bigint, m: bigint): bigint {
  let [r0, r1] = [((a % m) + m) % m, m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const k = r0 / r1;
    [r0, r1] = [r1, r0 - k * r1];
    [s0, s1] = [s1, s0 - k * s1];
  }
  return ((s0 % m) + m) % m;
}

const bitLen = (n: bigint): number => (n === 0n ? 0 : n.toString(2).length);

/**
 * DSA signature verification (FIPS 186-4 §4.7): `r` and `s` in 1…q−1, the digest's leftmost
 * min(N, outlen) bits taken as `z` (N = q's bit length), and v = ((g^u1 · y^u2) mod p) mod q = r.
 *
 * Spec: E§3 — DSA with the signer's key and the version's hash, the digest truncated to q's bit
 * length as FIPS 186 does.
 */
function dsaVerify(key: DsaKey, digest: Buffer, r: bigint, s: bigint): boolean {
  const { p, q, g, y } = key;
  if (q < 2n || p < 2n) return false;
  if (r <= 0n || r >= q || s <= 0n || s >= q) return false;
  let z = toBig(digest);
  const n = bitLen(q);
  const outlen = digest.length * 8;
  if (outlen > n) z >>= BigInt(outlen - n);
  const w = modInv(s, q);
  const u1 = (z * w) % q;
  const u2 = (r * w) % q;
  const v = ((modPow(g, u1, p) * modPow(y, u2, p)) % p) % q;
  return v === r;
}

// ---------------------------------------------------------------------------------------------
// The collector

/** RFC 5848 §4.2.1 versions this profile supports, with their hash. Spec: E§3 */
const VERSIONS: Record<string, { alg: "sha1" | "sha256"; size: number }> = {
  "0111": { alg: "sha1", size: 20 },
  "0121": { alg: "sha256", size: 32 },
};

/** A refusal: the block type and the README's reason token. Spec: E§3 */
class Refused extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

const hash = (alg: string, b: Uint8Array): Buffer => createHash(alg).update(b).digest();
const sha256hex = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** A configured signer. Spec: E§3 ("Signers are configured") */
interface Signer {
  hostname: string;
  type: string;
  keyBytes: Buffer;
  keySha256: string;
  dsa: DsaKey | null;
}

/** A held message. Spec: E§3 ("Holding") */
interface Held {
  bytes: Buffer;
  sha256: string;
  due: number;
}

/** A signed hash waiting for its message. Spec: E§3 ("Holding") */
interface Waiting {
  sessKey: string;
  groupKey: string;
  number: number;
  alg: string;
  hash: Buffer;
  due: number;
  signed: JsonObject;
  group: Set<number>;
}

/** A reboot session: its established payload and its groups' authenticated numbers. Spec: E§3 */
interface Session {
  payload: Buffer | null;
  groups: Map<string, Set<number>>;
  /** Fragments being assembled: `TPBL` and the stored (INDEX, bytes). */
  tpbl: number | null;
  frags: { index: number; bytes: Buffer }[];
}

/** The block element's parameters, raw positions of the SIGN parameter included. Spec: E§3 */
interface Block {
  id: "ssign" | "ssign-cert";
  params: Map<string, string>;
  raw: Map<string, Buffer>;
  signedBytes: Buffer;
}

const SSIGN = ["VER", "RSID", "SG", "SPRI", "GBC", "FMN", "CNT", "HB", "SIGN"];
const SSIGN_CERT = ["VER", "RSID", "SG", "SPRI", "TPBL", "INDEX", "FLEN", "FRAG", "SIGN"];

/**
 * Decimal with no leading zeros (`0` alone allowed), at most `digits` digits, within `[min, max]`.
 * Spec: E§3 (the README's `malformed-block` numbers)
 */
function num(v: string | undefined, digits: number, min: number, max = Infinity): number {
  if (v === undefined || !/^(0|[1-9][0-9]*)$/.test(v) || v.length > digits) throw new Refused("malformed-block");
  const n = Number(v);
  if (n < min || n > max) throw new Refused("malformed-block");
  return n;
}

/**
 * Locates the block's SD element in the raw message and returns the signed bytes: the message
 * with ` SIGN="<value>"` removed. Also returns each parameter's raw (unescaped) value bytes.
 *
 * Spec: E§3 ("The signed bytes") — the element starts with the `[` after the sixth space of the
 * message and closes at the first `]` outside a quoted value (inside quotes, `\` escapes the next
 * byte, README); ` SIGN="…"` is the last thing before that `]`.
 * Impl: values are unescaped as RFC 5424 §6.3.3 does (`\"`, `\\`, `\]`; any other backslash is
 * kept), as `check: "syslog"` does; FLEN counts these unescaped bytes. The removed span is the raw
 * one, escapes included.
 */
function locate(m: Buffer): { raw: Map<string, Buffer>; signedBytes: Buffer } {
  let p = 0;
  for (let spaces = 0; spaces < 6; p++) {
    if (p >= m.length) throw new Refused("malformed-block");
    if (m[p] === 0x20) spaces++;
  }
  if (m[p] !== 0x5b) throw new Refused("malformed-block");
  p++;
  while (p < m.length && m[p] !== 0x20 && m[p] !== 0x5d) p++;
  const raw = new Map<string, Buffer>();
  let signStart = -1;
  let signEnd = -1;
  while (m[p] === 0x20) {
    const sp = p;
    p++;
    const ns = p;
    while (p < m.length && m[p] !== 0x3d) p++;
    const name = m.subarray(ns, p).toString("latin1");
    p += 2; // `="`
    const v: number[] = [];
    while (p < m.length && m[p] !== 0x22) {
      const c = m[p]!;
      if (c === 0x5c && p + 1 < m.length) {
        const nx = m[p + 1]!;
        if (nx === 0x22 || nx === 0x5c || nx === 0x5d) v.push(nx);
        else v.push(c, nx);
        p += 2;
        continue;
      }
      v.push(c);
      p++;
    }
    p++; // closing quote
    if (!raw.has(name)) raw.set(name, Buffer.from(v));
    if (name === "SIGN") {
      signStart = sp;
      signEnd = p;
    }
  }
  if (m[p] !== 0x5d || signEnd !== p) throw new Refused("malformed-block");
  return { raw, signedBytes: Buffer.concat([m.subarray(0, signStart), m.subarray(signEnd)]) };
}

/**
 * The README's `malformed-block` checks of a block's SD element (only element; exact parameters
 * in order; numbers; `VER`; `SIGN`; `HB`; `FRAG`), returning the parsed block, `r` and `s`.
 *
 * Spec: E§3; RFC 5848 §4.2 (Signature Block), §4.2.8 (Certificate Block).
 * README: `HB` tokens are non-empty, so two spaces between hashes are malformed whatever the
 * version. For an unsupported `VER` the hash tokens are still checked as base64, not for size.
 */
function parseBlock(m: Buffer, sd: { id: string; params: { name: string; value: string }[] }[]): {
  block: Block;
  r: bigint;
  s: bigint;
} {
  const el = sd.find((e) => e.id === "ssign" || e.id === "ssign-cert")!;
  if (sd.length !== 1) throw new Refused("malformed-block");
  const want = el.id === "ssign" ? SSIGN : SSIGN_CERT;
  const names = el.params.map((x) => x.name);
  if (names.length !== want.length || names.some((n, i) => n !== want[i])) throw new Refused("malformed-block");
  const params = new Map(el.params.map((x) => [x.name, x.value]));
  const { raw, signedBytes } = locate(m);
  num(params.get("RSID"), 10, 0);
  num(params.get("SG"), 1, 0, 3);
  num(params.get("SPRI"), 3, 0, 191);
  if (el.id === "ssign") {
    num(params.get("GBC"), 10, 0);
    num(params.get("FMN"), 10, 1);
    num(params.get("CNT"), 2, 1, 99);
  } else {
    num(params.get("TPBL"), 8, 1);
    num(params.get("INDEX"), 8, 1);
    num(params.get("FLEN"), 4, 1);
  }
  const ver = params.get("VER")!;
  if ([...ver].length !== 4) throw new Refused("malformed-block");
  const sig = b64Strict(params.get("SIGN")!);
  const rs = sig === null ? null : parseMpis(sig, 2);
  if (rs === null) throw new Refused("malformed-block");
  if (el.id === "ssign") {
    const toks = params.get("HB")!.split(" ");
    if (toks.length !== Number(params.get("CNT"))) throw new Refused("malformed-block");
    for (const t of toks) {
      const d = t === "" ? null : b64Strict(t);
      if (d === null) throw new Refused("malformed-block");
      const v = VERSIONS[ver];
      if (v !== undefined && d.length !== v.size) throw new Refused("malformed-block");
    }
  } else {
    const frag = raw.get("FRAG")!;
    const index = Number(params.get("INDEX"));
    const flen = Number(params.get("FLEN"));
    if (frag.length !== flen || index + flen - 1 > Number(params.get("TPBL"))) throw new Refused("malformed-block");
  }
  return { block: { id: el.id as Block["id"], params, raw, signedBytes }, r: rs[0]!, s: rs[1]! };
}

/**
 * A signed syslog collector (`context.component: "syslog-sign"`), one `{emit, held, waiting}`
 * per step.
 *
 * Spec: E§3 ("Signed syslog"); the README's "Signed syslog traces".
 */
export class SyslogSignCollector {
  private now: number;
  private readonly holdS: number;
  private readonly signers: Signer[] = [];
  private held: Held[] = [];
  private waiting: Waiting[] = [];
  /** Sessions by (configured hostname, APP-NAME, PROCID, RSID). */
  private readonly sessions = new Map<string, Session>();
  /** The highest RSID ever established per (configured hostname, APP-NAME). */
  private readonly highest = new Map<string, number>();

  /** Spec: E§3 — the configured signers, `now` and `H` (`hold_s`, default 10). */
  constructor(context: JsonObject) {
    this.now = (context["now"] as number) ?? 0;
    this.holdS = (context["hold_s"] as number | undefined) ?? 10;
    for (const s of (context["signers"] as JsonObject[]) ?? []) {
      const type = s["type"] as string;
      const keyBytes = Buffer.from(s["key"] as string, "base64");
      let dsa: DsaKey | null = null;
      if (type === "K") {
        const m = parseMpis(keyBytes, 4);
        if (m !== null) dsa = { p: m[0]!, q: m[1]!, g: m[2]!, y: m[3]! };
      } else if (type === "C") {
        dsa = certDsaKey(keyBytes);
      }
      this.signers.push({ hostname: s["hostname"] as string, type, keyBytes, keySha256: sha256hex(keyBytes), dsa });
    }
  }

  /** The signer whose hostname equals `h` without (ASCII) case. Spec: E§3 */
  private signer(h: string | null): Signer | undefined {
    if (h === null) return undefined;
    const l = asciiLower(h);
    return this.signers.find((s) => asciiLower(s.hostname) === l);
  }

  /** One step: `{receive: {message}}` or `{advance: n}`. Spec: E§3 */
  step(event: JsonObject): JsonObject {
    const emit: Json[] = [];
    if ("receive" in event) {
      const m = Buffer.from((event["receive"] as JsonObject)["message"] as string, "hex");
      this.receive(m, emit);
    } else if ("advance" in event) {
      this.advance(event["advance"] as number, emit);
    } else {
      throw new Error(`unknown syslog-sign event ${JSON.stringify(event)}`);
    }
    return { emit, held: this.held.map((h) => h.sha256), waiting: this.waiting.length };
  }

  /**
   * `advance`: `now += n`; held messages due are deposited unsigned in arrival order; waiting
   * hashes due are dropped silently. Spec: E§3 ("Holding")
   */
  private advance(n: number, emit: Json[]): void {
    this.now += n;
    const keep: Held[] = [];
    for (const h of this.held) {
      if (h.due <= this.now) emit.push({ deposit: { sha256: h.sha256, signed: null } });
      else keep.push(h);
    }
    this.held = keep;
    this.waiting = this.waiting.filter((w) => w.due > this.now);
  }

  /**
   * Classifies a received message: not RFC 5424 or a nil HOSTNAME is deposited unsigned; a block
   * is processed and never deposited; a configured signer's message is matched against the
   * waiting hashes, else held; anything else is deposited unsigned.
   *
   * Spec: E§3 ("Holding"; "Block messages are never deposited").
   * README: the first `ssign` or `ssign-cert` element names the block (a message with two is
   * `malformed-block` either way).
   */
  private receive(m: Buffer, emit: Json[]): void {
    const parsed = parseSyslog(m)["syslog"] as JsonObject | undefined;
    const sha = sha256hex(m);
    if (parsed === undefined || parsed["format"] !== "rfc5424" || parsed["hostname"] === null) {
      emit.push({ deposit: { sha256: sha, signed: null } });
      return;
    }
    const sd = parsed["structured_data"] as unknown as { id: string; params: { name: string; value: string }[] }[];
    const blockEl = sd.find((e) => e.id === "ssign" || e.id === "ssign-cert");
    if (blockEl !== undefined) {
      try {
        this.block(m, parsed, sd);
      } catch (e) {
        if (!(e instanceof Refused)) throw e;
        emit.push({ refused: { block: blockEl.id, reason: e.reason } });
      }
      this.pending.forEach((x) => emit.push(x));
      this.pending = [];
      return;
    }
    if (this.signer(parsed["hostname"] as string) === undefined) {
      emit.push({ deposit: { sha256: sha, signed: null } });
      return;
    }
    // README: match on the waiting entry's algorithm; the earliest added wins
    const i = this.waiting.findIndex((w) => hash(w.alg, m).equals(w.hash));
    if (i >= 0) {
      const w = this.waiting[i]!;
      this.waiting.splice(i, 1);
      w.group.add(w.number);
      emit.push({ deposit: { sha256: sha, signed: w.signed } });
      return;
    }
    this.held.push({ bytes: m, sha256: sha, due: this.now + this.holdS });
  }

  /** Emits a block produces before (or instead of) a refusal. */
  private pending: Json[] = [];

  /**
   * A block, checked in the README's order: `malformed-block`, `unsupported-version`,
   * `unknown-signer`, `bad-signature`, `old-session`; then the Certificate Block or Signature
   * Block rules.
   *
   * Spec: E§3; RFC 5848 §4.1 (a rebooted signer may take a new PROCID, keeping its APP-NAME).
   * README: the `old-session` floor counts every RSID ever established for the signer and APP-NAME,
   * including sessions since ended by a new payload.
   */
  private block(m: Buffer, parsed: JsonObject, sd: { id: string; params: { name: string; value: string }[] }[]): void {
    const { block, r, s } = parseBlock(m, sd);
    const ver = VERSIONS[block.params.get("VER")!];
    if (ver === undefined) throw new Refused("unsupported-version");
    const signer = this.signer(parsed["hostname"] as string);
    if (signer === undefined) throw new Refused("unknown-signer");
    if (signer.dsa === null || !dsaVerify(signer.dsa, hash(ver.alg, block.signedBytes), r, s)) {
      throw new Refused("bad-signature");
    }
    const host = asciiLower(signer.hostname);
    const app = parsed["app_name"] as string | null;
    const procid = parsed["procid"] as string | null;
    const rsid = Number(block.params.get("RSID"));
    const signerKey = JSON.stringify([host, app]);
    const top = this.highest.get(signerKey);
    if (rsid > 0 && top !== undefined && rsid < top) throw new Refused("old-session");
    const sessKey = JSON.stringify([host, app, procid, rsid]);
    if (block.id === "ssign-cert") {
      this.certificate(block, sessKey, signer, parsed, rsid, signerKey);
    } else {
      this.signature(block, sessKey, signer, parsed, rsid, ver.alg);
    }
  }

  /**
   * A Certificate Block fragment: ignored when it repeats the established payload; otherwise it
   * ends an established session and is assembled; a complete payload must name the configured
   * key, and then the session is established.
   *
   * Spec: E§3 ("A Certificate Block's FRAG is the payload text itself"); RFC 5848 §4.2.8.
   * The README: any other fragment ends the session, dropping its authenticated numbers and its
   * waiting hashes; the `old-session` floor stays.
   * Impl: a fragment "equals the established payload's" only when its TPBL is also the payload's
   * length. The payload's timestamp is any non-empty run without spaces.
   */
  private certificate(block: Block, sessKey: string, signer: Signer, parsed: JsonObject, rsid: number, signerKey: string): void {
    const tpbl = Number(block.params.get("TPBL"));
    const index = Number(block.params.get("INDEX"));
    const frag = block.raw.get("FRAG")!;
    let sess = this.sessions.get(sessKey);
    if (sess === undefined) {
      sess = { payload: null, groups: new Map(), tpbl: null, frags: [] };
      this.sessions.set(sessKey, sess);
    }
    if (sess.payload !== null) {
      const pl = sess.payload;
      if (tpbl === pl.length && pl.subarray(index - 1, index - 1 + frag.length).equals(frag)) return;
      // README: ending the session drops its authenticated numbers and its waiting hashes
      sess.payload = null;
      sess.groups = new Map();
      sess.tpbl = null;
      sess.frags = [];
      this.waiting = this.waiting.filter((w) => w.sessKey !== sessKey);
    }
    if (sess.tpbl !== null && sess.tpbl !== tpbl) throw new Refused("fragment-mismatch");
    for (const f of sess.frags) {
      const lo = Math.max(f.index, index);
      const hi = Math.min(f.index + f.bytes.length, index + frag.length);
      for (let k = lo; k < hi; k++) {
        if (f.bytes[k - f.index] !== frag[k - index]) throw new Refused("fragment-mismatch");
      }
    }
    sess.tpbl = tpbl;
    sess.frags.push({ index, bytes: frag });
    const cover = new Uint8Array(tpbl);
    const assembled = Buffer.alloc(tpbl);
    for (const f of sess.frags) {
      cover.fill(1, f.index - 1, f.index - 1 + f.bytes.length);
      f.bytes.copy(assembled, f.index - 1);
    }
    if (!cover.every((c) => c === 1)) return;
    sess.tpbl = null;
    sess.frags = [];
    const fields = assembled.toString("latin1").split(" ");
    const keyB = fields.length === 3 && fields[0] !== "" ? b64Strict(fields[2]!) : null;
    if (keyB === null || fields[1] !== signer.type || !keyB.equals(signer.keyBytes)) {
      throw new Refused("payload-mismatch");
    }
    sess.payload = assembled;
    sess.groups = new Map();
    this.highest.set(signerKey, Math.max(this.highest.get(signerKey) ?? 0, rsid));
    this.pending.push({
      session: {
        hostname: parsed["hostname"] as string,
        app_name: parsed["app_name"] as string | null,
        procid: parsed["procid"] as string | null,
        rsid,
        key_sha256: signer.keySha256,
      },
    });
  }

  /**
   * A Signature Block: hash `i` is message number FMN + i in the group (session, SG, SPRI). An
   * authenticated number is skipped; else the earliest held message with that hash is deposited
   * signed; else the hash waits (once per group and number).
   *
   * Spec: E§3 ("Signature Blocks", "Holding"); RFC 5848 §4.2.6–§4.2.7.
   * A message matched later by a waiting hash makes that number authenticated (README).
   */
  private signature(block: Block, sessKey: string, signer: Signer, parsed: JsonObject, rsid: number, alg: string): void {
    const sess = this.sessions.get(sessKey);
    if (sess === undefined || sess.payload === null) throw new Refused("no-session");
    const sg = Number(block.params.get("SG"));
    const spri = Number(block.params.get("SPRI"));
    const fmn = Number(block.params.get("FMN"));
    const gk = JSON.stringify([sg, spri]);
    let group = sess.groups.get(gk);
    if (group === undefined) {
      group = new Set();
      sess.groups.set(gk, group);
    }
    const groupKey = sessKey + gk;
    const hashes = block.params.get("HB")!.split(" ").map((t) => Buffer.from(t, "base64"));
    hashes.forEach((h, i) => {
      const n = fmn + i;
      if (group!.has(n)) return;
      const signed: JsonObject = {
        hostname: parsed["hostname"] as string,
        app_name: parsed["app_name"] as string | null,
        procid: parsed["procid"] as string | null,
        rsid,
        sg,
        spri,
        message_number: n,
        key_sha256: signer.keySha256,
      };
      const k = this.held.findIndex((x) => hash(alg, x.bytes).equals(h));
      if (k >= 0) {
        const x = this.held[k]!;
        this.held.splice(k, 1);
        group!.add(n);
        this.pending.push({ deposit: { sha256: x.sha256, signed } });
        return;
      }
      if (this.waiting.some((w) => w.groupKey === groupKey && w.number === n)) return;
      this.waiting.push({ sessKey, groupKey, number: n, alg, hash: h, due: this.now + this.holdS, signed, group: group! });
    });
  }
}
