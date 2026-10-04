/**
 * Resolving a `did:webvh` v1.0 DID from its verifiable history log, offline.
 *
 * Spec: §7.2, §8.4 (v0.9: `did:webvh` as a recommended method beside `did:web`); did:webvh v1.0
 * (https://identity.foundation/didwebvh/v1.0/) for the log, SCID, entryHash, pre-rotation and
 * witness rules; RFC 8785 for JCS.
 * Impl: the check order, the reason tokens, the 300 s versionTime tolerance, v1.0-only `method`,
 * the cache's rollback/fork rule and the restricted JCS are DSIP choices the vectors README encodes
 * (`impl/vectors/README.md`, "Kind: `did-webvh`"; spec-gap 101).
 */
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { Json, JsonObject } from "../did.js";
import { base58Decode, base58Encode, ed25519FromMultibase } from "../encoding.js";

/** The resolver's input. Spec: §8.4; README "Kind: `did-webvh`" */
export interface WebvhInput {
  /** The requested DID. */
  did: string;
  /** The `did.jsonl` text. */
  log: string;
  /** The `did-witness.json` text, or `null`. */
  witness: string | null;
  /** The highest versionId this resolver verified before, or `null`. */
  cache: { versionId: string } | null;
  /** The resolver's clock, integer Unix seconds. */
  now: number;
}

/** A failed check: its reason token. */
class Rejected extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

function fail(reason: string): never {
  throw new Rejected(reason);
}

const isObject = (v: Json | undefined): v is JsonObject => typeof v === "object" && v !== null && !Array.isArray(v);
const B58CHARS = /^[1-9A-HJ-NP-Za-km-z]+$/;

/**
 * RFC 8785 JCS over the values a log holds: objects, arrays, strings, integers, booleans, null.
 *
 * Spec: RFC 8785 §3.2. Impl: restricted as the vectors README defines it — keys sorted by UTF-16 code
 * units, strings escape only `"`, `\` and U+0000–U+001F, everything else is raw UTF-8.
 */
export function jcs(value: Json): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("JCS: non-integer number");
    return String(value);
  }
  if (typeof value === "string") return jcsString(value);
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  // default sort compares UTF-16 code units
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => jcsString(k) + ":" + jcs(value[k]!)).join(",") + "}";
}

const SHORT: Record<number, string> = { 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r" };

function jcsString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c < 0x20) out += SHORT[c] ?? "\\u00" + c.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out + '"';
}

const sha256 = (data: Buffer | string): Buffer => createHash("sha256").update(data).digest();

/** base58btc of a sha2-256 multihash (0x12 0x20 ‖ digest). did:webvh v1.0 §SCID / §entryHash */
function multihash(data: Buffer | string): string {
  return base58Encode(Buffer.concat([Buffer.from([0x12, 0x20]), sha256(data)]));
}

/** True when `text` is base58btc of a sha2-256 multihash. */
function isMultihash(text: Json | undefined): boolean {
  if (typeof text !== "string" || !B58CHARS.test(text)) return false;
  const raw = base58Decode(text);
  return raw !== null && raw.length === 34 && raw[0] === 0x12 && raw[1] === 0x20;
}

const isEd25519Multikey = (v: Json | undefined): v is string => typeof v === "string" && ed25519FromMultibase(v) !== null;

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

function ed25519Verify(key: Buffer, message: Buffer, signature: Buffer): boolean {
  if (signature.length !== 64) return false;
  try {
    const pub = createPublicKey({ key: Buffer.concat([SPKI_ED25519, key]), format: "der", type: "spki" });
    return cryptoVerify(null, message, pub, signature);
  } catch {
    return false;
  }
}

/** `did:key:<mk>#<mk>` with identical parts: the multikey, else `null`. */
function didKeyMethod(vm: Json | undefined): string | null {
  if (typeof vm !== "string" || !vm.startsWith("did:key:")) return null;
  const rest = vm.slice("did:key:".length);
  const hash = rest.indexOf("#");
  if (hash < 0) return null;
  const [body, fragment] = [rest.slice(0, hash), rest.slice(hash + 1)];
  return body.length > 0 && body === fragment ? body : null;
}

/**
 * Verify an eddsa-jcs-2022 DataIntegrityProof by `key` over `document`.
 *
 * Spec: did:webvh v1.0 §Data Integrity; VC-DI-EdDSA eddsa-jcs-2022 — the signature covers
 * `sha256(JCS(proof without proofValue)) ‖ sha256(JCS(document))`.
 */
function proofVerifies(proof: JsonObject, key: string, document: Json): boolean {
  if (proof["type"] !== "DataIntegrityProof" || proof["cryptosuite"] !== "eddsa-jcs-2022") return false;
  if (proof["proofPurpose"] !== "assertionMethod") return false;
  const pv = proof["proofValue"];
  if (typeof pv !== "string" || !pv.startsWith("z") || !B58CHARS.test(pv.slice(1))) return false;
  const signature = base58Decode(pv.slice(1));
  const pub = ed25519FromMultibase(key);
  if (!signature || !pub) return false;
  const config: JsonObject = { ...proof };
  delete config["proofValue"];
  const message = Buffer.concat([sha256(jcs(config)), sha256(jcs(document))]);
  return ed25519Verify(pub, message, signature);
}

/** A parsed did:webvh DID: its SCID. Spec: did:webvh v1.0 §DID format; README check 1 */
function parseDid(did: Json | undefined): { scid: string } | null {
  if (typeof did !== "string" || !did.startsWith("did:webvh:")) return null;
  const parts = did.slice("did:webvh:".length).split(":");
  if (parts.length < 2) return null;
  const [scid, domain, ...path] = parts as [string, string, ...string[]];
  if (scid.length !== 46 || !B58CHARS.test(scid)) return null;
  if (!validDomain(domain)) return null;
  return path.every(validSegment) ? { scid } : null;
}

function validDomain(domain: string): boolean {
  // Impl: the port separator is the literal `%3A` the README writes (spec finding: `%3a`).
  const at = domain.indexOf("%3A");
  const host = at < 0 ? domain : domain.slice(0, at);
  if (at >= 0) {
    const port = domain.slice(at + 3);
    if (!/^[0-9]{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) return false;
  }
  const labels = host.split(".");
  if (labels.length < 2 || !labels.every((l) => /^[A-Za-z0-9-]{1,63}$/.test(l))) return false;
  return !labels.every((l) => /^[0-9]+$/.test(l));
}

function validSegment(segment: string): boolean {
  if (!/^([A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$/.test(segment)) return false;
  const bytes: number[] = [];
  for (let i = 0; i < segment.length; i++) {
    if (segment[i] === "%") {
      bytes.push(parseInt(segment.slice(i + 1, i + 3), 16));
      i += 2;
    } else bytes.push(segment.charCodeAt(i));
  }
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
  } catch {
    return false; // Impl: a segment that does not decode to UTF-8 is invalid (spec finding)
  }
  if (decoded === "." || decoded === "..") return false;
  if (/[/\\\u0000]/.test(decoded)) return false;
  return !WHITE_SPACE_START.test(decoded) && !WHITE_SPACE_END.test(decoded);
}

// Unicode White_Space, as the README lists it; U+FEFF is not in it (so not String.prototype.trim).
const WS = "\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000";
const WHITE_SPACE_START = new RegExp(`^[${WS}]`);
const WHITE_SPACE_END = new RegExp(`[${WS}]$`);

const MAX_SAFE = 2n ** 53n - 1n;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Parse `text` as I-JSON (RFC 7493): JSON with no duplicate member names, no lone surrogates
 * (escaped or raw), and integers only, within ±(2^53−1), written without fraction or exponent.
 * `null` when it is not.
 *
 * Spec: RFC 7493 §2.1–2.3 (RFC 8785 requires I-JSON input); README "Kind: `did-webvh`" checks 3 and 13.
 */
export function parseIJson(text: string): Json | null {
  let value: Json;
  try {
    value = JSON.parse(text) as Json;
  } catch {
    return null;
  }
  // `text` is valid JSON: a lexical walk sees every name, string and number exactly as written.
  const stack: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < text.length; ) {
    const c = text[i]!;
    if (c === "{") {
      stack.push(new Set());
      expectKey = true;
      i++;
    } else if (c === "[") {
      stack.push(null);
      expectKey = false;
      i++;
    } else if (c === "}" || c === "]") {
      stack.pop();
      i++;
    } else if (c === ",") {
      expectKey = stack[stack.length - 1] instanceof Set;
      i++;
    } else if (c === ":") {
      expectKey = false;
      i++;
    } else if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const str = JSON.parse(text.slice(i, j + 1)) as string;
      if (LONE_SURROGATE.test(str)) return null;
      if (expectKey) {
        const names = stack[stack.length - 1] as Set<string>;
        if (names.has(str)) return null;
        names.add(str);
        expectKey = false;
      }
      i = j + 1;
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i;
      while (j < text.length && /[-+0-9.eE]/.test(text[j]!)) j++;
      const lexeme = text.slice(i, j);
      if (!/^-?(0|[1-9][0-9]*)$/.test(lexeme)) return null;
      const n = BigInt(lexeme);
      if (n > MAX_SAFE || n < -MAX_SAFE) return null;
      i = j;
    } else i++;
  }
  return value;
}

const ENTRY_KEYS = ["parameters", "proof", "state", "versionId", "versionTime"];
const PARAMETER_KEYS = new Set([
  "method", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "portable", "deactivated", "ttl",
]);
const DEFAULTS: JsonObject = { nextKeyHashes: [], witness: {}, watchers: [], portable: false, deactivated: false, ttl: 3600 };
const TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/;

/** A versionTime as `[seconds, nanoseconds]`, or `null`. README check 5 */
function parseTime(t: Json | undefined): [number, number] | null {
  if (typeof t !== "string") return null;
  const m = TIME.exec(t);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const back = new Date(ms);
  // Impl: a calendar-invalid time (month 13, Feb 30, second 60) does not match (spec finding).
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) return null;
  if (h > 23 || mi > 59 || s > 59) return null;
  return [Math.floor(ms / 1000), Number((m[7] ?? "").padEnd(9, "0"))];
}

const later = (a: [number, number], b: [number, number]) => a[0] > b[0] || (a[0] === b[0] && a[1] > b[1]);

/** README check 6: the shape of one entry's parameters. */
function checkParameters(p: JsonObject, n: number): void {
  for (const k of Object.keys(p)) if (!PARAMETER_KEYS.has(k)) fail("parameters");
  if (n === 1 && !("method" in p && "scid" in p && "updateKeys" in p)) fail("parameters");
  if (n > 1 && "scid" in p) fail("parameters");
  if ("method" in p && p["method"] !== "did:webvh:1.0") fail("parameters");
  if ("scid" in p && !isMultihash(p["scid"])) fail("parameters");
  for (const k of ["updateKeys", "nextKeyHashes", "watchers"]) {
    if (k in p && !(Array.isArray(p[k]) && (p[k] as Json[]).every((x) => typeof x === "string"))) fail("parameters");
  }
  if ("updateKeys" in p && !(p["updateKeys"] as Json[]).every(isEd25519Multikey)) fail("parameters");
  for (const k of ["portable", "deactivated"]) if (k in p && typeof p[k] !== "boolean") fail("parameters");
  if ("ttl" in p) {
    const ttl = p["ttl"];
    if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 0 || ttl > 2 ** 31) fail("parameters");
  }
  if (n > 1 && p["portable"] === true) fail("parameters");
  if ("witness" in p) {
    const w = p["witness"];
    if (!isObject(w)) fail("parameters");
    const keys = Object.keys(w).sort();
    if (keys.length > 0) {
      if (keys.join(",") !== "threshold,witnesses") fail("parameters");
      const list = w["witnesses"];
      if (!Array.isArray(list) || list.length === 0) fail("parameters");
      const ids = list.map((e) => (isObject(e) ? e["id"] : undefined));
      for (const id of ids) {
        if (typeof id !== "string" || !id.startsWith("did:key:") || !isEd25519Multikey(id.slice(8))) fail("parameters");
      }
      if (new Set(ids).size !== ids.length) fail("parameters");
      const t = w["threshold"];
      if (typeof t !== "number" || !Number.isInteger(t) || t < 1 || t > list.length) fail("parameters");
    }
  }
}

const withoutProof = (entry: JsonObject): JsonObject => {
  const copy: JsonObject = { ...entry };
  delete copy["proof"];
  return copy;
};

/**
 * Resolve `input.did` from its log: the README's checks 1–14 in order, then the outcome.
 *
 * Spec: §7.2, §8.4; did:webvh v1.0 §Read (Resolve).
 * Impl: README "Kind: `did-webvh`" (spec-gap 101) fixes the order and the tokens.
 */
export function resolveWebvh(input: WebvhInput): JsonObject {
  try {
    return resolve(input);
  } catch (e) {
    if (e instanceof Rejected) return { outcome: "rejected", reason: e.reason };
    throw e;
  }
}

function resolve(input: WebvhInput): JsonObject {
  // 1. the requested DID
  const requested = parseDid(input.did);
  if (!requested) fail("invalid-did");

  // 2. the log is not empty; a single trailing newline is ignored
  const text = input.log.endsWith("\n") ? input.log.slice(0, -1) : input.log;
  if (text === "") fail("log-malformed");
  const lines = text.split("\n");

  const entries: JsonObject[] = [];
  const actives: JsonObject[] = []; // active parameters after each entry
  let active: JsonObject = { ...DEFAULTS };
  let prevTime: [number, number] | null = null;
  let scid = "";

  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    const previous = active;

    // 3. structure
    const entry = parseIJson(lines[i]!);
    if (!isObject(entry)) fail("log-malformed");
    if (Object.keys(entry).sort().join(",") !== ENTRY_KEYS.join(",")) fail("log-malformed");
    if (!isObject(entry["state"])) fail("log-malformed");
    if (!Array.isArray(entry["proof"]) || entry["proof"].length === 0) fail("log-malformed");
    const versionId = entry["versionId"];
    if (typeof versionId !== "string") fail("log-malformed");

    // 4. versionId: number n, then a sha2-256 multihash
    const vm = /^([1-9][0-9]*)-([1-9A-HJ-NP-Za-km-z]+)$/.exec(versionId);
    if (!vm || vm[1] !== String(n)) fail("version-number");
    const entryHash = vm[2]!;
    if (!isMultihash(entryHash)) fail("entry-hash");

    // 5. versionTime
    const time = parseTime(entry["versionTime"]);
    if (!time) fail("version-time");
    if (prevTime && !later(time, prevTime)) fail("version-time");
    if (later(time, [input.now + 300, 0])) fail("version-time");
    prevTime = time;

    // 6. parameters
    if (previous["deactivated"] === true) fail("after-deactivation");
    const params = entry["parameters"];
    if (!isObject(params)) fail("parameters");
    checkParameters(params, n);
    active = { ...previous, ...params };

    // 7. SCID (entry 1)
    if (n === 1) {
      scid = params["scid"] as string;
      const preliminary = withoutProof(entry);
      preliminary["versionId"] = "{SCID}";
      const replaced = jcs(preliminary).split(scid).join("{SCID}");
      if (multihash(jcs(JSON.parse(replaced) as Json)) !== scid) fail("scid");
    }

    // 8. entryHash
    const hashed = withoutProof(entry);
    hashed["versionId"] = n === 1 ? scid : (entries[i - 1]!["versionId"] as string);
    if (multihash(jcs(hashed)) !== entryHash) fail("entry-hash");

    // 9. pre-rotation
    const preRotation = n > 1 && (previous["nextKeyHashes"] as Json[]).length > 0;
    if (preRotation) {
      if (!("updateKeys" in params && "nextKeyHashes" in params)) fail("pre-rotation");
      const committed = previous["nextKeyHashes"] as Json[];
      for (const key of params["updateKeys"] as string[]) {
        if (!committed.includes(multihash(Buffer.from(key, "utf8")))) fail("pre-rotation");
      }
    }

    // 10. proofs
    const authorised = (n === 1 || preRotation ? params["updateKeys"] : previous["updateKeys"]) as string[];
    const document = withoutProof(entry);
    let signed = false;
    for (const proof of entry["proof"] as Json[]) {
      const mk = isObject(proof) ? didKeyMethod(proof["verificationMethod"]) : null;
      if (!mk) fail("proof");
      if (!authorised.includes(mk)) continue;
      if (!proofVerifies(proof as JsonObject, mk, document)) fail("proof");
      signed = true;
    }
    if (!signed) fail("unauthorized-key");

    // 11. state.id
    const id = (entry["state"] as JsonObject)["id"];
    const parsed = parseDid(id);
    if (!parsed || parsed.scid !== scid) fail("identity");
    if (n > 1) {
      const prevId = (entries[i - 1]!["state"] as JsonObject)["id"] as string;
      if (id !== prevId) {
        const aka = (entry["state"] as JsonObject)["alsoKnownAs"];
        if (active["portable"] !== true || !Array.isArray(aka) || !aka.includes(prevId)) fail("identity");
      }
    }

    entries.push(entry);
    actives.push(active);
  }

  // 12. the requested DID belongs to this log
  if (requested.scid !== scid || !entries.some((e) => (e["state"] as JsonObject)["id"] === input.did)) fail("identity");

  // 13. witnesses
  checkWitnesses(input.witness, entries, actives);

  // 14. cache
  // a cache versionId that is not `<n>-<something>` is treated as absent
  const cached = typeof input.cache?.versionId === "string" ? /^([1-9][0-9]*)-.+$/s.exec(input.cache.versionId) : null;
  if (cached) {
    const k = Number(cached[1]);
    if (entries.length < k) fail("rollback");
    if (entries[k - 1]!["versionId"] !== input.cache!.versionId) fail("fork");
  }

  const last = entries[entries.length - 1]!;
  if (active["deactivated"] === true) {
    return { outcome: "deactivated", versionId: last["versionId"]!, cache: last["versionId"]! };
  }
  return {
    outcome: "resolved",
    versionId: last["versionId"]!,
    versionTime: last["versionTime"]!,
    document: last["state"]!,
    ttl: active["ttl"]!,
    cache: last["versionId"]!,
  };
}

/**
 * README check 13: every entry with a witness configuration is approved by at least `threshold` of
 * its witnesses, a proof for a later entry approving the earlier ones too.
 *
 * Spec: did:webvh v1.0 §Witnesses.
 */
function checkWitnesses(witnessText: string | null, entries: JsonObject[], actives: JsonObject[]): void {
  const configs = entries.map((_, i) => {
    if (i === 0) return actives[0]!["witness"] as JsonObject;
    const prev = actives[i - 1]!["witness"] as JsonObject;
    return Object.keys(prev).length === 0 ? (actives[i]!["witness"] as JsonObject) : prev;
  });
  if (configs.every((c) => Object.keys(c).length === 0)) return;

  // a text that is not I-JSON counts as absent
  const records = witnessText === null ? null : parseIJson(witnessText);
  if (records === null) fail("witness");
  // Impl: a file that is not an array of records holds no evidence (spec finding).
  const list = Array.isArray(records) ? records : [];

  const index = new Map(entries.map((e, i) => [e["versionId"] as string, i]));
  // the witness ids with a valid proof for entry i
  const approvals: Set<string>[] = entries.map(() => new Set());
  for (const record of list) {
    if (!isObject(record) || typeof record["versionId"] !== "string") continue;
    const at = index.get(record["versionId"]);
    if (at === undefined || !Array.isArray(record["proof"])) continue;
    for (const proof of record["proof"]) {
      if (!isObject(proof)) continue;
      const mk = didKeyMethod(proof["verificationMethod"]);
      if (!mk || !isEd25519Multikey(mk)) continue;
      if (proofVerifies(proof, mk, { versionId: record["versionId"] })) approvals[at]!.add("did:key:" + mk);
    }
  }

  configs.forEach((config, i) => {
    if (Object.keys(config).length === 0) return;
    const members = new Set((config["witnesses"] as JsonObject[]).map((w) => w["id"] as string));
    const approving = new Set<string>();
    for (let j = i; j < entries.length; j++) for (const id of approvals[j]!) if (members.has(id)) approving.add(id);
    if (approving.size < (config["threshold"] as number)) fail("witness");
  });
}
