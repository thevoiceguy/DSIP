/**
 * Reachability hints carried on Pkarr: BEP 44 mutable items on the BitTorrent Mainline DHT, for
 * `did:key` subjects whose identity key is also their Pkarr key.
 *
 * Spec: §8.5, §8.3 (v0.9: Pkarr beside the hints overlay; DHT Reachability Hints Profile); BEP 44
 * (mutable items, the signed buffer); RFC 1035 §4.1 (the DNS message), §4.1.4 (compression), §3.3.14 (TXT);
 * DHT Hints Profile §9 (the Pkarr carrier: reading, carrying the zone's other records, the next `ts`); RFC 3597 §4.
 * Impl: the step order, the reason tokens and the `_dsip` TXT record format are the vectors README's
 * ("Kind: `pkarr`"), which the profile's §9 defers to (spec-gap 105).
 */
import type { Json, JsonObject } from "../did.js";
import { ed25519FromMultibase, utf8Decode } from "../encoding.js";
import { ed25519Verify } from "../envelope.js";

const Z32 = "ybndrfg8ejkmcpqxot1uwisza345h769";
/** Impl: `ts` stays exact as a JSON number (BEP 44 allows up to 2^63−1; spec-gap 105). */
const TS_MAX = (1n << 53n) - 1n;
/** Spec: §12.9 — a hint's lifetime cap, 3,600 s (spec-gap 96). */
const MAX_TTL = 3600;

type Rejected = { outcome: "rejected"; reason: string };
const rejected = (reason: string): Rejected => ({ outcome: "rejected", reason });

/** Hex to bytes; `null` when the text is not hex. Impl: either case is read (README: binary values are lowercase hex). */
function fromHex(text: Json | undefined): Buffer | null {
  if (typeof text !== "string" || !/^([0-9a-fA-F]{2})*$/.test(text)) return null;
  return Buffer.from(text, "hex");
}

/**
 * z-base-32, most significant bit first, the final character zero-padded.
 *
 * Spec: Pkarr (a public key's zone name is its z-base-32 form).
 */
export function z32Encode(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += Z32[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += Z32[(acc << (5 - bits)) & 31];
  return out;
}

/**
 * Decode a 52-character z-base-32 key to its 32 bytes.
 *
 * Spec: Pkarr. Impl: exactly 52 alphabet characters (else `malformed`) and zero padding bits (else
 * `non-canonical`): one key, one name — Pkarr ignores the padding bits (spec-gap 105).
 */
export function z32Decode(text: string): Buffer | Rejected {
  if (text.length !== 52) return rejected("malformed");
  let acc = 0n;
  for (const ch of text) {
    const v = Z32.indexOf(ch);
    if (v < 0) return rejected("malformed");
    acc = (acc << 5n) | BigInt(v);
  }
  // 260 bits: 256 key bits, then 4 padding bits
  if ((acc & 0xfn) !== 0n) return rejected("non-canonical");
  acc >>= 4n;
  return Buffer.from(acc.toString(16).padStart(64, "0"), "hex");
}

/**
 * The BEP 44 signed buffer: `["4:salt" ‖ len ‖ ":" ‖ salt]` (non-empty salt only) then
 * `"3:seqi" ‖ seq ‖ "e1:v" ‖ len ‖ ":" ‖ value`.
 *
 * Spec: BEP 44 (mutable items, signature).
 */
export function bep44Signable(seq: bigint, value: Buffer, salt: Buffer | null): Buffer {
  const parts: Buffer[] = [];
  if (salt && salt.length > 0) parts.push(Buffer.from(`4:salt${salt.length}:`), salt);
  parts.push(Buffer.from(`3:seqi${seq}e1:v${value.length}:`), value);
  return Buffer.concat(parts);
}

/** A parsed DNS resource record: owner name as raw labels, and its fields. */
interface RR {
  labels: Buffer[];
  type: number;
  cls: number;
  ttl: number;
  rdata: Buffer;
  /** Offset of `rdata` in the message, so names inside it can follow pointers (RFC 1035 §4.1.4). */
  rdStart: number;
}

/** A failure inside the DNS parser: the message is `malformed`. */
class Malformed extends Error {}

/**
 * Read a domain name at `pos`; returns its labels and the offset just past it in the message.
 *
 * Spec: RFC 1035 §3.1, §4.1.4. Impl: the vectors README's rule (spec-gap 105) — labels of 1–63 bytes,
 * a zero byte, or a pointer `0b11xxxxxx xxxxxxxx` whose target lies strictly before the start of the
 * segment it appears in (the name's own start, then each previous pointer's target), so every name
 * terminates; any other label type, or running past the end, is malformed. No 255-byte name limit.
 */
function readName(msg: Buffer, pos: number): { labels: Buffer[]; end: number } {
  const labels: Buffer[] = [];
  let segStart = pos;
  let end = -1;
  for (;;) {
    if (pos >= msg.length) throw new Malformed();
    const len = msg[pos]!;
    if (len === 0) {
      if (end < 0) end = pos + 1;
      return { labels, end };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= msg.length) throw new Malformed();
      const target = ((len & 0x3f) << 8) | msg[pos + 1]!;
      if (target >= segStart) throw new Malformed();
      if (end < 0) end = pos + 2;
      segStart = target;
      pos = target;
      continue;
    }
    if (len > 63) throw new Malformed(); // 0b01…… and 0b10…… label types
    if (pos + 1 + len > msg.length) throw new Malformed();
    labels.push(msg.subarray(pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
}

/**
 * Parse an RFC 1035 message and return its answer records.
 *
 * Spec: RFC 1035 §4.1. Impl: the header is not otherwise checked (flags, opcode, rcode); questions are
 * a name and 4 bytes; every section is parsed; the message must end where its last record ends.
 */
function parseAnswers(msg: Buffer): RR[] {
  if (msg.length < 12) throw new Malformed();
  const qd = msg.readUInt16BE(4);
  const an = msg.readUInt16BE(6);
  const rest = msg.readUInt16BE(8) + msg.readUInt16BE(10);
  let pos = 12;
  for (let i = 0; i < qd; i++) {
    pos = readName(msg, pos).end + 4;
    if (pos > msg.length) throw new Malformed();
  }
  const answers: RR[] = [];
  for (let i = 0; i < an + rest; i++) {
    const { labels, end } = readName(msg, pos);
    if (end + 10 > msg.length) throw new Malformed();
    const rdlength = msg.readUInt16BE(end + 8);
    const rdEnd = end + 10 + rdlength;
    if (rdEnd > msg.length) throw new Malformed();
    if (i < an) {
      answers.push({
        labels,
        type: msg.readUInt16BE(end),
        cls: msg.readUInt16BE(end + 2),
        ttl: msg.readUInt32BE(end + 4),
        rdata: msg.subarray(end + 10, rdEnd),
        rdStart: end + 10,
      });
    }
    pos = rdEnd;
  }
  if (pos !== msg.length) throw new Malformed();
  return answers;
}

/** ASCII-only lower-casing of one label's bytes (RFC 1035 §2.3.3, RFC 4343). */
function asciiLower(label: Buffer): string {
  return Array.from(label, (b) => String.fromCharCode(b >= 0x41 && b <= 0x5a ? b + 32 : b)).join("");
}

/**
 * True when the owner name is `_dsip.<z32>`, label by label, ASCII case-insensitively.
 *
 * Impl: only `_dsip.<z32(key)>` is DSIP's in the key's zone; every other name (the apex, Pubky's or iroh's
 * records, names outside the zone) is ignored (spec-gap 105). Compared as two labels, so a single label
 * holding a `.` byte never matches (spec finding: the README says "as dotted labels").
 */
function isDsipName(labels: Buffer[], z32: string): boolean {
  return labels.length === 2 && asciiLower(labels[0]!) === "_dsip" && asciiLower(labels[1]!) === z32;
}

/**
 * One `_dsip` TXT record to an endpoint `{uri, bindings[, service]}`.
 *
 * Spec: RFC 1035 §3.3.14 (character-strings); DHT Hints Profile §2 (`uri` is `wss://`, `bindings`,
 * optional `service`). Impl: strings are `key=value` split at the first `=`; exactly one `uri`, one or
 * more `b` in order, at most one `svc`; unknown keys are ignored; keys are case-sensitive (spec-gap 105).
 */
function endpointOf(rdata: Buffer): JsonObject | Rejected {
  const strings: Buffer[] = [];
  let pos = 0;
  while (pos < rdata.length) {
    const len = rdata[pos]!;
    if (pos + 1 + len > rdata.length) throw new Malformed();
    strings.push(rdata.subarray(pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  const uris: string[] = [];
  const bindings: string[] = [];
  const services: string[] = [];
  for (const raw of strings) {
    const text = utf8Decode(raw);
    if (text === null) return rejected("bad-endpoint");
    const eq = text.indexOf("=");
    if (eq < 0) return rejected("bad-endpoint");
    const [key, value] = [text.slice(0, eq), text.slice(eq + 1)];
    if (key === "uri") uris.push(value);
    else if (key === "b") bindings.push(value);
    else if (key === "svc") services.push(value);
  }
  if (uris.length !== 1 || !uris[0]!.startsWith("wss://") || bindings.length === 0 || services.length > 1) {
    return rejected("bad-endpoint");
  }
  const endpoint: JsonObject = { uri: uris[0]!, bindings };
  if (services.length === 1) endpoint["service"] = services[0]!;
  return endpoint;
}

/** A hint read from a Pkarr payload. */
interface Hint {
  outcome: "hint";
  subject: string;
  seq: number;
  issued_at: number;
  expires_at: number;
  endpoints: JsonObject[];
}

/**
 * Read a Pkarr relay payload `signature(64) ‖ ts(u64) ‖ dns` as a reachability hint for `did`.
 *
 * Spec: §8.5 (a hint is signed by the identity it describes and verified before use), §8.3 (records past
 * expiration are invalid), §12.9 (a hint's lifetime is capped at 3,600 s; its `issued_at` at most 300 s in
 * the future); BEP 44 (the signed buffer, `seq` = `ts`).
 * Impl (spec-gap 105, DSIP's additions over Pkarr): `ts` at most 300 s ahead of `now` (Pkarr accepts any) and at most 2^53−1;
 * only `_dsip.<z32>` TXT answers are read; `issued_at` is the signed `ts` and `expires_at` adds the
 * smallest DSIP record TTL, which must be ≤ 3,600 s. The first failing README step gives the reason.
 */
export function readHint(did: string, payloadHex: Json | undefined, now: number): Hint | Rejected {
  // 1. did:key with an Ed25519 key
  const key = did.startsWith("did:key:") ? ed25519FromMultibase(did.slice("did:key:".length)) : null;
  if (!key) return rejected("not-did-key");
  // 2. 72–1072 bytes: signature, timestamp, then at most 1,000 bytes of DNS (BEP 44's `v` limit)
  const payload = fromHex(payloadHex);
  if (!payload || payload.length < 72 || payload.length > 1072) return rejected("malformed");
  const signature = payload.subarray(0, 64);
  const ts = payload.readBigUInt64BE(64);
  const dns = payload.subarray(72);
  // 3. the BEP 44 signature over seq = ts, v = dns
  if (!ed25519Verify(key, bep44Signable(ts, dns, null), signature)) return rejected("signature");
  // 4. the timestamp
  if (ts > TS_MAX) return rejected("malformed");
  if (ts > (BigInt(now) + 300n) * 1_000_000n) return rejected("future");
  // 5–6. the DNS message, then the DSIP records among its answers
  const z32 = z32Encode(key);
  const endpoints: JsonObject[] = [];
  const ttls: number[] = [];
  try {
    for (const rr of parseAnswers(dns)) {
      if (rr.type !== 16 || rr.cls !== 1 || !isDsipName(rr.labels, z32)) continue;
      const endpoint = endpointOf(rr.rdata);
      if ("outcome" in endpoint) return endpoint as Rejected;
      endpoints.push(endpoint);
      ttls.push(rr.ttl);
    }
  } catch (e) {
    if (e instanceof Malformed) return rejected("malformed");
    throw e;
  }
  // 7. at least one, every TTL within the cap
  if (endpoints.length === 0) return rejected("no-endpoints");
  if (ttls.some((t) => t > MAX_TTL)) return rejected("ttl-too-long");
  // 8. expiry: the signed time plus the smallest TTL
  const issuedAt = Number(ts / 1_000_000n);
  const expiresAt = issuedAt + Math.min(...ttls);
  if (now >= expiresAt) return rejected("expired");
  return { outcome: "hint", subject: did, seq: Number(ts), issued_at: issuedAt, expires_at: expiresAt, endpoints };
}

/**
 * §8.3 between a newly received payload and one already held for the same key.
 *
 * Spec: §8.3 — records past expiration are invalid; the higher sequence number wins; conflicting live
 * records from the same key trigger a warning. Impl (spec-gap 105): a held payload that no longer reads,
 * for any reason, is absent; an equal `seq` keeps the held record, whatever the packet sizes (Pkarr's
 * "larger packet wins" is not used); byte-identical payloads are a no-op.
 */
export function select(did: string, payloadHex: Json | undefined, heldHex: Json | undefined, now: number): Json {
  const input = readHint(did, payloadHex, now);
  if (input.outcome === "rejected") return input;
  const held = readHint(did, heldHex, now);
  if (held.outcome === "rejected") return { winner: "input", conflict: "none" };
  if (input.seq > held.seq) return { winner: "input", conflict: "newer-seq" };
  if (input.seq < held.seq) return { winner: "held", conflict: "older-seq" };
  const same = fromHex(payloadHex)!.equals(fromHex(heldHex)!);
  return { winner: "held", conflict: same ? "none" : "same-seq-live" };
}

/** Labels to uncompressed wire form: length-prefixed labels, then a zero byte (RFC 1035 §3.1). */
function wireName(labels: Buffer[]): Buffer {
  const parts: Buffer[] = [];
  for (const l of labels) parts.push(Buffer.from([l.length]), l);
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/**
 * The layout of the RFC 1035 types whose rdata may hold compressed names, as RFC 3597 §4 lists them:
 * `n` is a name, a number is that many fixed bytes.
 *
 * Spec: DHT Hints Profile §9 (Publishing: "the names inside the record data are expanded"); RFC 3597 §4;
 * RFC 1035 §3.3 (NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, MINFO, MX).
 */
const COMPRESSIBLE: ReadonlyMap<number, ReadonlyArray<"n" | number>> = new Map<number, Array<"n" | number>>([
  [2, ["n"]], // NS
  [3, ["n"]], // MD
  [4, ["n"]], // MF
  [5, ["n"]], // CNAME
  [6, ["n", "n", 20]], // SOA: MNAME, RNAME, SERIAL REFRESH RETRY EXPIRE MINIMUM
  [7, ["n"]], // MB
  [8, ["n"]], // MG
  [9, ["n"]], // MR
  [12, ["n"]], // PTR
  [14, ["n", "n"]], // MINFO
  [15, [2, "n"]], // MX: PREFERENCE, EXCHANGE
]);

/**
 * Re-encode one carried record's rdata with every name in it expanded.
 *
 * Spec: DHT Hints Profile §9; RFC 3597 §4. Impl (vectors README, `check: "carry"`): the rdata must hold
 * exactly the type's layout; every inline name byte (labels, the zero byte or the pointer) lies inside the
 * rdata, while a pointer may target anywhere earlier in the message under the backward-only rule of the
 * owner names; anything else is malformed. Every other type is returned as it is.
 */
function expandRdata(msg: Buffer, rr: RR): Buffer {
  const layout = COMPRESSIBLE.get(rr.type);
  if (!layout) return rr.rdata;
  const rdEnd = rr.rdStart + rr.rdata.length;
  const parts: Buffer[] = [];
  let pos = rr.rdStart;
  for (const field of layout) {
    if (field === "n") {
      const { labels, end } = readName(msg, pos);
      if (end > rdEnd) throw new Malformed();
      parts.push(wireName(labels));
      pos = end;
    } else {
      if (pos + field > rdEnd) throw new Malformed();
      parts.push(msg.subarray(pos, pos + field));
      pos += field;
    }
  }
  if (pos !== rdEnd) throw new Malformed();
  return Buffer.concat(parts);
}

/**
 * The records a publisher carries over from its previous packet: every IN answer outside `_dsip.<zone>`,
 * in message order, owner names uncompressed (case kept) and names inside rdata expanded.
 *
 * Spec: DHT Hints Profile §9 (Publishing: "Keep the zone's other records"); RFC 1035 §4.1; RFC 3597 §4.
 * Impl (vectors README, `check: "carry"`; spec-gap 105): only answer records; class exactly 1; the `_dsip`
 * owner is compared label by label, ASCII case-insensitively, whatever the type; the excluded records'
 * rdata is not inspected; any parse failure anywhere in the message is `malformed`.
 */
export function carry(zone: string, dnsHex: Json | undefined): Json {
  const dns = fromHex(dnsHex);
  if (!dns) return { error: "malformed" };
  const zoneLower = asciiLower(Buffer.from(zone, "latin1"));
  const keep: JsonObject[] = [];
  try {
    for (const rr of parseAnswers(dns)) {
      if (rr.cls !== 1 || isDsipName(rr.labels, zoneLower)) continue;
      keep.push({
        name: wireName(rr.labels).toString("hex"),
        type: rr.type,
        ttl: rr.ttl,
        rdata: expandRdata(dns, rr).toString("hex"),
      });
    }
  } catch (e) {
    if (e instanceof Malformed) return { error: "malformed" };
    throw e;
  }
  return { keep };
}

/**
 * The timestamp a publisher signs: `max(clock, previous + 1)` µs, or the clock with no previous packet.
 *
 * Spec: DHT Hints Profile §9 (Publishing: never sign ahead of the clock except after it steps backwards,
 * since a lower `seq` is refused everywhere); §8.3 (the higher sequence number wins).
 * Impl (vectors README, `check: "next-ts"`; spec-gap 105): a result above 2^53−1, which every reader
 * refuses (`check: "hint"` step 4), is `{"error": "exhausted"}`: nothing is signed.
 */
export function nextTs(clock: number, previous: number | undefined): Json {
  const c = BigInt(clock);
  const next = previous === undefined ? c : BigInt(previous) + 1n > c ? BigInt(previous) + 1n : c;
  if (next > TS_MAX) return { error: "exhausted" };
  return { ts: Number(next) };
}

/** Kind `pkarr`: dispatch on `input.check`. Spec: §8.5; README "Kind: `pkarr`" */
export function runPkarr(input: JsonObject): Json | undefined {
  switch (input["check"]) {
    case "hint":
      return readHint(input["did"] as string, input["payload"], input["now"] as number) as unknown as Json;
    case "select":
      return select(input["did"] as string, input["payload"], input["held"], input["now"] as number);
    case "bep44-signable": {
      const salt = input["salt"] === null ? null : fromHex(input["salt"]);
      return { bytes: bep44Signable(BigInt(input["seq"] as number), fromHex(input["value"])!, salt).toString("hex") };
    }
    case "bep44-verify": {
      const [key, value, sig] = [fromHex(input["public_key"]), fromHex(input["value"]), fromHex(input["signature"])];
      const salt = input["salt"] === null ? null : fromHex(input["salt"]);
      if (!key || key.length !== 32 || !value || !sig) return { valid: false };
      return { valid: ed25519Verify(key, bep44Signable(BigInt(input["seq"] as number), value, salt), sig) };
    }
    case "z32-encode":
      return { z32: z32Encode(fromHex(input["key"])!) };
    case "z32-decode": {
      const out = z32Decode(input["z32"] as string);
      return Buffer.isBuffer(out) ? { key: out.toString("hex") } : out;
    }
    case "carry":
      return carry(input["zone"] as string, input["dns"]);
    case "next-ts":
      return nextTs(input["clock"] as number, input["previous"] as number | undefined);
    default:
      return undefined;
  }
}
