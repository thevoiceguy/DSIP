/**
 * Reachability hints carried on Pkarr: BEP 44 mutable items on the BitTorrent Mainline DHT, for
 * `did:key` subjects whose identity key is also their Pkarr key.
 *
 * Spec: §8.5, §8.3 (v0.9: Pkarr beside the hints overlay; DHT Reachability Hints Profile); BEP 44
 * (mutable items, the signed buffer); RFC 1035 §4.1 (the DNS message), §4.1.4 (compression), §3.3.14 (TXT);
 * DHT Hints Profile §9 (the Pkarr carrier: reading, carrying the zone's other records, the next `ts`), §9.1
 * (multi-device identities: the pointer, device hints and their delegations; §7.4); RFC 3597 §4.
 * Impl: the step order, the reason tokens and the `_dsip` TXT record format are the vectors README's
 * ("Kind: `pkarr`"), which the profile's §9 defers to (spec-gap 105).
 */
import type { Json, JsonObject } from "../did.js";
import { ed25519FromMultibase, utf8Decode } from "../encoding.js";
import { ed25519Verify, verifyDelegation, type ReceiverContext } from "../envelope.js";

const Z32 = "ybndrfg8ejkmcpqxot1uwisza345h769";
/** Impl: `ts` stays exact as a JSON number (BEP 44 allows up to 2^63−1; spec-gap 105). */
const TS_MAX = (1n << 53n) - 1n;
/** Spec: §12.9 — a hint's lifetime cap, 3,600 s (spec-gap 96). */
const MAX_TTL = 3600;
/** Spec: DHT Hints Profile §9.1 — a device pointer's TTL cap, 604,800 s (7 days). */
const MAX_POINTER_TTL = 604800;

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
  return isZoneName(labels, "_dsip", z32);
}

/**
 * True when the owner name is exactly the two labels `<first>.<z32>`, ASCII case-insensitively.
 *
 * Spec: DHT Hints Profile §9, §9.1 (`_dsip`, `_dsip-devices`, `_dsip-delegation` under the key's zone).
 */
function isZoneName(labels: Buffer[], first: string, z32: string): boolean {
  return labels.length === 2 && asciiLower(labels[0]!) === first && asciiLower(labels[1]!) === z32;
}

/** The owner names a DSIP publisher replaces in its zone. Spec: DHT Hints Profile §9, §9.1 */
const DSIP_OWNERS = ["_dsip", "_dsip-devices", "_dsip-delegation"];

/**
 * TXT rdata as its character-strings (RFC 1035 §3.3.14); throws `Malformed` unless they consume it exactly.
 */
function characterStrings(rdata: Buffer): Buffer[] {
  const strings: Buffer[] = [];
  let pos = 0;
  while (pos < rdata.length) {
    const len = rdata[pos]!;
    if (pos + 1 + len > rdata.length) throw new Malformed();
    strings.push(rdata.subarray(pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  return strings;
}

/**
 * One `_dsip` TXT record to an endpoint `{uri, bindings[, service]}`.
 *
 * Spec: RFC 1035 §3.3.14 (character-strings); DHT Hints Profile §2 (`uri` is `wss://`, `bindings`,
 * optional `service`). Impl: strings are `key=value` split at the first `=`; exactly one `uri`, one or
 * more `b` in order, at most one `svc`; unknown keys are ignored; keys are case-sensitive (spec-gap 105).
 */
function endpointOf(rdata: Buffer): JsonObject | Rejected {
  const strings = characterStrings(rdata);
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
  const opened = openPayload(did, payloadHex, now);
  if ("outcome" in opened) return opened;
  return hintOf(did, opened, now);
}

/** A Pkarr payload past steps 1–5: its key, zone name, signed timestamp and DNS answers. */
interface Opened {
  key: Buffer;
  z32: string;
  ts: bigint;
  answers: RR[];
}

/**
 * Steps 1–5 of the README's `check: "hint"`: the `did:key`, the payload size, the BEP 44 signature,
 * the timestamp, and the DNS message.
 *
 * Spec: §8.5; DHT Hints Profile §9 (Reading, 1–5), shared by the pointer of §9.1.
 */
function openPayload(did: string, payloadHex: Json | undefined, now: number): Opened | Rejected {
  // 1. did:key with an Ed25519 key
  const key = did.startsWith("did:key:") ? ed25519FromMultibase(did.slice("did:key:".length)) : null;
  if (!key) return rejected("not-did-key");
  return openUnder(key, payloadHex, now);
}

/**
 * Steps 2–5 of the README's `check: "hint"` under a known Ed25519 key: the payload size, the BEP 44
 * signature, the timestamp and the DNS message — what every Pkarr packet must pass.
 *
 * Spec: DHT Hints Profile §9 (Reading, 2–5), §10 (a node's verify-before-store applies exactly these).
 */
function openUnder(key: Buffer, payloadHex: Json | undefined, now: number): Opened | Rejected {
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
  // 5. the DNS message
  let answers: RR[];
  try {
    answers = parseAnswers(dns);
  } catch (e) {
    if (e instanceof Malformed) return rejected("malformed");
    throw e;
  }
  return { key, z32: z32Encode(key), ts, answers };
}

/** Steps 6–9 of the README's `check: "hint"` over an opened payload. Spec: DHT Hints Profile §9 */
function hintOf(did: string, opened: Opened, now: number): Hint | Rejected {
  const { z32, ts, answers } = opened;
  // 6. the DSIP records among the answers
  const endpoints: JsonObject[] = [];
  const ttls: number[] = [];
  try {
    for (const rr of answers) {
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
 * Spec: DHT Hints Profile §9 (Publishing: "Keep the zone's other records"), §9.1; RFC 1035 §4.1; RFC 3597 §4.
 * Impl (vectors README, `check: "carry"`; spec-gap 105): only answer records; class exactly 1; the owners
 * `_dsip`, `_dsip-devices` and `_dsip-delegation` `.<zone>` (§9.1), which the publisher replaces, are compared
 * label by label, ASCII case-insensitively, whatever the type; the excluded records'
 * rdata is not inspected; any parse failure anywhere in the message is `malformed`.
 */
export function carry(zone: string, dnsHex: Json | undefined): Json {
  const dns = fromHex(dnsHex);
  if (!dns) return { error: "malformed" };
  const zoneLower = asciiLower(Buffer.from(zone, "latin1"));
  const keep: JsonObject[] = [];
  try {
    for (const rr of parseAnswers(dns)) {
      if (rr.cls !== 1 || DSIP_OWNERS.some((first) => isZoneName(rr.labels, first, zoneLower))) continue;
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

/** A did:key whose base58btc multibase decodes to an Ed25519 key (the README's `check: "hint"` step 1). */
function isEd25519DidKey(text: string): boolean {
  return text.startsWith("did:key:") && ed25519FromMultibase(text.slice("did:key:".length)) !== null;
}

/**
 * A compact DSIP-JOSE envelope: three non-empty base64url segments joined by `.`.
 *
 * Impl (vectors README, `check: "devices"` step 3): the concatenated character-strings must be this, else
 * `delegation-invalid`; whether the segments decode and verify is the §7.4 verifier's.
 */
function compactEnvelope(bytes: Buffer): string | null {
  const text = bytes.toString("latin1");
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text) ? text : null;
}

/**
 * Resolve a multi-device identity on Pkarr: the identity-signed pointer, then each listed device's own
 * hint and the delegation it carries.
 *
 * Spec: DHT Hints Profile §9.1 (the pointer's `_dsip-devices` records and 7-day cap; the device hint with
 * its `_dsip-delegation` record; a device counts only if its hint reads as §9 and its delegation verifies,
 * and is usable until the earlier expiry); §7.4 (the delegation and its revocations); §8.1 (hints only).
 * Impl (vectors README, `check: "devices"`; spec-gap 105): the pointer passes steps 1–5 of `check: "hint"`;
 * a TXT string is `dev=` by its leading bytes and other strings are ignored even if not UTF-8; a pointer
 * record whose rdata does not frame as character-strings is `malformed`, as in step 6; devices are listed
 * in record order, a repeated DID (exact text) once; a device whose `devices` entry is absent or null is
 * `unavailable`; a delegation record that does not frame, or whose strings concatenated are not a compact
 * envelope, is `delegation-invalid`; expiries are whole seconds, the pointer's `⌊ts / 10^6⌋ + min(TTL)`.
 */
export function resolveDevices(
  did: string,
  payloadHex: Json | undefined,
  payloads: JsonObject,
  now: number,
  revocations: Json[],
): Json {
  const opened = openPayload(did, payloadHex, now);
  if ("outcome" in opened) return opened;
  const listed: string[] = [];
  const ttls: number[] = [];
  try {
    for (const rr of opened.answers) {
      if (rr.type !== 16 || rr.cls !== 1 || !isZoneName(rr.labels, "_dsip-devices", opened.z32)) continue;
      const devs = characterStrings(rr.rdata).filter((s) => s.subarray(0, 4).toString("latin1") === "dev=");
      const value = devs.length === 1 ? utf8Decode(devs[0]!.subarray(4)) : null;
      if (value === null || !isEd25519DidKey(value)) return rejected("bad-pointer");
      if (!listed.includes(value)) listed.push(value);
      ttls.push(rr.ttl);
    }
  } catch (e) {
    if (e instanceof Malformed) return rejected("malformed");
    throw e;
  }
  if (ttls.length === 0) return rejected("no-devices");
  if (ttls.some((t) => t > MAX_POINTER_TTL)) return rejected("ttl-too-long");
  const expiresAt = Number(opened.ts / 1_000_000n) + Math.min(...ttls);
  if (now >= expiresAt) return rejected("expired");

  const ctx = { now, revocations } as ReceiverContext;
  const devices: JsonObject[] = listed.map((device) => {
    const out = (rest: JsonObject): JsonObject => ({ device, ...rest });
    const payload = payloads[device];
    // 1. nothing fetched for it
    if (payload === undefined || payload === null) return out(rejected("unavailable"));
    // 2. its own hint, under its own key
    const dev = openPayload(device, payload, now);
    if ("outcome" in dev) return out(dev);
    const hint = hintOf(device, dev, now);
    if (hint.outcome === "rejected") return out(hint);
    // 3. exactly one delegation record, whose strings make a compact envelope
    const records = dev.answers.filter(
      (rr) => rr.type === 16 && rr.cls === 1 && isZoneName(rr.labels, "_dsip-delegation", dev.z32),
    );
    if (records.length === 0) return out(rejected("delegation-missing"));
    if (records.length > 1) return out(rejected("delegation-invalid"));
    let compact: string | null;
    try {
      compact = compactEnvelope(Buffer.concat(characterStrings(records[0]!.rdata)));
    } catch (e) {
      if (!(e instanceof Malformed)) throw e;
      compact = null;
    }
    if (compact === null) return out(rejected("delegation-invalid"));
    // 4. §7.4 for (identity, device) at now, with the revocations held
    const bound = verifyDelegation(compact, device, did, ctx);
    if ("verdict" in bound) return out(rejected(bound.code));
    // 5. usable until the earlier expiry
    return out({
      outcome: "hint",
      endpoints: hint.endpoints,
      expires_at: Math.min(hint.expires_at, bound.expires_at),
    });
  });
  return { outcome: "devices", seq: Number(opened.ts), expires_at: expiresAt, devices };
}

/** The outcome of a node's verify-before-store for `PUT /<z32>`. */
type StoreOutcome = { outcome: "stored" } | { outcome: "kept"; reason: "same" | "older" | "conflict" } | Rejected;

/**
 * A hints node's verify-before-store for `PUT /<z32>` (Pkarr's relay interface): the canonical key, then
 * the checks every Pkarr packet must pass, then §8.3's `ts` rule against the packet held for that key.
 *
 * Spec: DHT Hints Profile §10 (`PUT /<z32>`: 204 stored or the same bytes held, 409 an older or
 * conflicting `ts`, 400 rejected; `_dsip` content is judged by readers), §9 (Reading, 2–5), §8.3 (a higher
 * sequence wins; an equal one with other content keeps the held record).
 * Impl (vectors README, `check: "store"`): `key` must be exactly the canonical z-base-32 of a 32-byte key —
 * 52 lowercase alphabet characters, zero padding bits — else `bad-key`; no case folding of the path.
 * Nothing past step 5 of `check: "hint"` applies: a packet with no `_dsip` records, or whose `_dsip` hint
 * has expired, is stored. `held` is trusted as the node's own store (it passed this check when stored) and is
 * not re-verified: only its signed `ts` (bytes 64–71) is read, compared as an unsigned 64-bit integer, and a
 * held value too short to carry one counts as nothing held. "Same bytes" is equality of the decoded
 * payloads (signature, `ts` and DNS message), not of their hex text.
 */
export function store(keyText: Json | undefined, payloadHex: Json | undefined, heldHex: Json | undefined, now: number): StoreOutcome {
  // 1. the canonical key
  const key = typeof keyText === "string" ? z32Decode(keyText) : null;
  if (!Buffer.isBuffer(key)) return rejected("bad-key");
  // 2.–5. the frame, the signature, the timestamp, the DNS message
  const opened = openUnder(key, payloadHex, now);
  if ("outcome" in opened) return opened;
  // 6. §8.3 against what is held
  const held = heldHex === null || heldHex === undefined ? null : fromHex(heldHex);
  if (!held || held.length < 72) return { outcome: "stored" };
  const heldTs = held.readBigUInt64BE(64);
  if (opened.ts > heldTs) return { outcome: "stored" };
  if (opened.ts < heldTs) return { outcome: "kept", reason: "older" };
  return { outcome: "kept", reason: fromHex(payloadHex)!.equals(held) ? "same" : "conflict" };
}

/** Kind `pkarr`: dispatch on `input.check`. Spec: §8.5; README "Kind: `pkarr`" */
export function runPkarr(input: JsonObject): Json | undefined {
  switch (input["check"]) {
    case "hint":
      return readHint(input["did"] as string, input["payload"], input["now"] as number) as unknown as Json;
    case "store":
      return store(input["key"], input["payload"], input["held"], input["now"] as number) as unknown as Json;
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
    case "devices":
      return resolveDevices(
        input["did"] as string,
        input["payload"],
        (input["devices"] ?? {}) as JsonObject,
        input["now"] as number,
        Array.isArray(input["revocations"]) ? input["revocations"] : [],
      );
    case "next-ts":
      return nextTs(input["clock"] as number, input["previous"] as number | undefined);
    default:
      return undefined;
  }
}
