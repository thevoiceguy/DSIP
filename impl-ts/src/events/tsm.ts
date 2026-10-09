/**
 * SNMPv3 over TLS for the Device Events Profile: RFC 6353's certificate-to-security-name table,
 * splitting a TLS byte stream into BER messages, and a gateway's Transport Security Model
 * receiver (with RFC 5343 discovery).
 *
 * Spec: E§2 (`snmpv3-tls` basis), E§3 ("SNMPv3 over TLS"); RFC 6353 §5.3.2 and
 * `snmpTlstmCertToTSNTable`, RFC 5591 (TSM), RFC 5343 (context engine discovery). The exact
 * inputs, output shapes and order of checks are the vectors README's, "SNMPv3 over TLS"
 * (`check: "tsm-name"`, `"tls-frames"`, `"dtls-record"`, `"tsm"`).
 */
import type { Json, JsonObject } from "../did.js";
import { Bad, parseMessage, type Message } from "./usm.js";

// ---------------------------------------------------------------------------------------------
// The certificate-to-name table

/** ASCII-only lowercasing: A–Z become a–z, every other code point is kept. Spec: E§3 */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/** The SAN types a `san-*` map reads. Spec: E§3 */
const SAN_TYPES = ["rfc822", "dns", "ip"];

/**
 * One SAN value mapped as its type, or `null` when it fails.
 *
 * Spec: E§3 — `rfc822`: the part after the last `@` lowercased (ASCII), no `@` fails; `dns`:
 * lowercased (ASCII); `ip`: 4 bytes a dotted quad, 16 bytes 32 lowercase hex digits, any other
 * length fails.
 * Impl: a SAN value that is not a string fails the map; an `ip` value that is not an even run of
 * hex digits (either case) fails, as an address of no valid length.
 */
function mapSan(type: string, value: Json | undefined): string | null {
  if (typeof value !== "string") return null;
  switch (type) {
    case "rfc822": {
      const at = value.lastIndexOf("@");
      if (at < 0) return null;
      return value.slice(0, at + 1) + asciiLower(value.slice(at + 1));
    }
    case "dns":
      return asciiLower(value);
    case "ip": {
      if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) return null;
      const bytes = Buffer.from(value, "hex");
      if (bytes.length === 4) return Array.from(bytes).join(".");
      if (bytes.length === 16) return bytes.toString("hex");
      return null;
    }
    default:
      return null;
  }
}

/**
 * A matched row's map applied to the certificate: the name, or `null` when the map fails.
 *
 * Spec: E§3 — the maps `specified`, `san-rfc822`, `san-dns`, `san-ip`, `san-any` and
 * `common-name`; an unknown map, or one with nothing to map, fails.
 * Impl: `san-<type>` and `san-any` take the first qualifying SAN only; if mapping it fails, the
 * row fails (a later SAN is not tried), as the README's "the first `dns` SAN" reads.
 * Impl: `specified` needs `data` to be a JSON string; `common-name` needs `cn[0]` to be one.
 */
function applyMap(row: JsonObject, cert: JsonObject): string | null {
  const sans = Array.isArray(cert["san"]) ? (cert["san"] as JsonObject[]) : [];
  const firstOf = (types: string[]): JsonObject | undefined =>
    sans.find((s) => s !== null && typeof s === "object" && types.includes(s["type"] as string));
  switch (row["map"]) {
    case "specified": {
      const d = row["data"];
      return typeof d === "string" ? d : null;
    }
    case "san-rfc822":
    case "san-dns":
    case "san-ip": {
      const type = (row["map"] as string).slice(4);
      const s = firstOf([type]);
      return s ? mapSan(type, s["value"]) : null;
    }
    case "san-any": {
      const s = firstOf(SAN_TYPES);
      return s ? mapSan(s["type"] as string, s["value"]) : null;
    }
    case "common-name": {
      const cn = cert["cn"];
      const v = Array.isArray(cn) ? cn[0] : undefined;
      return typeof v === "string" ? v : null;
    }
    default:
      return null;
  }
}

/**
 * `check: "tsm-name"`: the security name a verified certificate maps to through the gateway's
 * `snmpTlstmCertToTSNTable`, as `{security_name, row}`, or `{error: "no-security-name"}`.
 *
 * Spec: E§3 — rows in ascending `id`; a row matches when its fingerprint, compared without case,
 * is the presented certificate's or a CA's in its verified path; a row that fails, or whose name
 * is not 1–32 octets of UTF-8, passes to the next; no transport prefix is added; with no name the
 * connection is closed (RFC 6353 §5.3.2).
 * Impl: `id` is compared as a number (the README promises distinct ids); "without case" is ASCII
 * case folding of the hex; a fingerprint that is not a string matches nothing.
 * Impl: the UTF-8 length is that of the JavaScript string encoded as UTF-8 (a lone surrogate,
 * which JSON input can carry, counts as U+FFFD's 3 bytes).
 */
export function tsmName(cert: JsonObject, table: JsonObject[]): JsonObject {
  const prints = new Set<string>();
  if (typeof cert["sha256"] === "string") prints.add(asciiLower(cert["sha256"]));
  for (const c of Array.isArray(cert["chain"]) ? cert["chain"] : []) if (typeof c === "string") prints.add(asciiLower(c));
  const rows = [...table].sort((a, b) => (a["id"] as number) - (b["id"] as number));
  for (const row of rows) {
    const fp = row["fingerprint"];
    if (typeof fp !== "string" || !prints.has(asciiLower(fp))) continue;
    const name = applyMap(row, cert);
    if (name === null) continue;
    // E§3: 1–32 octets of UTF-8 (VACM's SnmpAdminString limit for a securityName)
    const n = Buffer.byteLength(name, "utf8");
    if (n < 1 || n > 32) continue;
    return { security_name: name, row: row["id"] as Json };
  }
  return { error: "no-security-name" };
}

// ---------------------------------------------------------------------------------------------
// Framing

/** E§3 framing: the largest message, tag and length included. */
const MAX_MESSAGE = 65536;

/**
 * `check: "tls-frames"`: split a TLS byte stream into whole BER messages, as
 * `{messages, pending, close?}`.
 *
 * Spec: E§3 "Framing" — one BER SEQUENCE (first byte `0x30`), definite length in short form or
 * long form with 1–4 length bytes, at most 65,536 bytes; a stream that breaks these is closed, a
 * partial message waits. README "SNMPv3 over TLS", `tls-frames` steps 1–7.
 * Impl: the size limit is checked as soon as the length is known, before the content has
 * arrived; a non-minimal long-form length is accepted (BER); after a close, `pending` is the
 * unread rest, starting at the item that could not be framed.
 */
export function tlsFrames(stream: Uint8Array): JsonObject {
  const messages: string[] = [];
  let p = 0;
  const done = (close: boolean): JsonObject => {
    const out: JsonObject = { messages, pending: Buffer.from(stream.subarray(p)).toString("hex") };
    if (close) out["close"] = true;
    return out;
  };
  for (;;) {
    const left = stream.length - p;
    if (left < 2) return done(false); // 1
    if (stream[p] !== 0x30) return done(true); // 2
    const first = stream[p + 1]!;
    let header: number;
    let len: number;
    if (first < 0x80) {
      header = 2;
      len = first;
    } else {
      const n = first & 0x7f;
      if (n < 1 || n > 4) return done(true); // 3: 0x80 indefinite, 0x85–0xff
      if (left < 2 + n) return done(false); // 4
      header = 2 + n;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + stream[p + 2 + i]!;
    }
    const total = header + len;
    if (total > MAX_MESSAGE) return done(true); // 5
    if (left < total) return done(false); // 6
    messages.push(Buffer.from(stream.subarray(p, p + total)).toString("hex")); // 7
    p += total;
  }
}

/**
 * `check: "dtls-record"` (v0.11): one DTLS record carries exactly one message, as
 * `{message}` or `{error: "not-one-message"}`.
 *
 * Spec: E§3 "Transport" — over DTLS (RFC 6353 over UDP) each record carries exactly one message;
 * a record that does not is dropped and the session continues. README "SNMPv3 over TLS",
 * `dtls-record`: the record is split as `tls-frames` splits a stream, and it is the one message
 * when that gives exactly one message, nothing pending and no close.
 */
export function dtlsRecord(record: Uint8Array): JsonObject {
  const frames = tlsFrames(record);
  const messages = frames["messages"] as string[];
  if (messages.length === 1 && frames["pending"] === "" && !("close" in frames)) {
    return { message: messages[0]! };
  }
  return { error: "not-one-message" };
}

// ---------------------------------------------------------------------------------------------
// The TSM receiver

/** RFC 5343 §3's localEngineID, the contextEngineID a discovery request names. */
const LOCAL_ENGINE_ID = "8000000006";
/** `snmpEngineID.0` (RFC 3411), the only varbind of a discovery request. */
const SNMP_ENGINE_ID_0 = "1.3.6.1.6.3.10.2.1.1.0";

const refused = (reason: string): JsonObject => ({ refused: { reason } });

/**
 * `check: "tsm"`: one SNMPv3 message read from a TLS connection whose certificate already mapped
 * to a security name — `accepted` (a trap or inform), `discovery` (RFC 5343), or `refused`.
 *
 * Spec: E§3 "Each message" — `malformed` (USM's structure rules, `securityParameters` any OCTET
 * STRING and ignored, `msgData` always a plaintext ScopedPDU), then `unsupported-security-model`
 * (not 4, the TSM), then `not-a-notification`; any `msgFlags` level is accepted (RFC 5591 §5.2
 * step 4); E§3 "Discovery": a GetRequest-PDU (`0xA0`) with contextEngineID `80 00 00 00 06` and
 * only the varbind `snmpEngineID.0`, whose value is any valid value.
 * Impl: discovery compares the contextEngineID bytes exactly (5 bytes); a GetRequest that misses
 * any part of the pattern is `not-a-notification`.
 */
export function tsmReceive(b: Uint8Array): JsonObject {
  let m: Message;
  try {
    m = parseMessage(b, true);
  } catch (e) {
    if (e instanceof Bad) return refused("malformed");
    throw e;
  }
  // RFC 5591: TSM is security model 4; USM over TLS is refused (E§3)
  if (m.model !== 4) return refused("unsupported-security-model");
  const pdu = m.pdu!;
  if (pdu.tag === 0xa7 || pdu.tag === 0xa6) {
    const trap: JsonObject = { version: "v3", varbinds: pdu.varbinds };
    if (pdu.tag === 0xa6) trap["inform"] = { request_id: pdu.requestId };
    return { accepted: { trap } };
  }
  const vb = pdu.varbinds;
  if (
    pdu.tag === 0xa0 &&
    Buffer.from(pdu.contextEngineId).toString("hex") === LOCAL_ENGINE_ID &&
    vb.length === 1 &&
    (vb[0] as JsonObject)["oid"] === SNMP_ENGINE_ID_0
  ) {
    return { discovery: { request_id: pdu.requestId } };
  }
  return refused("not-a-notification");
}
