/**
 * Syslog for the Device Events Profile: a datagram parsed into `raw.syslog` (RFC 5424, else
 * RFC 3164), and a `raw.syslog` event mapped to an alarm through the gateway's rule table.
 *
 * Spec: E§3 (parsing), E§4 (syslog rules); RFC 5424 §6, RFC 3164 §4.1. The exact grammar is the
 * vectors README's, "Kind: `device-events`", `check: "syslog"` and `check: "map"` for `raw.syslog`.
 */
import type { Json, JsonObject } from "../did.js";

const MALFORMED: JsonObject = { error: "malformed-syslog" };

/** Thrown inside the parser; turned into `malformed-syslog`. */
class Malformed extends Error {}

const SP = 0x20;
const isDigit = (b: number | undefined): boolean => b !== undefined && b >= 0x30 && b <= 0x39;
const isPrint = (b: number | undefined): boolean => b !== undefined && b >= 33 && b <= 126;

/**
 * UTF-8 decoding, each maximal invalid subpart replaced with U+FFFD (WHATWG decode, which is
 * what a non-fatal `TextDecoder` does). Spec: E§3
 */
function utf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(bytes);
}

/** Header bytes, already restricted to ASCII 33–126 by the grammar. */
const ascii = (bytes: Uint8Array): string => String.fromCharCode(...bytes);

/** The message text: decoded, then every trailing CR and LF removed. Spec: E§3 */
function msgText(bytes: Uint8Array): string {
  return utf8(bytes).replace(/[\r\n]+$/, "");
}

interface SdElement {
  id: string;
  params: { name: string; value: string }[];
}

/** RFC 5424 parsing after the version and its space. Spec: E§3; RFC 5424 §6 */
function parse5424(b: Uint8Array, pos: number): JsonObject {
  // TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, each preceded by exactly one space
  const header: (string | null)[] = [];
  const limits = [Infinity, 255, 48, 128, 32];
  for (let f = 0; f < 5; f++) {
    if (f > 0) {
      if (b[pos] !== SP) throw new Malformed();
      pos++;
    }
    const start = pos;
    while (pos < b.length && isPrint(b[pos])) pos++;
    const len = pos - start;
    if (len < 1 || len > limits[f]!) throw new Malformed();
    const tok = ascii(b.subarray(start, pos));
    header.push(tok === "-" ? null : tok);
  }
  if (b[pos] !== SP) throw new Malformed();
  pos++;
  const sd: SdElement[] = [];
  if (b[pos] === 0x2d /* - */) {
    pos++;
  } else if (b[pos] === 0x5b /* [ */) {
    const name = (): string => {
      const s = pos;
      while (pos < b.length && isPrint(b[pos]) && b[pos] !== 0x3d && b[pos] !== 0x5d && b[pos] !== 0x22) pos++;
      if (pos - s < 1 || pos - s > 32) throw new Malformed();
      return ascii(b.subarray(s, pos));
    };
    while (b[pos] === 0x5b) {
      pos++;
      const id = name();
      const params: { name: string; value: string }[] = [];
      while (b[pos] === SP) {
        pos++;
        const n = name();
        if (b[pos] !== 0x3d || b[pos + 1] !== 0x22) throw new Malformed();
        pos += 2;
        const v: number[] = [];
        for (;;) {
          if (pos >= b.length) throw new Malformed();
          const c = b[pos]!;
          if (c === 0x22) break;
          if (c === 0x5c) {
            if (pos + 1 >= b.length) throw new Malformed();
            const nx = b[pos + 1]!;
            // RFC 5424 §6.3.3: only \" \\ \] are escapes; any other backslash is kept
            if (nx === 0x22 || nx === 0x5c || nx === 0x5d) v.push(nx);
            else v.push(c, nx);
            pos += 2;
            continue;
          }
          v.push(c);
          pos++;
        }
        pos++; // the closing quote
        params.push({ name: n, value: utf8(Uint8Array.from(v)) });
      }
      if (b[pos] !== 0x5d) throw new Malformed();
      pos++;
      sd.push({ id, params });
    }
  } else {
    throw new Malformed();
  }
  let msg = "";
  if (pos < b.length) {
    if (b[pos] !== SP) throw new Malformed();
    let m = b.subarray(pos + 1);
    if (m[0] === 0xef && m[1] === 0xbb && m[2] === 0xbf) m = m.subarray(3);
    msg = msgText(m);
  }
  return {
    format: "rfc5424",
    timestamp: header[0]!,
    hostname: header[1]!,
    app_name: header[2]!,
    procid: header[3]!,
    msgid: header[4]!,
    structured_data: sd as unknown as Json[],
    msg,
  };
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** `Mmm dd hh:mm:ss` exactly. Spec: E§3; RFC 3164 §4.1.2 */
function isBsdTimestamp(t: string): boolean {
  const m = /^([A-Z][a-z]{2}) ( [1-9]|[12][0-9]|3[01]) ([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/.exec(t);
  return m !== null && MONTHS.includes(m[1]!);
}

const isTagByte = (c: number): boolean =>
  (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || isDigit(c) || c === 0x5f || c === 0x2e || c === 0x2d || c === 0x2f;

/** RFC 3164 parsing of the bytes after `>`. Spec: E§3; RFC 3164 §4.1.2–§4.1.3 */
function parse3164(b: Uint8Array): JsonObject {
  let timestamp: string | null = null;
  let hostname: string | null = null;
  let content = b;
  if (b.length >= 16 && b[15] === SP && isBsdTimestamp(ascii(b.subarray(0, 15)))) {
    timestamp = ascii(b.subarray(0, 15));
    content = b.subarray(16);
    let e = 0;
    while (e < content.length && content[e] !== SP) e++;
    const tok = content.subarray(0, e);
    if (e >= 1 && e < content.length && tok.every((c) => isPrint(c))) {
      hostname = ascii(tok);
      content = content.subarray(e + 1);
    }
  }
  let appName: string | null = null;
  let procid: string | null = null;
  let msgBytes = content;
  let r = 0;
  while (r < content.length && isTagByte(content[r]!)) r++;
  if (r >= 1 && r <= 32) {
    let after = -1; // index just past the ':'
    let pid: string | null = null;
    if (content[r] === 0x3a) {
      after = r + 1;
    } else if (content[r] === 0x5b) {
      let d = r + 1;
      while (d < content.length && isDigit(content[d])) d++;
      const n = d - (r + 1);
      if (n >= 1 && n <= 10 && content[d] === 0x5d && content[d + 1] === 0x3a) {
        pid = ascii(content.subarray(r + 1, d));
        after = d + 2;
      }
    }
    if (after >= 0) {
      appName = ascii(content.subarray(0, r));
      procid = pid;
      msgBytes = content.subarray(after);
      if (msgBytes[0] === SP) msgBytes = msgBytes.subarray(1);
    }
  }
  return {
    format: "rfc3164",
    timestamp,
    hostname,
    app_name: appName,
    procid,
    msgid: null,
    structured_data: [],
    msg: msgText(msgBytes),
  };
}

/**
 * A syslog datagram (bytes) as `{syslog: {...}}`, or `{error: "malformed-syslog"}`.
 *
 * Spec: E§3 — RFC 5424 when the PRI is followed by a version and a space, else RFC 3164; a
 * datagram without a valid PRI (0–191) is malformed. The grammar is the vectors README's.
 * README `check: "syslog"`: a leading `0` only as the single digit `0`, so `<00>` is malformed.
 */
export function parseSyslog(datagram: Uint8Array): JsonObject {
  try {
    const b = datagram;
    if (b[0] !== 0x3c) throw new Malformed();
    let p = 1;
    while (p < b.length && p <= 4 && isDigit(b[p])) p++;
    const nd = p - 1;
    if (nd < 1 || nd > 3 || b[p] !== 0x3e) throw new Malformed();
    if (b[1] === 0x30 && nd > 1) throw new Malformed();
    const pri = Number(ascii(b.subarray(1, p)));
    if (pri > 191) throw new Malformed();
    p++; // past '>'
    const head = { facility: Math.floor(pri / 8), severity: pri % 8 };
    // RFC 5424: 1–3 digits, the first not 0, then a space
    let v = p;
    while (v < b.length && v - p < 4 && isDigit(b[v])) v++;
    const vd = v - p;
    let body: JsonObject;
    if (vd >= 1 && vd <= 3 && b[p] !== 0x30 && b[v] === SP) {
      if (vd !== 1 || b[p] !== 0x31) throw new Malformed();
      body = parse5424(b, v + 1);
    } else {
      body = parse3164(b.subarray(p));
    }
    const s = body;
    return {
      syslog: {
        format: s["format"]!,
        facility: head.facility,
        severity: head.severity,
        timestamp: s["timestamp"]!,
        hostname: s["hostname"]!,
        app_name: s["app_name"]!,
        procid: s["procid"]!,
        msgid: s["msgid"]!,
        structured_data: s["structured_data"]!,
        msg: s["msg"]!,
      },
    };
  } catch (e) {
    if (e instanceof Malformed) return MALFORMED;
    throw e;
  }
}

/** The match conditions of a syslog rule. Spec: E§4 */
interface SyslogMatch {
  app_name?: string;
  msgid?: string;
  hostname?: string;
  facility?: number;
  msg_contains?: string;
}

/**
 * Map a `raw.syslog` event to an alarm through the rule table; rules with `trap_oid` never match.
 *
 * Spec: E§4 — the first matching rule wins; a raise takes the rule's severity, else the
 * table's, and with neither is an event with no alarm; `resource_sd` refines the resource; an
 * unmatched message the table maps raises `(source, syslog, app_name or "")`.
 * `resource_sd` reads the first structured-data element with that `id` and, in it, the first
 * parameter with that name; a later element with the same id is never consulted.
 */
export function mapSyslog(
  syslog: JsonObject,
  rules: JsonObject[],
  source: string,
  tableSeverity: (sev: number) => string | null,
): JsonObject {
  const matches = (m: SyslogMatch): boolean => {
    for (const f of ["app_name", "msgid", "hostname"] as const) {
      if (f in m && (syslog[f] === null || syslog[f] !== m[f])) return false;
    }
    if ("facility" in m && syslog["facility"] !== m.facility) return false;
    if ("msg_contains" in m && !String(syslog["msg"]).includes(String(m.msg_contains))) return false;
    return true;
  };
  const sev = syslog["severity"] as number;
  const rule = rules.find((r) => r["syslog"] !== undefined && r["syslog"] !== null && matches(r["syslog"] as SyslogMatch));
  if (!rule) {
    const s = tableSeverity(sev);
    if (s === null) return { notify: true };
    return {
      alarm: { resource: source, type: "syslog", qualifier: (syslog["app_name"] as string | null) ?? "", severity: s, cleared: false },
    };
  }
  if (rule["action"] === "notify") return { notify: true };
  let resource = source;
  const rsd = rule["resource_sd"] as JsonObject | undefined;
  if (rsd) {
    const el = (syslog["structured_data"] as unknown as SdElement[]).find((e) => e.id === rsd["id"]);
    const prm = el?.params.find((p) => p.name === rsd["param"]);
    if (prm) resource = `${source}/${prm.value}`;
  }
  const type = (rule["type"] as string | undefined) ?? "";
  if (rule["action"] === "clear") return { alarm: { resource, type, qualifier: "", severity: null, cleared: true } };
  const own = rule["severity"];
  const severity = own !== undefined && own !== null ? (own as string) : tableSeverity(sev);
  if (severity === null) return { notify: true };
  return { alarm: { resource, type, qualifier: "", severity, cleared: false } };
}
