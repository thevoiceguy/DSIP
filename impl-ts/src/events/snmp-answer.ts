/**
 * The gateway's answers to SNMPv3, byte for byte: USM Reports (discovery, the time window) and Responses to informs,
 * and the TSM Response and discovery answer.
 *
 * Spec: E§3 (spec-gap 168); RFC 3412 §6.2, §7.1; RFC 3414 §3.1, §3.2; RFC 3416 §4.2.7; RFC 3826 §3.1.2.1; RFC 5343.
 * The exact bytes are the vectors README's `check: "snmp-answer"`.
 */
import { createCipheriv, createDecipheriv, createHmac } from "node:crypto";
import type { JsonObject } from "../did.js";
import { AUTH, Bad, children, parseMessage, tlv, type Tlv } from "./usm.js";

/** Spec: E§3 (spec-gap 168) — the largest UDP payload. */
const MAX_SIZE = 65507;
const REPORT_OID: Record<string, string> = {
  "unknown-engine-id": "1.3.6.1.6.3.15.1.1.4.0", // usmStatsUnknownEngineIDs
  "not-in-time-window": "1.3.6.1.6.3.15.1.1.2.0", // usmStatsNotInTimeWindows
};
const SNMP_ENGINE_ID = "1.3.6.1.6.3.10.2.1.1.0";

/** A definite length in its shortest form. */
function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function enc(tag: number, body: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
}

/** An INTEGER in its shortest two's complement form. */
function int(v: bigint): Buffer {
  const bytes: number[] = [];
  let x = v;
  for (;;) {
    bytes.unshift(Number(x & 0xffn));
    const top = bytes[0]! & 0x80;
    x >>= 8n;
    if ((x === 0n && !top) || (x === -1n && top)) break;
  }
  return enc(0x02, Buffer.from(bytes));
}

/** An unsigned value (Counter32) in its shortest form, with a leading 00 when the top bit would be set. */
function uint(tag: number, v: bigint): Buffer {
  const bytes: number[] = [];
  for (let x = v; bytes.length === 0 || x > 0n; x >>= 8n) bytes.unshift(Number(x & 0xffn));
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return enc(tag, Buffer.from(bytes));
}

function oid(dotted: string): Buffer {
  const p = dotted.split(".").map(BigInt);
  const out: number[] = [];
  for (const sub of [p[0]! * 40n + p[1]!, ...p.slice(2)]) {
    const chunk = [Number(sub & 0x7fn)];
    for (let x = sub >> 7n; x > 0n; x >>= 7n) chunk.unshift(0x80 | Number(x & 0x7fn));
    out.push(...chunk);
  }
  return enc(0x06, Buffer.from(out));
}

interface Clock {
  engine_id: string;
  boots: number;
  time: number;
}

/** The whole message, and where `sec` (securityParameters' content) starts in it. */
function message(msgId: bigint, flags: number, model: number, sec: Buffer, data: Buffer): { msg: Buffer; at: number } {
  const head = Buffer.concat([int(3n), enc(0x30, Buffer.concat([int(msgId), int(BigInt(MAX_SIZE)), enc(0x04, Buffer.from([flags])), int(BigInt(model))]))]);
  const body = Buffer.concat([head, enc(0x04, sec), data]);
  return { msg: enc(0x30, body), at: 1 + len(body.length).length + head.length + 1 + len(sec.length).length };
}

/** A USM message from the gateway's engine: encrypted when `flags` say priv, then authenticated when they say auth. */
function usm(msgId: bigint, flags: number, local: Clock, userName: Uint8Array, scoped: Buffer, user: JsonObject | undefined, salt: Buffer): Buffer {
  let data = scoped;
  if (flags & 2) {
    const iv = Buffer.alloc(16);
    iv.writeUInt32BE(local.boots, 0);
    iv.writeUInt32BE(local.time, 4);
    salt.copy(iv, 8);
    const c = createCipheriv("aes-128-cfb", Buffer.from(user!["priv_key"] as string, "hex").subarray(0, 16), iv);
    data = enc(0x04, Buffer.concat([c.update(scoped), c.final()]));
  }
  const proto = flags & 1 ? AUTH[user!["auth"] as string]! : null;
  const macLen = proto ? proto.mac : 0;
  const head = Buffer.concat([enc(0x04, Buffer.from(local.engine_id, "hex")), int(BigInt(local.boots)), int(BigInt(local.time)), enc(0x04, userName)]);
  const content = Buffer.concat([head, enc(0x04, Buffer.alloc(macLen)), enc(0x04, flags & 2 ? salt : Buffer.alloc(0))]);
  const { msg, at } = message(msgId, flags, 3, enc(0x30, content), data);
  if (!proto) return msg;
  // past the SEQUENCE's tag and length, the fields before authParams, and authParams' tag and one-byte length
  const zeros = at + 1 + len(content.length).length + head.length + 2;
  const mac = createHmac(proto.hash, Buffer.from(user!["auth_key"] as string, "hex")).update(msg).digest().subarray(0, macLen);
  mac.copy(msg, zeros);
  return msg;
}

/** The parts of a ScopedPDU's bytes that an answer copies: its contexts, request-id and VarBindList as received. */
function scopedParts(b: Uint8Array): { engine: Uint8Array; name: Uint8Array; rid: bigint; vbl: Uint8Array } {
  const outer = tlv(b, 0, b.length);
  if (outer.tag !== 0x30 || outer.end !== b.length) throw new Bad();
  const [e, n, pdu] = children(b, outer) as [Tlv, Tlv, Tlv];
  const parts = children(b, pdu);
  const vblStart = parts[2]!.end; // the VarBindList's tag follows error-index
  const ridT = parts[0]!;
  let rid = 0n;
  const raw = b.subarray(ridT.start, ridT.end);
  for (const x of raw) rid = (rid << 8n) | BigInt(x);
  if (raw[0]! & 0x80) rid -= 1n << BigInt(8 * raw.length);
  return { engine: b.subarray(e.start, e.end), name: b.subarray(n.start, n.end), rid, vbl: b.subarray(vblStart, parts[3]!.end) };
}

function scoped(engine: Uint8Array, name: Uint8Array, tag: number, rid: bigint, vbl: Uint8Array): Buffer {
  return enc(0x30, Buffer.concat([enc(0x04, engine), enc(0x04, name), enc(tag, Buffer.concat([int(rid), int(0n), int(0n), vbl]))]));
}

/**
 * README `check: "snmp-answer"`: the gateway's answer to a received SNMPv3 message, or `malformed`.
 * Spec: E§3 (spec-gap 168) — the received `msgID` and `userName`; a Report at noAuthNoPriv (discovery) or authNoPriv
 * (the time window), never encrypted, request-id 0; a Response with the inform's contexts, request-id and
 * VarBindList as received; `msgFlags` the auth and priv bits only.
 */
export function snmpAnswer(input: JsonObject): JsonObject {
  const b = Buffer.from(input["message"] as string, "hex");
  const local = input["local"] as unknown as Clock;
  const kind = input["answer"] as string;
  const user = input["user"] as JsonObject | undefined;
  const engineId = Buffer.from(local.engine_id, "hex");
  try {
    const top = tlv(b, 0, b.length);
    const [, globalT, , dataT] = children(b, top) as [Tlv, Tlv, Tlv, Tlv];
    const [idT, , flagsT, modelT] = children(b, globalT) as [Tlv, Tlv, Tlv, Tlv];
    let msgId = 0n;
    for (const x of b.subarray(idT.start, idT.end)) msgId = (msgId << 8n) | BigInt(x);
    const flags = b[flagsT.start]! & 0x03;
    const model = b[modelT.end - 1]!;
    const dataStart = children(b, top)[2]!.end;
    if (REPORT_OID[kind]) {
      const m = parseMessage(b);
      const vbl = enc(0x30, enc(0x30, Buffer.concat([oid(REPORT_OID[kind]), uint(0x41, BigInt(input["counter"] as number))])));
      const reportFlags = kind === "not-in-time-window" ? 0x01 : 0x00; // RFC 3414 §3.2 step 7a: authNoPriv
      return { answer: usm(msgId, reportFlags, local, m.userName, scoped(engineId, Buffer.alloc(0), 0xa8, 0n, vbl), user, Buffer.alloc(0)).toString("hex") };
    }
    if (modelT.end - modelT.start === 1 && model === 4) {
      parseMessage(b, true); // TSM (E§3): a plaintext ScopedPDU
      const p = scopedParts(b.subarray(dataStart, dataT.end));
      const vbl = kind === "discovery" ? enc(0x30, enc(0x30, Buffer.concat([oid(SNMP_ENGINE_ID), enc(0x04, engineId)]))) : p.vbl;
      return { answer: message(msgId, flags, 4, Buffer.alloc(0), scoped(p.engine, p.name, 0xa2, p.rid, vbl)).msg.toString("hex") };
    }
    const m = parseMessage(b);
    let plain: Uint8Array = b.subarray(dataStart, dataT.end);
    if (m.priv) {
      const iv = Buffer.alloc(16);
      iv.writeUInt32BE(m.boots, 0);
      iv.writeUInt32BE(m.time, 4);
      Buffer.from(m.privParams).copy(iv, 8);
      const d = createDecipheriv("aes-128-cfb", Buffer.from(user!["priv_key"] as string, "hex").subarray(0, 16), iv);
      plain = Buffer.concat([d.update(m.encrypted!), d.final()]);
    }
    const p = scopedParts(plain);
    const salt = flags & 2 ? Buffer.from(input["salt"] as string, "hex") : Buffer.alloc(0);
    return { answer: usm(msgId, flags, local, m.userName, scoped(p.engine, p.name, 0xa2, p.rid, p.vbl), user, salt).toString("hex") };
  } catch (e) {
    if (e instanceof Bad || e instanceof RangeError || e instanceof TypeError) return { error: "malformed" };
    throw e;
  }
}
