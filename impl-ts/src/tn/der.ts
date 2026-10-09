/**
 * A strict DER reader: just enough ASN.1 to walk an X.509 certificate and a TNAuthList.
 *
 * Spec: none (infrastructure) for the reader itself; the strictness is the vectors README's
 * ("Kind: `tn-binding`", step 2: "lengths are definite and minimal (the short form below 128)",
 * "an `INTEGER` has no redundant leading `00` or `FF` byte", "every tagged or constructed element
 * holds exactly its contents"), from X.690 §10 (DER).
 * Impl: the same strict reader parses the whole certificate, not only the TNAuthList: the README says each
 * block is a certificate "in DER", and DER has one encoding per value.
 */

/** A DER element that does not decode. Every caller turns it into a step reason. */
export class DerError extends Error {}

/** One decoded TLV. `raw` is the whole element (tag, length and contents) as received. */
export interface Tlv {
  /** The identifier octet. Impl: only low tag numbers (< 31) are read; a high-tag-number form is an error. */
  tag: number;
  /** The contents octets. */
  value: Buffer;
  /** The whole encoding, tag through contents. */
  raw: Buffer;
}

/** True when the identifier octet has the constructed bit. */
export const constructed = (tag: number): boolean => (tag & 0x20) !== 0;

/** Read one element at `offset`; throws {@link DerError} on any non-DER length or truncation. */
export function readTlv(buf: Buffer, offset: number): { tlv: Tlv; next: number } {
  if (offset >= buf.length) throw new DerError("truncated tag");
  const tag = buf[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("high tag number");
  let i = offset + 1;
  if (i >= buf.length) throw new DerError("truncated length");
  const first = buf[i++]!;
  let len: number;
  if (first < 0x80) len = first;
  else if (first === 0x80) throw new DerError("indefinite length");
  else {
    const n = first & 0x7f;
    if (n > 4) throw new DerError("length too long");
    if (i + n > buf.length) throw new DerError("truncated length");
    if (buf[i] === 0) throw new DerError("non-minimal length");
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++]!;
    if (len < 0x80) throw new DerError("non-minimal length");
  }
  if (i + len > buf.length) throw new DerError("truncated contents");
  return { tlv: { tag, value: buf.subarray(i, i + len), raw: buf.subarray(offset, i + len) }, next: i + len };
}

/** Decode exactly one element filling `buf`; trailing bytes are an error. */
export function readOne(buf: Buffer): Tlv {
  const { tlv, next } = readTlv(buf, 0);
  if (next !== buf.length) throw new DerError("trailing bytes");
  return tlv;
}

/** The children of a constructed element, which must fill its contents exactly. */
export function children(tlv: Tlv): Tlv[] {
  if (!constructed(tlv.tag)) throw new DerError("not constructed");
  const out: Tlv[] = [];
  let i = 0;
  while (i < tlv.value.length) {
    const { tlv: child, next } = readTlv(tlv.value, i);
    out.push(child);
    i = next;
  }
  return out;
}

/** Require `tlv` to carry `tag`; returns it. */
export function expectTag(tlv: Tlv | undefined, tag: number): Tlv {
  if (!tlv || tlv.tag !== tag) throw new DerError(`expected tag ${tag.toString(16)}`);
  return tlv;
}

/** Universal tags used here. */
export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

/** A DER INTEGER as a bigint: two's complement, no redundant leading `00`/`FF` byte (X.690 §8.3.2). */
export function integer(tlv: Tlv): bigint {
  expectTag(tlv, TAG.INTEGER);
  const v = tlv.value;
  if (v.length === 0) throw new DerError("empty integer");
  if (v.length > 1 && ((v[0] === 0x00 && (v[1]! & 0x80) === 0) || (v[0] === 0xff && (v[1]! & 0x80) !== 0))) {
    throw new DerError("non-minimal integer");
  }
  let n = 0n;
  for (const b of v) n = (n << 8n) | BigInt(b);
  if (v[0]! & 0x80) n -= 1n << BigInt(8 * v.length);
  return n;
}

/** A DER BOOLEAN. Impl: only `00` and `FF` (X.690 §11.1); any other contents byte does not parse. */
export function boolean(tlv: Tlv): boolean {
  expectTag(tlv, TAG.BOOLEAN);
  if (tlv.value.length !== 1 || (tlv.value[0] !== 0 && tlv.value[0] !== 0xff)) throw new DerError("bad boolean");
  return tlv.value[0] === 0xff;
}

/** An OBJECT IDENTIFIER in dotted form; minimal base-128 arcs (X.690 §8.19). */
export function oid(tlv: Tlv): string {
  expectTag(tlv, TAG.OID);
  const v = tlv.value;
  if (v.length === 0 || (v[v.length - 1]! & 0x80) !== 0) throw new DerError("bad oid");
  const arcs: bigint[] = [];
  let n = 0n;
  let start = true;
  for (const b of v) {
    if (start && b === 0x80) throw new DerError("non-minimal oid arc");
    start = false;
    n = (n << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(n);
      n = 0n;
      start = true;
    }
  }
  const first = arcs[0]!;
  const head = first < 40n ? [0n, first] : first < 80n ? [1n, first - 40n] : [2n, first - 80n];
  return [...head, ...arcs.slice(1)].join(".");
}

/**
 * A DER BIT STRING: the unused-bit count and the bits. Unused bits must be zero, and an empty string has
 * no unused bits (X.690 §11.2).
 */
export function bitString(tlv: Tlv): { unused: number; bytes: Buffer } {
  expectTag(tlv, TAG.BIT_STRING);
  const v = tlv.value;
  if (v.length === 0) throw new DerError("empty bit string");
  const unused = v[0]!;
  if (unused > 7 || (v.length === 1 && unused !== 0)) throw new DerError("bad bit string");
  const bytes = v.subarray(1);
  if (unused && (bytes[bytes.length - 1]! & ((1 << unused) - 1)) !== 0) throw new DerError("non-zero unused bits");
  return { unused, bytes };
}
