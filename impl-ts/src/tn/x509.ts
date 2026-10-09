/**
 * PEM, X.509 v3 certificates and the TNAuthList extension, as a number binding's verifier reads them.
 *
 * Spec: N§3.2 (the certificate rules, RFC 8226 as SHAKEN uses them); RFC 5280 §4.1 (certificate structure),
 * §4.2.1.3 (keyUsage), §4.2.1.9 (basicConstraints); RFC 8226 §9 (TNAuthList, EXPLICIT tags); RFC 7468 (PEM).
 * Impl: the parsing rules are the vectors README's ("Kind: `tn-binding`", step 2); where it is silent the
 * choices are marked `Impl:` below.
 */
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { DerError, TAG, bitString, boolean, children, expectTag, integer, oid, readOne, type Tlv } from "./der.js";

/** ecdsa-with-SHA256 with no parameters: `SEQUENCE { OID 1.2.840.10045.4.3.2 }`. Spec: N§3.2 (algorithms) */
const ECDSA_SHA256 = Buffer.from("300a06082a8648ce3d040302", "hex");
const EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const PRIME256V1 = "1.2.840.10045.3.1.7";
const BASIC_CONSTRAINTS = "2.5.29.19";
const KEY_USAGE = "2.5.29.15";
/** id-pe-TNAuthList. Spec: RFC 8226 §9 */
const TN_AUTH_LIST = "1.3.6.1.5.5.7.1.26";
/** The critical extensions a verifier recognizes. Spec: N§3.4 step 2 (unknown critical extension) */
const RECOGNIZED = new Set([BASIC_CONSTRAINTS, KEY_USAGE, TN_AUTH_LIST]);
const ORGANIZATION = "2.5.4.10";
const COMMON_NAME = "2.5.4.3";

/** One certificate extension, undecoded. */
export interface Extension {
  /** extnID, dotted. */
  id: string;
  /** The critical flag (DEFAULT FALSE). */
  critical: boolean;
  /** The extnValue OCTET STRING's contents. */
  value: Buffer;
}

/** A parsed certificate: the fields the path rules read, with the raw DER they compare. */
export interface Certificate {
  /** The whole certificate DER. */
  raw: Buffer;
  /** The tbsCertificate element as received: the bytes its issuer signed. */
  tbs: Buffer;
  /** The outer signatureAlgorithm element. */
  signatureAlgorithm: Buffer;
  /** The tbsCertificate's own signature AlgorithmIdentifier element. */
  tbsSignatureAlgorithm: Buffer;
  /** The signatureValue contents (a DER ECDSA-Sig-Value for the algorithms allowed here). */
  signature: Buffer;
  /** The issuer Name element, DER. */
  issuer: Buffer;
  /** The subject Name element, DER. */
  subject: Buffer;
  /** The subject Name as RDNs of (type, value element), in encoded order. */
  subjectAttributes: { type: string; value: Tlv }[];
  /** The SubjectPublicKeyInfo element, DER. */
  spki: Buffer;
  /** notBefore, Unix seconds. */
  notBefore: number;
  /** notAfter, Unix seconds. */
  notAfter: number;
  /** The extensions, in encoded order. */
  extensions: Extension[];
  /** The extensions the path rules read, decoded at parse time. */
  known: KnownExtensions;
}

// ---------------------------------------------------------------------------------------------------------
// PEM

/** What a PEM body loses before base64: SP, HT, CR and LF only (README step 2 "PEM"; FF and VT stay). */
const BODY_WS = /[\t\n\r ]/g;
const BEGIN = "-----BEGIN CERTIFICATE-----";
const END = "-----END CERTIFICATE-----";

/**
 * Strict padded base64: the standard alphabet, a length that is a multiple of 4, and at most two `=` at the end.
 * `null` when the text is not that.
 *
 * Spec: README step 2 "PEM" and "Context" (RFC 4648 alphabet, `=` padding, no whitespace); non-zero unused bits
 * in the last character are accepted (RFC 4648 §3.5).
 */
export function base64Decode(text: string): Buffer | null {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  return Buffer.from(text, "base64");
}

/**
 * The certificate blocks in a PEM text, leaf first, as DER; `null` when a block's body is not padded base64,
 * a block is left open, or there is no block.
 *
 * Spec: N§3.1 (`x5u` serves the chain in PEM, leaf first); README step 2 "PEM": lines end in LF or CRLF, a marker
 * line is exactly the marker, and a BEGIN left open anywhere fails the text.
 */
export function pemBlocks(text: string): Buffer[] | null {
  const lines = text.split("\n").map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));
  const out: Buffer[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] !== BEGIN) continue;
    const end = lines.indexOf(END, i + 1);
    if (end < 0) return null; // a block left open
    const der = base64Decode(lines.slice(i + 1, end).join("").replace(BODY_WS, ""));
    if (!der) return null;
    out.push(der);
    i = end;
  }
  return out.length ? out : null;
}

// ---------------------------------------------------------------------------------------------------------
// Certificates

/** A UTCTime or GeneralizedTime as Unix seconds. Spec: RFC 5280 §4.1.2.5.1–2 (Z, seconds, no fraction). */
function time(tlv: Tlv): number {
  const s = tlv.value.toString("latin1");
  let m: RegExpExecArray | null;
  let year: number;
  if (tlv.tag === TAG.UTC_TIME && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    const yy = Number(m[1]);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
  } else if (tlv.tag === TAG.GENERALIZED_TIME && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    year = Number(m[1]);
  } else throw new DerError("bad time");
  const [mo, d, h, mi, se] = m.slice(2, 7).map(Number) as [number, number, number, number, number];
  const ms = Date.UTC(year, mo - 1, d, h, mi, se);
  const back = new Date(ms);
  if (back.getUTCFullYear() !== year || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59 || se > 59) {
    throw new DerError("bad time");
  }
  return Math.floor(ms / 1000);
}

/** A Name: SEQUENCE OF SET (non-empty) OF SEQUENCE { type OID, value }. Returns its attributes in encoded order. */
function name(tlv: Tlv): { type: string; value: Tlv }[] {
  expectTag(tlv, TAG.SEQUENCE);
  const out: { type: string; value: Tlv }[] = [];
  for (const rdn of children(tlv)) {
    const atvs = children(expectTag(rdn, TAG.SET));
    if (!atvs.length) throw new DerError("empty rdn");
    for (const atv of atvs) {
      const parts = children(expectTag(atv, TAG.SEQUENCE));
      if (parts.length !== 2) throw new DerError("bad attribute");
      out.push({ type: oid(parts[0]!), value: parts[1]! });
    }
  }
  return out;
}

/** An AlgorithmIdentifier: SEQUENCE { OID, optional parameters }. */
function algorithm(tlv: Tlv): { id: string; params?: Tlv } {
  const parts = children(expectTag(tlv, TAG.SEQUENCE));
  if (parts.length < 1 || parts.length > 2) throw new DerError("bad algorithm");
  return parts[1] ? { id: oid(parts[0]!), params: parts[1] } : { id: oid(parts[0]!) };
}

/**
 * Parse one certificate. Throws {@link DerError} when it is not an X.509 v3 certificate in DER.
 *
 * Spec: RFC 5280 §4.1; README step 2 "Parse" ("an X.509 v3 certificate in DER").
 * Spec: README step 2 "Parse", which holds for every block, after an anchor too: version 2, DER with nothing
 * after it, the tbsCertificate `signature` byte-for-byte the outer `signatureAlgorithm`, no extension twice
 * (RFC 5280 §4.2), and basicConstraints, keyUsage and TNAuthList decoding (see {@link extensionsOf}).
 * Impl: in the zone the README leaves unpinned (spec-gap 110) this reader is strict DER: an encoded DEFAULT
 * (`critical FALSE`), a BOOLEAN other than `00`/`FF` and an empty extensions list do not parse.
 */
export function parseCertificate(der: Buffer): Certificate {
  const top = children(expectTag(readOne(der), TAG.SEQUENCE));
  if (top.length !== 3) throw new DerError("certificate is not three elements");
  const [tbsTlv, sigAlg, sigVal] = top as [Tlv, Tlv, Tlv];
  algorithm(sigAlg);
  const sig = bitString(sigVal);
  if (sig.unused !== 0) throw new DerError("signature has unused bits");
  const f = children(expectTag(tbsTlv, TAG.SEQUENCE));
  let i = 0;
  const version = expectTag(f[i++], 0xa0);
  const v = children(version);
  if (v.length !== 1 || integer(v[0]!) !== 2n) throw new DerError("not v3");
  integer(f[i++]!); // serialNumber
  const tbsSigAlg = f[i++]!;
  algorithm(tbsSigAlg);
  const issuer = f[i++]!;
  name(issuer);
  const validity = children(expectTag(f[i++], TAG.SEQUENCE));
  if (validity.length !== 2) throw new DerError("bad validity");
  const subject = f[i++]!;
  const subjectAttributes = name(subject);
  const spki = f[i++]!;
  const spkiParts = children(expectTag(spki, TAG.SEQUENCE));
  if (spkiParts.length !== 2) throw new DerError("bad spki");
  algorithm(spkiParts[0]!);
  bitString(spkiParts[1]!);
  if (f[i]?.tag === 0x81) i++; // issuerUniqueID
  if (f[i]?.tag === 0x82) i++; // subjectUniqueID
  const extensions: Extension[] = [];
  if (f[i]?.tag === 0xa3) {
    const wrapped = children(f[i++]!);
    if (wrapped.length !== 1) throw new DerError("bad extensions wrapper");
    const list = children(expectTag(wrapped[0], TAG.SEQUENCE));
    if (!list.length) throw new DerError("empty extensions");
    for (const ext of list) {
      const p = children(expectTag(ext, TAG.SEQUENCE));
      let k = 0;
      const id = oid(p[k++]!);
      const critical = p[k]?.tag === TAG.BOOLEAN ? boolean(p[k++]!) : false;
      if (p.length === 3 && !critical) throw new DerError("DEFAULT FALSE encoded"); // X.690 §11.5
      const value = expectTag(p[k++], TAG.OCTET_STRING).value;
      if (k !== p.length) throw new DerError("bad extension");
      if (extensions.some((e) => e.id === id)) throw new DerError("duplicate extension");
      extensions.push({ id, critical, value });
    }
  }
  if (i !== f.length) throw new DerError("unexpected tbsCertificate field");
  if (!tbsSigAlg.raw.equals(sigAlg.raw)) throw new DerError("tbs signature differs from signatureAlgorithm");
  const cert: Certificate = {
    raw: der,
    tbs: tbsTlv.raw,
    signatureAlgorithm: sigAlg.raw,
    tbsSignatureAlgorithm: tbsSigAlg.raw,
    signature: sig.bytes,
    issuer: issuer.raw,
    subject: subject.raw,
    subjectAttributes,
    spki: spki.raw,
    notBefore: time(validity[0]!),
    notAfter: time(validity[1]!),
    extensions,
    known: { unknownCritical: false },
  };
  cert.known = extensionsOf(cert);
  return cert;
}

/**
 * The certificate's key when it is id-ecPublicKey on prime256v1 with a valid point; `null` otherwise.
 *
 * Spec: N§3.2 (every certificate "holds a P-256 key"); README step 2 ("the point is valid").
 * Impl: the point may be uncompressed (`04`, 65 bytes) or compressed (`02`/`03`, 33 bytes); the point at
 * infinity is refused; node:crypto (OpenSSL) checks that the point is on the curve.
 */
export function p256Key(cert: Certificate): KeyObject | null {
  try {
    const parts = children(readOne(cert.spki));
    const alg = algorithm(parts[0]!);
    if (alg.id !== EC_PUBLIC_KEY || !alg.params || oid(alg.params) !== PRIME256V1) return null;
    const { unused, bytes } = bitString(parts[1]!);
    if (unused !== 0) return null;
    const ok = (bytes.length === 65 && bytes[0] === 0x04) || (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03));
    if (!ok) return null;
    const key = createPublicKey({ key: cert.spki, format: "der", type: "spki" });
    return key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1" ? key : null;
  } catch {
    return null;
  }
}

/**
 * Whether the certificate is signed ecdsa-with-SHA256 with no parameters, in both places it names its algorithm.
 *
 * Spec: N§3.2 (algorithms); README step 2 ("its `signatureAlgorithm` is ecdsa-with-SHA256 … with no parameters").
 * The tbsCertificate's `signature` field is byte-for-byte the same (README step 2 "Parse"; RFC 5280 §4.1.1.2).
 */
export function signedEs256(cert: Certificate): boolean {
  return cert.signatureAlgorithm.equals(ECDSA_SHA256) && cert.tbsSignatureAlgorithm.equals(ECDSA_SHA256);
}

/** Whether `key` verifies `cert`'s signature over its tbsCertificate bytes (ECDSA, SHA-256, DER signature). */
export function signedBy(cert: Certificate, key: KeyObject | null): boolean {
  if (!key) return false;
  try {
    return verify("sha256", cert.tbs, key, cert.signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------------
// Extensions

/** One TNAuthList entry. Spec: RFC 8226 §9 (TNEntry) */
export type TnEntry = { spc: string } | { start: string; count: bigint } | { one: string };

/** The extensions the path rules read, decoded. */
export interface KnownExtensions {
  /** basicConstraints, when present. */
  basicConstraints?: { ca: boolean; pathLen?: bigint };
  /** keyUsage bits, when present. */
  keyUsage?: { digitalSignature: boolean; keyCertSign: boolean };
  /** TNAuthList entries, when present. */
  tnAuthList?: TnEntry[];
  /** True when a critical extension is not one of the three recognized. */
  unknownCritical: boolean;
}

/**
 * Decode the extensions the path rules read. Throws {@link DerError} when one does not decode; that is a parse
 * failure of the certificate.
 *
 * Spec: RFC 5280 §4.2.1.9, §4.2.1.3; RFC 8226 §9; README step 2.
 * README step 2 "Parse": basicConstraints and keyUsage decode, a negative pathLenConstraint does not, a
 * pathLenConstraint needs `cA` true, and a TNAuthList is well-formed.
 * Impl: an explicitly encoded `cA FALSE` does not decode (DER, X.690 §11.5; not pinned).
 */
export function extensionsOf(cert: Certificate): KnownExtensions {
  const out: KnownExtensions = { unknownCritical: false };
  for (const ext of cert.extensions) {
    if (ext.critical && !RECOGNIZED.has(ext.id)) out.unknownCritical = true;
    if (ext.id === BASIC_CONSTRAINTS) {
      const p = children(expectTag(readOne(ext.value), TAG.SEQUENCE));
      let k = 0;
      const explicitCa = p[k]?.tag === TAG.BOOLEAN;
      const ca = explicitCa ? boolean(p[k++]!) : false;
      if (explicitCa && !ca) throw new DerError("DEFAULT FALSE encoded"); // X.690 §11.5
      let pathLen: bigint | undefined;
      if (p[k]?.tag === TAG.INTEGER) {
        pathLen = integer(p[k++]!);
        if (pathLen < 0n) throw new DerError("negative pathLen");
        // RFC 5280 §4.2.1.9; README step 2 "Parse": no pathLenConstraint unless cA is true, even on a leaf
        if (!ca) throw new DerError("pathLen without cA");
      }
      if (k !== p.length) throw new DerError("bad basicConstraints");
      out.basicConstraints = pathLen === undefined ? { ca } : { ca, pathLen };
    } else if (ext.id === KEY_USAGE) {
      const { bytes } = bitString(readOne(ext.value));
      const bit = (n: number) => ((bytes[n >> 3] ?? 0) & (0x80 >> (n & 7))) !== 0;
      out.keyUsage = { digitalSignature: bit(0), keyCertSign: bit(5) };
    } else if (ext.id === TN_AUTH_LIST) {
      out.tnAuthList = tnAuthList(ext.value);
    }
  }
  return out;
}

/** A TelephoneNumber: IA5String of 1–15 characters from `0123456789#*`. Spec: RFC 8226 §9 */
function telephoneNumber(tlv: Tlv | undefined): string {
  const t = expectTag(tlv, TAG.IA5_STRING).value.toString("latin1");
  if (!/^[0-9#*]{1,15}$/.test(t)) throw new DerError("bad TelephoneNumber");
  return t;
}

/** The single element an EXPLICIT tag wraps. */
function explicit(tlv: Tlv): Tlv {
  const inner = children(tlv);
  if (inner.length !== 1) throw new DerError("explicit tag must wrap one element");
  return inner[0]!;
}

/**
 * Parse a TNAuthList extension value strictly. Throws {@link DerError} when it is not well-formed.
 *
 * Spec: RFC 8226 §9 (EXPLICIT tags); README step 2 "A well-formed TNAuthList".
 */
export function tnAuthList(value: Buffer): TnEntry[] {
  const entries = children(expectTag(readOne(value), TAG.SEQUENCE));
  if (!entries.length) throw new DerError("empty TNAuthList");
  return entries.map((e): TnEntry => {
    switch (e.tag) {
      case 0xa0: {
        const spc = expectTag(explicit(e), TAG.IA5_STRING).value;
        if (spc.length < 1 || spc.some((b) => b >= 0x80)) throw new DerError("bad spc");
        return { spc: spc.toString("latin1") };
      }
      case 0xa1: {
        const range = children(expectTag(explicit(e), TAG.SEQUENCE));
        if (range.length !== 2) throw new DerError("bad range");
        const start = telephoneNumber(range[0]);
        const count = integer(range[1]!);
        if (count < 2n) throw new DerError("range count below 2");
        return { start, count };
      }
      case 0xa2:
        return { one: telephoneNumber(explicit(e)) };
      default:
        throw new DerError("unknown TNEntry");
    }
  });
}

/**
 * Whether a TNAuthList covers the digits `d` (`tn` without its `+`).
 *
 * Spec: N§3.2 (coverage: `one`, `range`, `spc`); README step 4.
 */
export function covers(list: TnEntry[], d: string, spcNumbers: Record<string, unknown>): boolean {
  return list.some((e) => {
    if ("one" in e) return e.one === d;
    if ("start" in e) {
      if (!/^[0-9]+$/.test(e.start) || e.start.length !== d.length) return false;
      const diff = BigInt(d) - BigInt(e.start);
      return diff >= 0n && diff < e.count;
    }
    const assigned = Object.prototype.hasOwnProperty.call(spcNumbers, e.spc) ? spcNumbers[e.spc] : undefined;
    return Array.isArray(assigned) && assigned.includes(d);
  });
}

/**
 * Who attested the binding: the leaf subject's first organizationName, else its first commonName, else `null`.
 *
 * Spec: N§3.4 (the leaf certificate subject's first organization name, or its first common name).
 * Spec: README "Expect": only UTF8String and PrintableString values whose bytes are valid UTF-8 count; any other
 * attribute of the right type is passed over. The PrintableString character set is not checked (not pinned).
 */
export function attestedBy(cert: Certificate): string | null {
  const first = (type: string): string | null => {
    for (const a of cert.subjectAttributes) {
      if (a.type !== type) continue;
      if (a.value.tag === TAG.PRINTABLE_STRING || a.value.tag === TAG.UTF8_STRING) {
        try {
          return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(a.value.value);
        } catch {
          continue;
        }
      }
    }
    return null;
  };
  return first(ORGANIZATION) ?? first(COMMON_NAME);
}
