/**
 * Byte and text encodings the wire format depends on.
 *
 * Spec: §10.2 (base64url envelope members), §10.3 (UTF-8, no floats, ULID ids), §7.2 (did:key multibase).
 */

const B64URL = /^[A-Za-z0-9_-]*$/;

/** Decode unpadded base64url; `null` when the text is not base64url. Spec: §10.2 */
export function b64urlDecode(text: string): Buffer | null {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  return Buffer.from(text, "base64url");
}

/** Strict UTF-8 decode; `null` on any invalid sequence. Spec: §10.3 */
export function utf8Decode(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * True when any JSON number in `text` is written with a fraction or an exponent.
 *
 * Spec: §10.3 — floats are forbidden even when integral (`1760000000.0`).
 * Impl: the check is lexical, on the signed text, because `JSON.parse` erases the difference
 * between `1.0` and `1`. `text` must already be known to be valid JSON.
 */
export function hasFloat(text: string): boolean {
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    if (c === '"') {
      i++;
      while (text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
      i++;
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      const start = i;
      while (i < text.length && /[-+0-9.eE]/.test(text[i]!)) i++;
      if (/[.eE]/.test(text.slice(start, i))) return true;
    } else {
      i++;
    }
  }
  return false;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Decode base58btc; `null` on a character outside the alphabet. */
export function base58Decode(text: string): Buffer | null {
  let n = 0n;
  for (const ch of text) {
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    n = n * 58n + BigInt(v);
  }
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of text) {
    if (ch !== "1") break;
    out.unshift(0);
  }
  return Buffer.from(out);
}

/**
 * The raw Ed25519 public key inside a `z6Mk…` multibase value, or `null`.
 *
 * Spec: §7.2 — multibase `z` (base58btc) over multicodec `ed25519-pub` (0xed 0x01) + 32 key bytes.
 */
export function ed25519FromMultibase(multibase: string): Buffer | null {
  if (!multibase.startsWith("z")) return null;
  const raw = base58Decode(multibase.slice(1));
  if (!raw || raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) return null;
  return raw.subarray(2);
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** True for a 26-character Crockford base32 ULID. Spec: §10.3 */
export function isUlid(text: string): boolean {
  return /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(text);
}

/** The ULID's 48-bit timestamp in whole seconds, or `null` when `text` is not a ULID. Spec: §20.6 */
export function ulidSeconds(text: string): number | null {
  if (!isUlid(text)) return null;
  let ms = 0;
  for (const ch of text.slice(0, 10)) ms = ms * 32 + CROCKFORD.indexOf(ch);
  return Math.floor(ms / 1000);
}
