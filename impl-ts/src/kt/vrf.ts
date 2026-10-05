/**
 * ECVRF-EDWARDS25519-SHA512-TAI verification, on Edwards25519 point arithmetic written here with
 * BigInt (node:crypto has no raw point operations).
 *
 * Spec: T§2 (the cipher suite's VRF), T§5 item 2; RFC 9381 §5.3 (ECVRF_verify), §5.4.1.1
 * (encode_to_curve_try_and_increment), §5.4.3 (challenge generation), §5.4.4 (decode_proof),
 * §5.4.5 (validate_key), §5.2 (proof_to_hash), §5.5 (the EDWARDS25519-SHA512-TAI suite);
 * RFC 8032 §5.1 (curve constants, point addition, encoding §5.1.2, decoding §5.1.3).
 * Impl (spec-gap 104): `validate_key = TRUE`, which KEYTRANS leaves unstated.
 */
import { createHash } from "node:crypto";

/** The field prime 2^255 − 19. Spec: RFC 8032 §5.1 */
const P = (1n << 255n) - 19n;
/** The prime order of the base point. Spec: RFC 8032 §5.1 */
export const Q = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (a: bigint, m = P): bigint => ((a % m) + m) % m;

function pow(base: bigint, exp: bigint, m = P): bigint {
  let r = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return r;
}
const inv = (a: bigint): bigint => pow(a, P - 2n);

/** d = −121665/121666. Spec: RFC 8032 §5.1 */
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

/** A point in extended homogeneous coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z. Spec: RFC 8032 §5.1.4 */
export type Point = readonly [bigint, bigint, bigint, bigint];

const IDENTITY: Point = [0n, 1n, 1n, 0n];

/** Point addition. Spec: RFC 8032 §5.1.4 */
function add(a: Point, b: Point): Point {
  const [x1, y1, z1, t1] = a;
  const [x2, y2, z2, t2] = b;
  const A = mod((y1 - x1) * (y2 - x2));
  const B = mod((y1 + x1) * (y2 + x2));
  const C = mod(2n * t1 * t2 * D);
  const Dd = mod(2n * z1 * z2);
  const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}

const negate = ([x, y, z, t]: Point): Point => [mod(-x), y, z, mod(-t)];

/** Scalar multiplication, double-and-add. */
function mul(k: bigint, p: Point): Point {
  let r = IDENTITY;
  let q = p;
  while (k > 0n) {
    if (k & 1n) r = add(r, q);
    q = add(q, q);
    k >>= 1n;
  }
  return r;
}

const equalPoints = (a: Point, b: Point): boolean =>
  mod(a[0] * b[2] - b[0] * a[2]) === 0n && mod(a[1] * b[2] - b[1] * a[2]) === 0n;

const littleEndian = (bytes: Uint8Array): bigint => {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
};

/**
 * string_to_point: RFC 8032 §5.1.3 decoding, canonical only (y < p; not x = 0 with the sign bit set); `null` when the
 * string is not a point. Spec: RFC 9381 §5.5; RFC 8032 §5.1.3
 */
export function decodePoint(bytes: Uint8Array): Point | null {
  if (bytes.length !== 32) return null;
  const n = littleEndian(bytes);
  const x0 = n >> 255n;
  const y = n & ((1n << 255n) - 1n);
  if (y >= P) return null; // RFC 8032 §5.1.3 step 1
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === u) {
    // x is a square root
  } else if (vx2 === mod(-u)) x = mod(x * SQRT_M1);
  else return null;
  if (x === 0n && x0 === 1n) return null;
  if ((x & 1n) !== x0) x = P - x;
  return [x, y, 1n, mod(x * y)];
}

/** point_to_string: RFC 8032 §5.1.2 encoding. */
export function encodePoint(p: Point): Buffer {
  const zi = inv(p[2]);
  const x = mod(p[0] * zi);
  let y = mod(p[1] * zi);
  if (x & 1n) y |= 1n << 255n;
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(y & 0xffn);
    y >>= 8n;
  }
  return out;
}

/** The base point B. Spec: RFC 8032 §5.1 */
const BASE = decodePoint(Buffer.from("5866666666666666666666666666666666666666666666666666666666666666", "hex"))!;

/** suite_string for ECVRF-EDWARDS25519-SHA512-TAI. Spec: RFC 9381 §5.5 */
const SUITE = 0x03;
const COFACTOR = 8n;
/** cLen. Spec: RFC 9381 §5.5 */
const C_LEN = 16;

const sha512 = (...parts: Uint8Array[]): Buffer => {
  const h = createHash("sha512");
  for (const p of parts) h.update(p);
  return h.digest();
};

/**
 * ECVRF_encode_to_curve_try_and_increment, with encode_to_curve_salt = PK_string; `null` when the one-byte
 * counter is exhausted. Spec: RFC 9381 §5.4.1.1, §5.5; README "Kind: `alias-transparency`" (exhausted → invalid)
 */
function encodeToCurve(salt: Uint8Array, alpha: Uint8Array): Point | null {
  for (let ctr = 0; ctr < 256; ctr++) {
    const h = sha512(Uint8Array.of(SUITE, 0x01), salt, alpha, Uint8Array.of(ctr, 0x00));
    const point = decodePoint(h.subarray(0, 32)); // interpret_hash_value_as_a_point
    if (point) return mul(COFACTOR, point);
  }
  return null;
}

/** ECVRF_challenge_generation. Spec: RFC 9381 §5.4.3 */
function challenge(points: Point[]): bigint {
  const h = sha512(Uint8Array.of(SUITE, 0x02), ...points.map(encodePoint), Uint8Array.of(0x00));
  return littleEndian(h.subarray(0, C_LEN));
}

/**
 * ECVRF_verify with validate_key = TRUE; the 64-byte beta when the proof is valid, else `null`.
 * Spec: RFC 9381 §5.3, §5.2; T§2
 * Impl (spec-gap 104): validate_key is TRUE (RFC 9381 §5.4.5: reject Y when cofactor·Y is the identity).
 */
export function vrfVerify(publicKey: Uint8Array, alpha: Uint8Array, proof: Uint8Array): Buffer | null {
  const Y = decodePoint(publicKey);
  if (!Y) return null;
  // §5.4.5 validate_key. Impl: tested as cofactor·Y = identity; on keys that decode this is exactly the README's
  // list of low-order y encodings (sign bit cleared), since every other entry of that list does not decode.
  if (equalPoints(mul(COFACTOR, Y), IDENTITY)) return null;
  // §5.4.4 decode_proof
  if (proof.length !== 32 + C_LEN + 32) return null;
  const gamma = decodePoint(proof.subarray(0, 32));
  if (!gamma) return null;
  const c = littleEndian(proof.subarray(32, 32 + C_LEN));
  const s = littleEndian(proof.subarray(32 + C_LEN));
  if (s >= Q) return null;
  const H = encodeToCurve(publicKey, alpha);
  if (!H) return null;
  const U = add(mul(s, BASE), negate(mul(c, Y)));
  const V = add(mul(s, H), negate(mul(c, gamma)));
  if (challenge([Y, H, gamma, U, V]) !== c) return null;
  // §5.2 ECVRF_proof_to_hash
  return sha512(Uint8Array.of(SUITE, 0x03), encodePoint(mul(COFACTOR, gamma)), Uint8Array.of(0x00));
}
