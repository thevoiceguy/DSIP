"""ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5, suite §5.5) in pure Python — the VRF of the Alias Transparency
Profile (T§2; KEYTRANS suite KT_128_SHA256_Ed25519).

Spec: T§2, T§5 (RFC 9381 §5.1–§5.4, RFC 8032 §5.1 point arithmetic). Not constant-time: vector use only.
"""
import hashlib

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493  # group order L
d = (-121665 * pow(121666, p - 2, p)) % p
SQRT_M1 = pow(2, (p - 1) // 4, p)
SUITE = b"\x03"
C_LEN, Q_LEN, PT_LEN = 16, 32, 32


def H512(b):
    return hashlib.sha512(b).digest()


# --- RFC 8032 §5.1.4 point ops, extended homogeneous coords (X,Y,Z,T) ---
def padd(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, Hh = B - A, D - C, D + C, B + A
    return (E * F % p, G * Hh % p, F * G % p, E * Hh % p)


def pmul(s, P):
    R = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            R = padd(R, P)
        P = padd(P, P)
        s >>= 1
    return R


def pneg(P):
    return ((-P[0]) % p, P[1], P[2], (-P[3]) % p)


def pequal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


g_y = 4 * pow(5, p - 2, p) % p
g_x = recover_x(g_y, 0)
B = (g_x, g_y, 1, g_x * g_y % p)
IDENT = (0, 1, 1, 0)


def point_to_string(P):  # RFC 8032 §5.1.2
    zinv = pow(P[2], p - 2, p)
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def string_to_point(s):  # RFC 8032 §5.1.3; None == "INVALID"
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def i2s(a, n):
    return int.to_bytes(a, n, "little")


def s2i(b):
    return int.from_bytes(b, "little")


# --- RFC 9381 ---
def encode_to_curve_tai(salt, alpha):  # §5.4.1.1
    ctr = 0
    while ctr <= 255:
        h = H512(SUITE + b"\x01" + salt + alpha + bytes([ctr]) + b"\x00")
        Hp = string_to_point(h[:32])
        if Hp is not None:
            Hp = pmul(8, Hp)  # cofactor
            if not pequal(Hp, IDENT):
                return Hp
        ctr += 1
    return None  # the one-byte counter is exhausted: no point, the proof is invalid


def challenge(*pts):  # §5.4.3
    s = SUITE + b"\x02" + b"".join(point_to_string(P) for P in pts) + b"\x00"
    return s2i(H512(s)[:C_LEN])


def secret_expand(sk):  # RFC 8032 §5.1.5
    h = H512(sk)
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return s2i(bytes(a)), h


def public_key(sk):
    x, _ = secret_expand(sk)
    return point_to_string(pmul(x, B))


def prove(sk, alpha):  # §5.1
    x, h = secret_expand(sk)
    Y = pmul(x, B)
    pk = point_to_string(Y)
    Hp = encode_to_curve_tai(pk, alpha)
    h_string = point_to_string(Hp)
    Gamma = pmul(x, Hp)
    k = s2i(H512(h[32:64] + h_string)) % q  # §5.4.2.2
    c = challenge(Y, Hp, Gamma, pmul(k, B), pmul(k, Hp))
    s = (k + c * x) % q
    return point_to_string(Gamma) + i2s(c, C_LEN) + i2s(s, Q_LEN)


def decode_proof(pi):  # §5.4.4
    if len(pi) != PT_LEN + C_LEN + Q_LEN:
        return None
    Gamma = string_to_point(pi[:32])
    if Gamma is None:
        return None
    c = s2i(pi[32:48])
    s = s2i(pi[48:80])
    if s >= q:
        return None
    return Gamma, c, s


def proof_to_hash(pi):  # §5.2
    D = decode_proof(pi)
    if D is None:
        return None
    return H512(SUITE + b"\x03" + point_to_string(pmul(8, D[0])) + b"\x00")


BAD_Y2 = 2707385501144840649318225287225658788936804267575313519463743609750303402022


def validate_key(pk):  # §5.4.5 (list form)
    y = bytearray(pk)
    y[31] &= 0x7F
    bad = [0, 1, BAD_Y2, p - BAD_Y2, p - 1, p, p + 1]
    return bytes(y) not in [i2s(b, 32) for b in bad]


def verify(pk, alpha, pi, validate=True):  # §5.3 -> beta or None
    Y = string_to_point(pk)
    if Y is None or (validate and not validate_key(pk)):
        return None
    D = decode_proof(pi)
    if D is None:
        return None
    Gamma, c, s = D
    Hp = encode_to_curve_tai(pk, alpha)
    if Hp is None:
        return None
    U = padd(pmul(s, B), pneg(pmul(c, Y)))
    V = padd(pmul(s, Hp), pneg(pmul(c, Gamma)))
    if challenge(Y, Hp, Gamma, U, V) != c:
        return None
    return proof_to_hash(pi)

