from __future__ import annotations

import os
import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa13 import gen_prime, fast_mod_pow


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def mod_inverse(a: int, m: int) -> int:
    """Modular inverse using EGCD."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def rsa_keygen(bits: int) -> tuple[tuple[int, int], tuple[int, int, int, int, int, int, int]]:
    """Generates RSA keypair. Returns (pk, sk).
    pk = (N, e)
    sk = (N, d, p, q, dp, dq, q_inv)
    """
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while p == q:
        q = gen_prime(bits // 2)

    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)

    return (N, e), (N, d, p, q, dp, dq, q_inv)


def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA Encryption."""
    N, e = pk
    return fast_mod_pow(m, e, N)


def rsa_dec(sk: tuple, c: int) -> int:
    """Textbook RSA Decryption."""
    N, d = sk[0], sk[1]
    return fast_mod_pow(c, d, N)


def pkcs15_enc(pk: tuple[int, int], m: bytes) -> int:
    """PKCS#1 v1.5 Encryption."""
    N, e = pk
    k = (N.bit_length() + 7) // 8
    
    if len(m) > k - 11:
        raise ValueError("Message too long for this key size")

    # Generate non-zero random padding
    ps_len = k - len(m) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b[0] != 0:
            ps.append(b[0])
            
    em = b"\x00\x02" + bytes(ps) + b"\x00" + m
    m_int = int.from_bytes(em, "big")
    return rsa_enc(pk, m_int)


def pkcs15_dec(sk: tuple, c: int) -> bytes:
    """PKCS#1 v1.5 Decryption."""
    N = sk[0]
    k = (N.bit_length() + 7) // 8

    m_int = rsa_dec(sk, c)
    em = m_int.to_bytes(k, "big")

    if em[0] != 0x00 or em[1] != 0x02:
        return None  # Bad padding

    try:
        zero_idx = em.index(b"\x00", 2)
    except ValueError:
        return None  # No zero separator

    if zero_idx - 2 < 8:
        return None  # Padding too short

    return em[zero_idx + 1:]


class PA12(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA12",
            title="Textbook RSA and PKCS#1 v1.5",
            part="Public-Key Cryptography",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement RSA Keygen, Textbook Encrypt/Decrypt",
            "Implement EGCD explicitly",
            "Implement PKCS#1 v1.5 padding scheme",
            "Demonstrate Textbook RSA determinism attack",
        ]
        
    def run_demo(self) -> str:
        out = ["PA12 Demo Active", ""]
        
        out.append("Generating 512-bit RSA key...")
        pk, sk = rsa_keygen(512)
        out.append(f"  Public Key (N, e): ({pk[0]}, {pk[1]})")
        out.append("")
        
        # Determinism demo
        msg_int = 42
        c1 = rsa_enc(pk, msg_int)
        c2 = rsa_enc(pk, msg_int)
        out.append("Textbook RSA Determinism:")
        out.append(f"  Encrypt({msg_int}) = {c1}")
        out.append(f"  Encrypt({msg_int}) = {c2}")
        out.append("  Are ciphertexts identical? " + ("YES" if c1 == c2 else "NO"))
        out.append("")
        
        # PKCS#1 v1.5
        msg_bytes = b"Hello, RSA!"
        cp1 = pkcs15_enc(pk, msg_bytes)
        cp2 = pkcs15_enc(pk, msg_bytes)
        out.append("PKCS#1 v1.5 Randomized Encryption:")
        out.append(f"  Encrypt({msg_bytes}) = {cp1}")
        out.append(f"  Encrypt({msg_bytes}) = {cp2}")
        out.append("  Are ciphertexts identical? " + ("YES (Broken)" if cp1 == cp2 else "NO (Secure from CPA)"))
        
        dec_bytes = pkcs15_dec(sk, cp1)
        out.append(f"  Decrypted bytes: {dec_bytes}")
        
        return "\n".join(out)
