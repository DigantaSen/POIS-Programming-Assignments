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


def ceildiv(a: int, b: int) -> int:
    return -(-a // b)


def floordiv(a: int, b: int) -> int:
    return a // b


def bleichenbacher_padding_oracle(sk: tuple, c: int) -> bool:
    """Returns True if the decrypted ciphertext is PKCS#1 v1.5 compliant."""
    N = sk[0]
    k = (N.bit_length() + 7) // 8
    
    m_int = rsa_dec(sk, c)
    em = m_int.to_bytes(k, 'big')
    
    return em[0] == 0x00 and em[1] == 0x02


def bleichenbacher_attack(pk: tuple[int, int], c: int, oracle, log_fn=print) -> int:
    """Simplified Bleichenbacher's attack (1998) on PKCS#1 v1.5."""
    N, e = pk
    k = (N.bit_length() + 7) // 8
    
    B = 2**(8 * (k - 2))
    
    # We assume c is already compliant, so s0 = 1
    M = [(2*B, 3*B - 1)]
    
    i = 1
    s_list = [1]
    
    def check_oracle(s_i):
        c_prime = (c * fast_mod_pow(s_i, e, N)) % N
        return oracle(c_prime)
    
    log_fn("  Starting adaptive search for intervals...")
    while True:
        if i == 1:
            s_i = ceildiv(N, 3*B)
            while not check_oracle(s_i):
                s_i += 1
        elif len(M) > 1:
            s_i = s_list[-1] + 1
            while not check_oracle(s_i):
                s_i += 1
        else:
            a, b = M[0]
            s_i = None
            r = ceildiv(2 * (b * s_list[-1] - 2 * B), N)
            found = False
            while not found:
                s_min = ceildiv(2 * B + r * N, b)
                s_max = floordiv(3 * B - 1 + r * N, a)
                for potential_s in range(s_min, s_max + 1):
                    if check_oracle(potential_s):
                        s_i = potential_s
                        found = True
                        break
                if not found:
                    r += 1
        
        s_list.append(s_i)
        
        M_new = []
        for a, b in M:
            r_min = ceildiv(a * s_i - 3 * B + 1, N)
            r_max = floordiv(b * s_i - 2 * B, N)
            for r in range(r_min, r_max + 1):
                new_a = max(a, ceildiv(2 * B + r * N, s_i))
                new_b = min(b, floordiv(3 * B - 1 + r * N, s_i))
                if new_a <= new_b:
                    M_new.append((new_a, new_b))
                    
        M = M_new
        
        if len(M) == 1 and M[0][0] == M[0][1]:
            log_fn(f"  Converged after {i} iterations.")
            return M[0][0]
            
        i += 1


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
            "Implement Bleichenbacher's Padding Oracle Attack",
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
        
        # Bleichenbacher attack demo
        out.append("")
        out.append("Bleichenbacher Padding Oracle Attack (CCA2):")
        
        # Use a smaller key (256-bit) specifically for Bleichenbacher to keep the demo fast
        out.append("  Generating 256-bit key for fast oracle demo...")
        pk_small, sk_small = rsa_keygen(256)
        msg_small = b"CCA2"
        c_small = pkcs15_enc(pk_small, msg_small)
        
        out.append(f"  Target Message: {msg_small}")
        out.append(f"  Ciphertext: {c_small}")
        
        oracle = lambda c_test: bleichenbacher_padding_oracle(sk_small, c_test)
        m_recovered_int = bleichenbacher_attack(pk_small, c_small, oracle, log_fn=lambda msg: out.append(msg))
        
        k_small = (pk_small[0].bit_length() + 7) // 8
        em_recovered = m_recovered_int.to_bytes(k_small, 'big')
        
        try:
            zero_idx = em_recovered.index(b"\x00", 2)
            recovered_msg = em_recovered[zero_idx + 1:]
            out.append(f"  Recovered Plaintext: {recovered_msg}")
            out.append("  Attack Successful: " + ("YES" if recovered_msg == msg_small else "NO"))
        except ValueError:
            out.append("  Failed to parse recovered padding.")
        
        return "\n".join(out)
