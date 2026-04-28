from __future__ import annotations

import time

from .base import AssignmentInfo, AssignmentModule
from .pa12 import mod_inverse, rsa_keygen, rsa_enc, rsa_dec


def crt(residues: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem solver."""
    if len(residues) != len(moduli):
        raise ValueError("Lengths of residues and moduli must match.")
        
    N = 1
    for m in moduli:
        N *= m
        
    x = 0
    for a, m in zip(residues, moduli):
        m_i = N // m
        y = mod_inverse(m_i, m)
        x = (x + a * m_i * y) % N
        
    return x


def rsa_dec_crt(sk: tuple, c: int) -> int:
    """RSA decryption using CRT (Garner's algorithm)."""
    N, d, p, q, dp, dq, q_inv = sk
    # Compute in both primes
    mp = pow(c, dp, p)
    mq = pow(c, dq, q)
    
    # Garner's recombination
    h = (q_inv * (mp - mq)) % p
    m = mq + h * q
    return m


def int_nth_root(A: int, n: int) -> int:
    """Integer n-th root using Newton's method."""
    if A < 0:
        if n % 2 == 0:
            raise ValueError
        return -int_nth_root(-A, n)
    if A == 0:
        return 0
    u, s = A, A + 1
    while u < s:
        s = u
        t = (n - 1) * s + A // pow(s, n - 1)
        u = t // n
    return s


def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> int:
    """Hastad's Broadcast Attack on Textbook RSA."""
    if len(ciphertexts) != e or len(moduli) != e:
        raise ValueError(f"Need exactly {e} ciphertexts and moduli for e={e}.")
        
    x = crt(ciphertexts, moduli)
    # x should be m^e. Take integer e-th root.
    m = int_nth_root(x, e)
    return m


class PA14(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA14",
            title="Chinese Remainder Theorem & Attacks",
            part="Public-Key Cryptography",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement generic CRT solver",
            "Implement CRT-based fast RSA decryption",
            "Implement Hastad's Broadcast Attack",
            "Demonstrate Hastad's attack success on textbook RSA",
        ]

    def run_demo(self) -> str:
        out = ["PA14 Demo Active", ""]
        
        # CRT Decryption Benchmark
        out.append("1. Fast CRT Decryption vs Standard Decryption:")
        pk, sk = rsa_keygen(512)
        plaintext = 123456789
        c = rsa_enc(pk, plaintext)
        
        # correctness
        assert rsa_dec_crt(sk, c) == plaintext
        
        rounds = 50
        st = time.time()
        for _ in range(rounds):
            rsa_dec(sk, c)
        std_time = time.time() - st
        
        st = time.time()
        for _ in range(rounds):
            rsa_dec_crt(sk, c)
        crt_time = time.time() - st
        
        out.append(f"  Standard Decryption time ({rounds} calls): {std_time:.4f}s")
        out.append(f"  CRT Decryption time ({rounds} calls):      {crt_time:.4f}s")
        out.append(f"  Speedup ratio: {std_time / crt_time:.2f}x")
        out.append("")
        
        # Hastad's Attack Demo
        out.append("2. Hastad's Broadcast Attack (e=3):")
        e = 3
        # Assuming e=3, though our keygen uses 65537, we can just use e=3 for the demo 
        # by manually making the ciphertexts m^3 mod N
        msg = 42
        keys = [rsa_keygen(512) for _ in range(3)]
        moduli = [k[0][0] for k in keys]
        
        # Encrypt with e=3
        ciphertexts = [pow(msg, 3, N) for N in moduli]
        out.append(f"  Original message: {msg}")
        out.append(f"  Captured ciphertexts from {e} distinct moduli..")
        
        recovered = hastad_attack(ciphertexts, moduli, 3)
        out.append(f"  Recovered using CRT + cube root: {recovered}")
        out.append("  Attack " + ("SUCCESS" if recovered == msg else "FAILED"))
        
        return "\n".join(out)
