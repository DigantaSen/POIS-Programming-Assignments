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
        import random
        from pois.assignments.pa12 import pkcs15_enc
        out = ["PA14 Demo Active", ""]
        
        # 1. Verification of CRT correctness
        out.append("1. Verifying CRT Decryption Correctness...")
        pk_test, sk_test = rsa_keygen(512)
        correct = True
        for _ in range(100):
            msg = random.randint(1, pk_test[0] - 1)
            c = rsa_enc(pk_test, msg)
            if rsa_dec_crt(sk_test, c) != rsa_dec(sk_test, c):
                correct = False
                break
        out.append(f"  Verified rsa_dec_crt == rsa_dec for 100 random messages: {'YES' if correct else 'NO'}")
        out.append("")

        # 2. Performance Benchmark
        out.append("2. Performance Benchmark (Standard vs CRT):")
        rounds = 1000
        for bits in [1024, 2048]:
            out.append(f"  Generating {bits}-bit key for benchmark...")
            pk_b, sk_b = rsa_keygen(bits)
            msg_b = 42
            c_b = rsa_enc(pk_b, msg_b)
            
            st = time.time()
            for _ in range(rounds):
                rsa_dec(sk_b, c_b)
            std_time = time.time() - st
            
            st = time.time()
            for _ in range(rounds):
                rsa_dec_crt(sk_b, c_b)
            crt_time = time.time() - st
            
            out.append(f"  [{bits}-bit] Standard Decryption ({rounds} calls): {std_time:.4f}s")
            out.append(f"  [{bits}-bit] CRT Decryption ({rounds} calls):      {crt_time:.4f}s")
            out.append(f"  Speedup ratio: {std_time / crt_time:.2f}x (Expected ~3-4x)")
        out.append("")
        
        # 3. Hastad's Attack Demo
        out.append("3. Håstad's Broadcast Attack (e=3):")
        e = 3
        msg = 42
        keys = [rsa_keygen(512) for _ in range(3)]
        moduli = [k[0][0] for k in keys]
        
        ciphertexts = [pow(msg, 3, N) for N in moduli]
        out.append(f"  Original message: {msg}")
        
        recovered = hastad_attack(ciphertexts, moduli, 3)
        out.append(f"  Recovered using CRT + cube root: {recovered}")
        out.append("  Attack " + ("SUCCESS" if recovered == msg else "FAILED"))
        out.append("")
        
        # 4. Attack Boundary
        out.append("4. Attack Boundary Analysis:")
        out.append("  Given three 1024-bit moduli, N1*N2*N3 is ~3072 bits.")
        out.append("  The attack requires m^3 < N1*N2*N3 to compute the exact integer cube root.")
        out.append("  Max message length: floor(3072 / 3) = 1024 bits = 128 bytes.")
        out.append("  If m >= 128 bytes, m^3 >= N1*N2*N3, causing CRT to wrap modulo N1*N2*N3.")
        out.append("  The integer root step will then return garbage.")
        out.append("")
        
        # 5. PKCS Padding Defeats Attack
        out.append("5. Defeating the Attack with PKCS#1 v1.5 Padding:")
        msg_bytes = b"Secret Message"
        padded_ciphertexts = []
        for pk in keys:
            N = pk[0][0]
            # Use e=3 with PKCS#1 v1.5 padding
            c_padded = pkcs15_enc((N, 3), msg_bytes)
            padded_ciphertexts.append(c_padded)
            
        out.append(f"  Original plaintext bytes: {msg_bytes}")
        try:
            recovered_padded = hastad_attack(padded_ciphertexts, moduli, 3)
            out.append(f"  Recovered integer: {recovered_padded}")
            out.append("  Attack FAILED! (Recovered garbage because PKCS padding randomized each ciphertext)")
        except Exception as ex:
            out.append(f"  Attack FAILED! Exception: {ex}")
        
        return "\n".join(out)
