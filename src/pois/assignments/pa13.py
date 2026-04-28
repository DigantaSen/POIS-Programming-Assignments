from __future__ import annotations

import random
import time

from .base import AssignmentInfo, AssignmentModule


def fast_mod_pow(base: int, exp: int, mod: int) -> int:
    """Implement textbook square-and-multiply modular exponentiation."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result


def fermat_test(n: int, k: int = 40) -> bool:
    """Naive Fermat primality test, prone to Carmichael number failure."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        if fast_mod_pow(a, n - 1, n) != 1:
            return False
    return True


def miller_rabin(n: int, k: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Extract s and d such that n-1 = 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = fast_mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = fast_mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # If the inner loop didn't break, the number is composite
            return False

    return True


def gen_prime(bits: int) -> int:
    """Generates a random k-bit prime using Miller-Rabin tests."""
    while True:
        # Generate an odd number with `bits` length
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # Ensure it has exactly `bits` length and is odd
        
        if miller_rabin(n, 40):
            return n


class PA13(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA13",
            title="Miller-Rabin Primality Testing",
            part="Public-Key Utilities",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement Miller-Rabin primality test algorithm.",
            "Implement fast modular exponentiation natively.",
            "Generate large primes via trial sampling.",
            "Demonstrate Carmichael number 561 fooling Fermat test but caught by M-R.",
        ]
        
    def is_prime(self, n: int) -> bool:
        return miller_rabin(n, 40)
        
    def generate_prime(self, bits: int) -> int:
        return gen_prime(bits)

    def run_demo(self) -> str:
        out = ["PA13 Demo Active", ""]
        
        # Carmichael demo
        carmichael = 561
        # To reliably demonstrate Fermat being fooled, we pick a base coprime to 561, like 2.
        # fast_mod_pow(2, 560, 561) == 1
        fermat_result = (fast_mod_pow(2, carmichael - 1, carmichael) == 1)
        mr_result = miller_rabin(carmichael, 40)
        
        out.append(f"Carmichael number {carmichael} tested:")
        out.append(f"  Fermat test (base 2) says: {'PRIME' if fermat_result else 'COMPOSITE'} (Fermat is fooled!)")
        out.append(f"  Miller-Rabin test says: {'PRIME' if mr_result else 'COMPOSITE'} (MR works!)")
        out.append("")
        
        # Benchmark
        out.append("Benchmarking prime generation...")
        for bits in [256, 512]:
            st = time.time()
            candidates = 0
            while True:
                candidates += 1
                n = random.getrandbits(bits)
                n |= (1 << (bits - 1)) | 1
                if miller_rabin(n, 40):
                    break
            elapsed = time.time() - st
            out.append(f"  Generated {bits}-bit prime in {elapsed:.3f}s. Tested {candidates} candidates.")
            
        return "\n".join(out)
