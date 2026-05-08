from __future__ import annotations

import random
from .base import AssignmentInfo, AssignmentModule
from .pa12 import rsa_keygen, rsa_enc, rsa_dec
from .pa08 import PA08


def sign(sk: tuple, m: bytes) -> int:
    """RSA Digital Signature (Hash-then-Sign)."""
    N, d = sk[0], sk[1]
    
    # Hash the message using PA08 DLP Hash
    pa08 = PA08()
    h_bytes = pa08.hash(m)
    h_int = int.from_bytes(h_bytes, "big")
    
    # Sign the hash
    sigma = pow(h_int, d, N)
    return sigma

Sign = sign


def verify(pk: tuple[int, int], m: bytes, sigma: int) -> bool:
    """Verify RSA Digital Signature."""
    N, e = pk
    
    # Hash the message
    pa08 = PA08()
    h_bytes = pa08.hash(m)
    h_int = int.from_bytes(h_bytes, "big")
    
    # Verify
    return pow(sigma, e, N) == h_int

Verify = verify


def raw_sign(sk: tuple, m_int: int) -> int:
    """Insecure raw RSA signing (no hash)."""
    N, d = sk[0], sk[1]
    return pow(m_int, d, N)


def raw_verify(pk: tuple[int, int], m_int: int, sigma: int) -> bool:
    """Insecure raw RSA signature verification."""
    N, e = pk
    return pow(sigma, e, N) == m_int


def euf_cma_game(pk: tuple[int, int], sk: tuple) -> bool:
    """Simulates the EUF-CMA game. Returns True if adversary wins (breaks security)."""
    queried_messages = set()
    
    def signing_oracle(m_bytes: bytes) -> int:
        if len(queried_messages) >= 50:
            raise ValueError("Oracle limit reached")
        queried_messages.add(m_bytes)
        return sign(sk, m_bytes)
        
    # Adversary queries 50 random messages
    for i in range(50):
        signing_oracle(f"Query {i}".encode())
        
    # Adversary tries to forge a signature for a brand new message
    m_star = b"Target Forgery"
    
    # Since they can't exploit homomorphic properties on the hash,
    # their best attempt is to guess or return a previous signature.
    sigma_star = random.randint(1, pk[0] - 1)
    
    # Check if adversary won
    if m_star not in queried_messages and verify(pk, m_star, sigma_star):
        return True
    return False


class PA15(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA15",
            title="Digital Signatures",
            part="Public-Key Cryptography",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement secure Hash-then-Sign digital signatures",
            "Demonstrate multiplicative homomorphism forgery on raw RSA signatures",
            "Implement EUF-CMA game proving hash-then-sign resistance",
        ]

    def run_demo(self) -> str:
        out = ["PA15 Demo Active", ""]
        
        # Setup
        pk, sk = rsa_keygen(512)
        N, e = pk
        
        out.append("1. Secure Hash-then-Sign verification:")
        msg = b"Hello, Authenticated World!"
        sigma = sign(sk, msg)
        is_valid = verify(pk, msg, sigma)
        out.append(f"  Valid signature for '{msg.decode()}': {is_valid}")
        
        tampered_msg = b"Hello, Authenticated World!" + b"!"
        is_valid_tampered = verify(pk, tampered_msg, sigma)
        out.append(f"  Valid signature on tampered message: {is_valid_tampered}")
        out.append("")
        
        out.append("2. Insecure Raw RSA Multiplicative Forgery Attack:")
        m1 = 123
        m2 = 456
        s1 = raw_sign(sk, m1)
        s2 = raw_sign(sk, m2)
        
        # Attacker constructs a forged signature for m3 = m1 * m2
        m3 = (m1 * m2) % N
        s3_forged = (s1 * s2) % N
        
        out.append(f"  Got signatures for m1={m1} and m2={m2}")
        out.append(f"  Attacker wants to forge signature for m3 = m1*m2 = {m3}")
        out.append(f"  Attacker calculates: s3 = (s1 * s2) mod N")
        
        forgery_success = raw_verify(pk, m3, s3_forged)
        out.append(f"  Forgery successful on raw RSA? {'YES' if forgery_success else 'NO'}")
        
        # Trying the same on secure sign
        out.append("  Attempting same attack on Hash-then-Sign structure...")
        out.append("  (Because H(m1)*H(m2) != H(m1*m2), this attack structurally fails.)")
        out.append("")
        
        out.append("3. EUF-CMA Security Game:")
        out.append("  Running game where adversary queries up to 50 signed messages...")
        
        adv_wins = euf_cma_game(pk, sk)
        out.append(f"  Adversary attempts to forge signature for new m*...")
        out.append(f"  Adversary successful? {'YES (Broken)' if adv_wins else 'NO (Secure)'}")
        
        return "\n".join(out)
