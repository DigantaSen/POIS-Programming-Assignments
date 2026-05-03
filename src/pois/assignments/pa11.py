from __future__ import annotations

import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa13 import gen_prime, miller_rabin


def gen_safe_prime(bits: int = 31) -> tuple[int, int]:
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if miller_rabin(p):
            return p, q


def find_generator(p: int, q: int) -> int:
    # For safe prime p=2q+1, g is generator if g^2 != 1 and g^q != 1 (mod p).
    while True:
        g = secrets.randbelow(p - 3) + 2
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


class DiffieHellman:
    """Basic finite-field Diffie-Hellman key exchange."""

    def __init__(self, p: int, g: int) -> None:
        self.p = p
        self.g = g

    def keygen(self) -> tuple[int, int]:
        sk = secrets.randbelow(self.p - 3) + 2
        pk = pow(self.g, sk, self.p)
        return sk, pk

    def shared(self, sk: int, peer_pk: int) -> int:
        return pow(peer_pk, sk, self.p)


class MITMDemo:
    """Man-in-the-middle attack on unauthenticated DH."""

    def __init__(self, dh: DiffieHellman) -> None:
        self.dh = dh

    def run(self) -> dict[str, object]:
        # Honest endpoints.
        a_sk, a_pk = self.dh.keygen()
        b_sk, b_pk = self.dh.keygen()

        # Attacker creates two keys, one for each side.
        m1_sk, m1_pk = self.dh.keygen()
        m2_sk, m2_pk = self.dh.keygen()

        # Alice receives m1_pk instead of b_pk; Bob receives m2_pk instead of a_pk.
        k_alice = self.dh.shared(a_sk, m1_pk)
        k_bob = self.dh.shared(b_sk, m2_pk)

        # Attacker derives both session keys.
        k_malice_with_alice = self.dh.shared(m1_sk, a_pk)
        k_malice_with_bob = self.dh.shared(m2_sk, b_pk)

        # Honest no-MITM key for comparison.
        k_honest_a = self.dh.shared(a_sk, b_pk)
        k_honest_b = self.dh.shared(b_sk, a_pk)

        return {
            "a_pk": a_pk,
            "b_pk": b_pk,
            "m1_pk": m1_pk,
            "m2_pk": m2_pk,
            "honest_keys_match": k_honest_a == k_honest_b,
            "alice_key_under_attack": k_alice,
            "bob_key_under_attack": k_bob,
            "attacker_alice_key": k_malice_with_alice,
            "attacker_bob_key": k_malice_with_bob,
            "alice_compromised": k_alice == k_malice_with_alice,
            "bob_compromised": k_bob == k_malice_with_bob,
            "alice_bob_still_equal": k_alice == k_bob,
        }


class PA11(AssignmentModule):
    """PA11: Diffie-Hellman key exchange and MITM demo."""

    def __init__(self) -> None:
        # PA11 now shares the prime-generation path with PA13 so later PAs can reuse it.
        p, q = gen_safe_prime(bits=31)
        g = find_generator(p, q)
        self.p = p
        self.q = q
        self.g = g
        self.dh = DiffieHellman(p, g)
        self.mitm = MITMDemo(self.dh)

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA11",
            title="Diffie-Hellman Key Exchange",
            part="Key agreement and MITM vulnerability",
        )

    def deliverables(self) -> list[str]:
        return [
            "Safe-prime group setup p=2q+1 and generator selection",
            "DH keygen and shared-secret derivation",
            "Correctness demo: both parties derive identical gab",
            "MITM transcript showing separate attacker-shared keys",
            "Shared prime-generation lineage via PA13 helpers",
        ]

    def run_demo(self) -> str:
        a_sk, a_pk = self.dh.keygen()
        b_sk, b_pk = self.dh.keygen()
        k_a = self.dh.shared(a_sk, b_pk)
        k_b = self.dh.shared(b_sk, a_pk)

        mitm = self.mitm.run()

        return "\n".join([
            "PA11 demo active",
            "",
            "  Group parameters:",
            f"    p = {self.p}",
            f"    q = {self.q}",
            f"    g = {self.g}",
            "",
            "  Honest Diffie-Hellman:",
            f"    A = g^a mod p = {a_pk}",
            f"    B = g^b mod p = {b_pk}",
            f"    Alice shared key = {k_a}",
            f"    Bob shared key   = {k_b}",
            f"    keys match: {k_a == k_b}",
            "",
            "  MITM (unauthenticated DH is broken):",
            f"    Alice key compromised: {mitm['alice_compromised']}",
            f"    Bob key compromised:   {mitm['bob_compromised']}",
            f"    Alice and Bob still share same key: {mitm['alice_bob_still_equal']}",
            "",
            "  Conclusion:",
            "    DH gives secrecy only with authentication; otherwise MITM can",
            "    establish separate keys with each party undetected.",
        ])


