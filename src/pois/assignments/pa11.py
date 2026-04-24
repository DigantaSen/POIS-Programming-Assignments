from __future__ import annotations

import secrets

from .base import AssignmentInfo, AssignmentModule


def _miller_rabin(n: int, rounds: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(cand):
            return cand


def _gen_safe_prime(bits: int = 31) -> tuple[int, int]:
    while True:
        q = _gen_prime(bits - 1)
        p = 2 * q + 1
        if _miller_rabin(p):
            return p, q


def _find_generator(p: int, q: int) -> int:
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
        # TODO lineage note: replace with PA13 prime generation once PA13 is implemented.
        p, q = _gen_safe_prime(bits=31)
        g = _find_generator(p, q)
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
            "Lineage hook to PA13 prime generation (currently local helper)",
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


