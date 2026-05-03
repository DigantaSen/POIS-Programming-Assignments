from __future__ import annotations

import secrets
from dataclasses import dataclass

from .base import AssignmentInfo, AssignmentModule
from .pa11 import find_generator, gen_safe_prime


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def fast_mod_pow(base: int, exp: int, mod: int) -> int:
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big") if data else 0


def int_to_bytes(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def _pack_bytes(data: bytes) -> bytes:
    if len(data) > 0xFFFF:
        raise ValueError("payload too large")
    return b"\x01" + len(data).to_bytes(2, "big") + data


def _unpack_bytes(data: bytes) -> bytes:
    if len(data) < 3:
        raise ValueError("payload too short")
    if data[0] != 0x01:
        raise ValueError("payload marker missing")
    length = int.from_bytes(data[1:3], "big")
    return data[3 : 3 + length]


def pack_int(value: int) -> bytes:
    width = max(1, (value.bit_length() + 7) // 8)
    return width.to_bytes(2, "big") + value.to_bytes(width, "big")


def unpack_int(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("packed integer is truncated")
    width = int.from_bytes(data[offset : offset + 2], "big")
    start = offset + 2
    end = start + width
    if end > len(data):
        raise ValueError("packed integer is truncated")
    return int.from_bytes(data[start:end], "big"), end


def pack_ciphertext(ciphertext: tuple[int, int]) -> bytes:
    c1, c2 = ciphertext
    return pack_int(c1) + pack_int(c2)


def unpack_ciphertext(data: bytes) -> tuple[int, int]:
    c1, offset = unpack_int(data, 0)
    c2, offset = unpack_int(data, offset)
    if offset != len(data):
        raise ValueError("unexpected trailing data in ciphertext")
    return c1, c2


def elgamal_keygen(bits: int = 64) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    p, q = gen_safe_prime(bits)
    g = find_generator(p, q)
    x = secrets.randbelow(p - 3) + 2
    h = pow(g, x, p)
    return (p, g, h), (p, g, x)


def elgamal_encrypt_int(pk: tuple[int, int, int], message: int) -> tuple[int, int]:
    p, g, h = pk
    if not 0 <= message < p:
        message %= p
    y = secrets.randbelow(p - 3) + 2
    c1 = pow(g, y, p)
    shared = pow(h, y, p)
    c2 = (message * shared) % p
    return c1, c2


def elgamal_decrypt_int(sk: tuple[int, int, int], ciphertext: tuple[int, int]) -> int:
    p, g, x = sk
    c1, c2 = ciphertext
    shared = pow(c1, x, p)
    return (c2 * mod_inverse(shared, p)) % p


def elgamal_encrypt_bytes(pk: tuple[int, int, int], message: bytes | str) -> tuple[int, int]:
    payload = message.encode("utf-8") if isinstance(message, str) else message
    packed = _pack_bytes(payload)
    plaintext = bytes_to_int(packed)
    p = pk[0]
    if plaintext >= p:
        raise ValueError("message too large for this ElGamal modulus")
    return elgamal_encrypt_int(pk, plaintext)


def elgamal_decrypt_bytes(sk: tuple[int, int, int], ciphertext: tuple[int, int]) -> bytes:
    plaintext = elgamal_decrypt_int(sk, ciphertext)
    width = max(1, (plaintext.bit_length() + 7) // 8)
    payload = int_to_bytes(plaintext, width)
    return _unpack_bytes(payload)


def double_ciphertext(pk: tuple[int, int, int], ciphertext: tuple[int, int]) -> tuple[int, int]:
    p = pk[0]
    return ciphertext[0], (ciphertext[1] * 2) % p


def demonstrate_malleability(pk: tuple[int, int, int], sk: tuple[int, int, int], trials: int = 100) -> tuple[int, int]:
    successes = 0
    for _ in range(trials):
        message = secrets.randbelow(pk[0] - 3) + 2
        ciphertext = elgamal_encrypt_int(pk, message)
        tampered = double_ciphertext(pk, ciphertext)
        recovered = elgamal_decrypt_int(sk, tampered)
        if recovered == (2 * message) % pk[0]:
            successes += 1
    return successes, trials


@dataclass(frozen=True)
class ElGamalCPAChallenge:
    pk: tuple[int, int, int]
    challenge: tuple[int, int]
    message: int


def cpa_challenge(pk: tuple[int, int, int], message: int) -> ElGamalCPAChallenge:
    return ElGamalCPAChallenge(pk=pk, challenge=elgamal_encrypt_int(pk, message), message=message)


def cpa_decryption_oracle(sk: tuple[int, int, int], ciphertext: tuple[int, int]) -> int:
    return elgamal_decrypt_int(sk, ciphertext)


class PA16(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA16",
            title="ElGamal Public-Key Cryptosystem",
            part="Public-Key Cryptography",
        )

    def deliverables(self) -> list[str]:
        return [
            "Generate a safe-prime group and ElGamal keypair",
            "Encrypt and decrypt short messages with randomized ElGamal",
            "Demonstrate multiplicative homomorphism / malleability",
            "Expose reusable helpers for later PA17-PA20 protocols",
        ]

    def run_demo(self) -> str:
        pk, sk = elgamal_keygen(64)
        p, g, h = pk

        message = 37
        challenge = cpa_challenge(pk, message)
        doubled_ciphertext = double_ciphertext(pk, challenge.challenge)
        doubled_message = cpa_decryption_oracle(sk, doubled_ciphertext)
        malleability_successes, malleability_trials = demonstrate_malleability(pk, sk, 100)

        m1 = 7
        m2 = 11
        enc1 = elgamal_encrypt_int(pk, m1)
        enc2 = elgamal_encrypt_int(pk, m2)
        combined = ((enc1[0] * enc2[0]) % p, (enc1[1] * enc2[1]) % p)
        product = elgamal_decrypt_int(sk, combined)

        challenge_bytes = elgamal_encrypt_bytes(pk, b"PA16")
        recovered = elgamal_decrypt_bytes(sk, challenge_bytes)

        return "\n".join([
            "PA16 demo active",
            "",
            "  Group parameters:",
            f"    p = {p}",
            f"    g = {g}",
            f"    h = {h}",
            "",
            "  CPA/malleability demo:",
            f"    challenge message m = {challenge.message}",
            f"    challenge ciphertext = {challenge.challenge}",
            f"    tampered ciphertext  = {doubled_ciphertext}",
            f"    oracle output        = {doubled_message}",
            f"    expected 2m mod p    = {(2 * challenge.message) % p}",
            f"    100/100 malleability trials succeeded = {malleability_successes == malleability_trials}",
            "",
            "  Multiplicative homomorphism:",
            f"    m1 = {m1}, m2 = {m2}",
            f"    Dec(c1) = {elgamal_decrypt_int(sk, enc1)}",
            f"    Dec(c2) = {elgamal_decrypt_int(sk, enc2)}",
            f"    Dec(c1 * c2) = {product}",
            f"    Expected product mod p = {(m1 * m2) % p}",
            "",
            "  Randomized byte encryption:",
            f"    decrypted message = {recovered!r}",
            "",
            "  Conclusion:",
            "    ElGamal is probabilistic, decrypts correctly, and is malleable",
            "    because ciphertext multiplication corresponds to plaintext multiplication.",
        ])
