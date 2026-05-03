from __future__ import annotations

from dataclasses import dataclass

from .base import AssignmentInfo, AssignmentModule
from .pa15 import rsa_keygen, sign, verify
from .pa16 import (
    cpa_challenge,
    cpa_decryption_oracle,
    double_ciphertext,
    elgamal_decrypt_bytes,
    elgamal_decrypt_int,
    elgamal_encrypt_bytes,
    elgamal_encrypt_int,
    elgamal_keygen,
    pack_ciphertext,
)


@dataclass(frozen=True)
class CCAEnvelope:
    ciphertext: tuple[int, int]
    signature: int


@dataclass(frozen=True)
class CCA2Game:
    pk_enc: tuple[int, int, int]
    sk_enc: tuple[int, int, int]
    pk_sig: tuple[int, int]
    sk_sig: tuple
    challenge: CCAEnvelope | None = None
    challenge_message: int | None = None

    def encrypt_challenge(self, message: int) -> CCAEnvelope:
        envelope = cca_encrypt_int(self.pk_enc, self.sk_sig, message)
        object.__setattr__(self, "challenge", envelope)
        object.__setattr__(self, "challenge_message", message)
        return envelope

    def decrypt_oracle(self, envelope: CCAEnvelope) -> int | None:
        if self.challenge is not None and envelope == self.challenge:
            return None
        return cca_decrypt_int(self.pk_sig, self.sk_enc, envelope)


def cca_encrypt(
    pk_enc: tuple[int, int, int],
    sk_sig: tuple,
    message: bytes | str,
) -> CCAEnvelope:
    ciphertext = elgamal_encrypt_bytes(pk_enc, message)
    signature = sign(sk_sig, pack_ciphertext(ciphertext))
    return CCAEnvelope(ciphertext=ciphertext, signature=signature)


def cca_decrypt(
    pk_sig: tuple[int, int],
    sk_enc: tuple[int, int, int],
    envelope: CCAEnvelope,
) -> bytes | None:
    payload = pack_ciphertext(envelope.ciphertext)
    if not verify(pk_sig, payload, envelope.signature):
        return None
    return elgamal_decrypt_bytes(sk_enc, envelope.ciphertext)


def cca_encrypt_int(
    pk_enc: tuple[int, int, int],
    sk_sig: tuple,
    message: int,
) -> CCAEnvelope:
    ciphertext = elgamal_encrypt_int(pk_enc, message)
    signature = sign(sk_sig, pack_ciphertext(ciphertext))
    return CCAEnvelope(ciphertext=ciphertext, signature=signature)


def cca_decrypt_int(
    pk_sig: tuple[int, int],
    sk_enc: tuple[int, int, int],
    envelope: CCAEnvelope,
) -> int | None:
    payload = pack_ciphertext(envelope.ciphertext)
    if not verify(pk_sig, payload, envelope.signature):
        return None
    return elgamal_decrypt_int(sk_enc, envelope.ciphertext)


def signcrypt(pk_enc: tuple[int, int, int], sk_sig: tuple, message: int) -> CCAEnvelope:
    return cca_encrypt_int(pk_enc, sk_sig, message)


def verify_then_decrypt(pk_sig: tuple[int, int], sk_enc: tuple[int, int, int], envelope: CCAEnvelope) -> int | None:
    return cca_decrypt_int(pk_sig, sk_enc, envelope)


class PA17(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA17",
            title="CCA-Secure Public-Key Encryption",
            part="ElGamal + Signatures",
        )

    def deliverables(self) -> list[str]:
        return [
            "Combine ElGamal encryption with RSA signatures for authenticity",
            "Reject tampered ciphertexts before decryption",
            "Show that the wrapper behaves like a CCA-safe envelope in the demo",
        ]

    def run_demo(self) -> str:
        pk_enc, sk_enc = elgamal_keygen(64)
        pk_sig, sk_sig = rsa_keygen(512)

        message = 37
        game = CCA2Game(pk_enc=pk_enc, sk_enc=sk_enc, pk_sig=pk_sig, sk_sig=sk_sig)
        envelope = game.encrypt_challenge(message)
        recovered = game.decrypt_oracle(envelope)

        tampered_ciphertext = double_ciphertext(pk_enc, envelope.ciphertext)
        tampered_envelope = CCAEnvelope(ciphertext=tampered_ciphertext, signature=envelope.signature)
        tampered_result = game.decrypt_oracle(tampered_envelope)

        forged_signature_envelope = CCAEnvelope(ciphertext=envelope.ciphertext, signature=(envelope.signature + 1) % pk_sig[0])
        forged_result = game.decrypt_oracle(forged_signature_envelope)

        plain_challenge = cpa_challenge(pk_enc, message)
        plain_tampered = double_ciphertext(pk_enc, plain_challenge.challenge)
        plain_result = cpa_decryption_oracle(sk_enc, plain_tampered)

        return "\n".join([
            "PA17 demo active",
            "",
            "  Encrypt-then-Sign envelope:",
            f"    ciphertext = {envelope.ciphertext}",
            f"    signature  = {envelope.signature}",
            f"    decrypted  = {recovered!r}",
            "",
            "  CCA2 oracle checks:",
            f"    tamper CE by doubling c2 -> {tampered_result!r}",
            f"    forge signature         -> {forged_result!r}",
            "",
            "  Plain ElGamal contrast:",
            f"    challenge ciphertext = {plain_challenge.challenge}",
            f"    tampered output       = {plain_result}",
            f"    expected 2m mod p     = {(2 * plain_challenge.message) % pk_enc[0]}",
            "",
            "  Conclusion:",
            "    The signature check runs before decryption, so tampered signed",
            "    ciphertexts are rejected while plain ElGamal remains malleable.",
        ])
