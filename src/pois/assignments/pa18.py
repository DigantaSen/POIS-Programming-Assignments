from __future__ import annotations

import secrets
from dataclasses import dataclass

from .base import AssignmentInfo, AssignmentModule
from .pa16 import elgamal_decrypt_bytes, elgamal_encrypt_bytes, elgamal_keygen


def _coerce_message(message: bytes | str | int) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    if message < 0:
        raise ValueError("negative messages are not supported")
    width = max(1, (message.bit_length() + 7) // 8)
    return message.to_bytes(width, "big")


@dataclass(frozen=True)
class OTTranscript:
    sender_public_keys: tuple[tuple[int, int, int], tuple[int, int, int]]
    ciphertexts: tuple[tuple[int, int], tuple[int, int]]
    selected_index: int
    selected_message: bytes
    log: tuple[str, ...] = ()


@dataclass(frozen=True)
class OTReceiverState:
    choice: int
    secret_key: tuple[int, int, int]
    public_keys: tuple[tuple[int, int, int], tuple[int, int, int]]
    honest_index: int


def ot_receiver_step1(choice: int, bits: int = 64) -> tuple[tuple[int, int, int], tuple[int, int, int], OTReceiverState]:
    if choice not in (0, 1):
        raise ValueError("choice must be 0 or 1")

    honest_pk, honest_sk = elgamal_keygen(bits)
    p, g, _ = honest_pk
    fake_pk = (p, g, secrets.randbelow(p - 2) + 1)

    if choice == 0:
        pk0, pk1 = honest_pk, fake_pk
    else:
        pk0, pk1 = fake_pk, honest_pk

    state = OTReceiverState(choice=choice, secret_key=honest_sk, public_keys=(pk0, pk1), honest_index=choice)
    return pk0, pk1, state


def ot_sender_step(
    pk0: tuple[int, int, int],
    pk1: tuple[int, int, int],
    m0: bytes | str | int,
    m1: bytes | str | int,
) -> tuple[tuple[int, int], tuple[int, int]]:
    c0 = elgamal_encrypt_bytes(pk0, _coerce_message(m0))
    c1 = elgamal_encrypt_bytes(pk1, _coerce_message(m1))
    return c0, c1


def ot_receiver_step2(state: OTReceiverState, c0: tuple[int, int], c1: tuple[int, int]) -> bytes:
    selected = c0 if state.choice == 0 else c1
    return elgamal_decrypt_bytes(state.secret_key, selected)


def ot_attempt_other_decrypt(state: OTReceiverState, c0: tuple[int, int], c1: tuple[int, int]) -> bytes | None:
    # The receiver only knows one secret key; the other ciphertext is not decryptable.
    other = c1 if state.choice == 0 else c0
    try:
        return elgamal_decrypt_bytes(state.secret_key, other)
    except Exception:
        return None


def oblivious_transfer(messages: tuple[bytes | str, bytes | str], choice: int, bits: int = 64) -> OTTranscript:
    pk0, pk1, state = ot_receiver_step1(choice, bits=bits)
    ciphertexts = ot_sender_step(pk0, pk1, messages[0], messages[1])
    selected_message = ot_receiver_step2(state, ciphertexts[0], ciphertexts[1])

    return OTTranscript(
        sender_public_keys=(pk0, pk1),
        ciphertexts=ciphertexts,
        selected_index=choice,
        selected_message=selected_message,
        log=(
            f"receiver choice = {choice}",
            "receiver step1: generated one honest keypair and one random public key",
            "sender step: encrypted both messages under the two public keys",
            "receiver step2: decrypted only the chosen ciphertext",
        ),
    )


def ot_correctness_trials(trials: int = 100, bits: int = 64) -> int:
    successes = 0
    for _ in range(trials):
        choice = secrets.randbelow(2)
        m0 = secrets.token_bytes(1)
        m1 = secrets.token_bytes(1)
        transcript = oblivious_transfer((m0, m1), choice, bits=bits)
        expected = m0 if choice == 0 else m1
        if transcript.selected_message == expected:
            successes += 1
    return successes


class PA18(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA18",
            title="Oblivious Transfer",
            part="Public-Key Protocols",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement a toy 1-out-of-2 OT using ElGamal-style public keys",
            "Let the receiver learn only the selected message",
            "Expose the transcript for later secure-computation demos",
        ]

    def run_demo(self) -> str:
        left = b"left"
        right = b"right"

        pk0, pk1, state = ot_receiver_step1(1)
        ciphertexts = ot_sender_step(pk0, pk1, left, right)
        selected = ot_receiver_step2(state, ciphertexts[0], ciphertexts[1])
        cheated = ot_attempt_other_decrypt(state, ciphertexts[0], ciphertexts[1])

        trials = ot_correctness_trials(100)

        return "\n".join([
            "PA18 demo active",
            "",
            "  Sender public keys:",
            f"    pk0 = {pk0}",
            f"    pk1 = {pk1}",
            "",
            "  Ciphertexts sent to the receiver:",
            f"    c0 = {ciphertexts[0]}",
            f"    c1 = {ciphertexts[1]}",
            f"    selected index = {state.choice}",
            f"    recovered message = {selected!r}",
            "",
            "  Cheat attempt:",
            f"    attempt to decrypt the other ciphertext -> {cheated!r}",
            f"    correctness over 100 trials = {trials}/100",
            "",
            "  Message log:",
            *[f"    {entry}" for entry in (
                f"choice bit {state.choice}",
                "receiver generated one honest public key and one random public key",
                "sender encrypted both branches",
                "receiver decrypted only the chosen branch",
            )],
            "",
            "  Conclusion:",
            "    The sender encrypts both branches, but the receiver decrypts only",
            "    the branch matched by the chosen input bit.",
        ])
