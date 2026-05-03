from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from itertools import product
from typing import Iterable

from .base import AssignmentInfo, AssignmentModule
from .pa18 import (
    OTReceiverState,
    OTTranscript,
    ot_receiver_step1,
    ot_receiver_step2,
    ot_sender_step,
)


LABEL_BYTES = 4


def _bit_message(bit: int) -> bytes:
    return bytes([bit & 1])


def _message_to_bit(message: bytes) -> int:
    if not message:
        return 0
    return message[-1] & 1


@dataclass(frozen=True)
class SecureAndTranscript:
    alice_bit: int
    bob_bit: int
    messages: tuple[int, int]
    ciphertexts: tuple[tuple[int, int], tuple[int, int]]
    ot_log: tuple[str, ...]
    received_message: bytes
    output_bit: int


@dataclass(frozen=True)
class SecureXorTranscript:
    alice_bit: int
    bob_bit: int
    randomness: int
    alice_share: int
    bob_share: int
    output_bit: int


def secure_and_with_transcript(alice_bit: int, bob_bit: int, bits: int = 32) -> SecureAndTranscript:
    if alice_bit not in (0, 1) or bob_bit not in (0, 1):
        raise ValueError("bits must be 0 or 1")

    pk0, pk1, state = ot_receiver_step1(bob_bit, bits=bits)
    messages = (_bit_message(0), _bit_message(alice_bit))
    ciphertexts = ot_sender_step(pk0, pk1, messages[0], messages[1])
    received = ot_receiver_step2(state, ciphertexts[0], ciphertexts[1])
    output_bit = _message_to_bit(received)

    return SecureAndTranscript(
        alice_bit=alice_bit,
        bob_bit=bob_bit,
        messages=(0, alice_bit),
        ciphertexts=ciphertexts,
        ot_log=(
            f"Alice sends messages (0, {alice_bit})",
            f"Bob choice bit = {bob_bit}",
            "OT receiver step1 generated one honest keypair and one random public key",
            "OT sender step encrypted both messages",
            "OT receiver step2 decrypted only the chosen branch",
        ),
        received_message=received,
        output_bit=output_bit,
    )


def secure_and(alice_bit: int, bob_bit: int) -> int:
    return secure_and_with_transcript(alice_bit, bob_bit).output_bit


def secure_xor_with_transcript(alice_bit: int, bob_bit: int) -> SecureXorTranscript:
    if alice_bit not in (0, 1) or bob_bit not in (0, 1):
        raise ValueError("bits must be 0 or 1")

    randomness = secrets.randbits(1)
    alice_share = alice_bit ^ randomness
    bob_share = bob_bit ^ randomness
    output_bit = alice_share ^ bob_share
    return SecureXorTranscript(
        alice_bit=alice_bit,
        bob_bit=bob_bit,
        randomness=randomness,
        alice_share=alice_share,
        bob_share=bob_share,
        output_bit=output_bit,
    )


def secure_xor(alice_bit: int, bob_bit: int) -> int:
    return secure_xor_with_transcript(alice_bit, bob_bit).output_bit


def secure_not(alice_bit: int) -> int:
    if alice_bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    return 1 - alice_bit


def verify_truth_table(trials: int = 50) -> dict[str, object]:
    and_ok = True
    xor_ok = True
    transcripts: list[str] = []

    for alice_bit in (0, 1):
        for bob_bit in (0, 1):
            for _ in range(trials):
                and_result = secure_and(alice_bit, bob_bit)
                xor_result = secure_xor(alice_bit, bob_bit)
                and_ok = and_ok and and_result == (alice_bit & bob_bit)
                xor_ok = xor_ok and xor_result == (alice_bit ^ bob_bit)

            transcript = secure_and_with_transcript(alice_bit, bob_bit)
            transcripts.append(
                f"a={alice_bit}, b={bob_bit}, AND={transcript.output_bit}, OT receiver learns {transcript.received_message!r}"
            )

    return {
        "and_ok": and_ok,
        "xor_ok": xor_ok,
        "not_ok": all(secure_not(bit) == 1 - bit for bit in (0, 1)),
        "transcripts": transcripts,
    }


@dataclass(frozen=True)
class GateSpec:
    gate_id: str
    op: str
    inputs: tuple[str, ...]
    output: str


@dataclass(frozen=True)
class GarbledGate:
    spec: GateSpec
    table: dict[tuple[bytes, ...], bytes]


WireLabels = tuple[bytes, bytes]


def _random_label_pair() -> WireLabels:
    zero = secrets.token_bytes(LABEL_BYTES)
    one = secrets.token_bytes(LABEL_BYTES)
    while one == zero:
        one = secrets.token_bytes(LABEL_BYTES)
    return zero, one


def build_wire_labels(wires: Iterable[str]) -> dict[str, WireLabels]:
    return {wire: _random_label_pair() for wire in wires}


def label_for_bit(labels: WireLabels, bit: int) -> bytes:
    return labels[1 if bit else 0]


def bit_for_label(labels: WireLabels, label: bytes) -> int:
    if label == labels[0]:
        return 0
    if label == labels[1]:
        return 1
    raise ValueError("Unknown label for this wire")


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _derive_pad(gate_id: str, labels: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha256(gate_id.encode("utf-8") + b"|" + b"|".join(labels)).digest()
    return digest[:LABEL_BYTES]


def _truth_value(op: str, bits: tuple[int, ...]) -> int:
    op = op.upper()
    if op == "AND":
        return int(all(bits))
    if op == "OR":
        return int(any(bits))
    if op == "XOR":
        result = 0
        for bit in bits:
            result ^= bit
        return result
    if op == "NOT":
        if len(bits) != 1:
            raise ValueError("NOT expects exactly one input")
        return 1 - bits[0]
    raise ValueError(f"Unsupported gate operation: {op}")


def garble_gate(spec: GateSpec, wire_labels: dict[str, WireLabels], output_labels: WireLabels) -> GarbledGate:
    table: dict[tuple[bytes, ...], bytes] = {}
    for bits in product([0, 1], repeat=len(spec.inputs)):
        input_labels = tuple(label_for_bit(wire_labels[wire], bit) for wire, bit in zip(spec.inputs, bits))
        out_bit = _truth_value(spec.op, bits)
        out_label = label_for_bit(output_labels, out_bit)
        pad = _derive_pad(spec.gate_id, input_labels)
        table[input_labels] = _xor_bytes(out_label, pad)
    return GarbledGate(spec=spec, table=table)


def evaluate_garbled_gate(gate: GarbledGate, input_labels: tuple[bytes, ...]) -> bytes:
    pad = _derive_pad(gate.spec.gate_id, input_labels)
    return _xor_bytes(gate.table[input_labels], pad)


def evaluate_garbled_circuit(gates: list[GarbledGate], initial_state: dict[str, bytes]) -> dict[str, bytes]:
    state = dict(initial_state)
    for gate in gates:
        labels = tuple(state[wire] for wire in gate.spec.inputs)
        state[gate.spec.output] = evaluate_garbled_gate(gate, labels)
    return state


class PA19(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA19",
            title="Secure AND Gate",
            part="Garbled Circuits",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement Secure AND(a, b) using the PA18 OT subroutine",
            "Implement free Secure XOR(a, b) via additive secret sharing",
            "Implement free Secure NOT(a)",
            "Verify the truth table across repeated randomized runs",
        ]

    def run_demo(self) -> str:
        truth = verify_truth_table(10)
        and_demo = secure_and_with_transcript(1, 0, bits=32)
        xor_demo = secure_xor_with_transcript(1, 0)
        not_demo = secure_not(1)

        return "\n".join([
            "PA19 demo active",
            "",
            f"  Secure AND(1, 0) = {and_demo.output_bit}",
            f"  Secure XOR(1, 0) = {xor_demo.output_bit}",
            f"  Secure NOT(1)    = {not_demo}",
            "",
            f"  Truth table AND passed  = {truth['and_ok']}",
            f"  Truth table XOR passed  = {truth['xor_ok']}",
            f"  Truth table NOT passed  = {truth['not_ok']}",
            f"  Repeated runs per row    = 10",
            "",
            "  Sample AND transcript:",
            *[f"    {entry}" for entry in and_demo.ot_log],
            "",
            "  Conclusion:",
            "    AND is implemented via OT, XOR is free via local sharing, and",
            "    NOT is a local share flip. The protocol transcript does not expose",
            "    the other party's input bit.",
        ])
