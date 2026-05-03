from __future__ import annotations

from dataclasses import dataclass

from .base import AssignmentInfo, AssignmentModule
from .pa18 import oblivious_transfer
from .pa19 import (
    GateSpec,
    GarbledGate,
    bit_for_label,
    build_wire_labels,
    evaluate_garbled_circuit,
    garble_gate,
    label_for_bit,
    secure_and,
    secure_and_with_transcript,
    secure_not,
    secure_xor,
    secure_xor_with_transcript,
)


@dataclass(frozen=True)
class SecureComputationResult:
    output_bit: int
    input_labels: dict[str, bytes]
    gates: list[GarbledGate]


@dataclass(frozen=True)
class CircuitGate:
    gate_id: str
    op: str
    inputs: tuple[int, ...]
    output: int


@dataclass
class Circuit:
    name: str
    num_alice_inputs: int
    num_bob_inputs: int
    public_inputs: tuple[int, ...]
    gates: list[CircuitGate]
    outputs: tuple[int, ...]

    @property
    def input_count(self) -> int:
        return self.num_alice_inputs + self.num_bob_inputs + len(self.public_inputs)

    def _initial_wire_values(self, inputs: list[int]) -> dict[int, int]:
        if len(inputs) != self.input_count:
            raise ValueError(f"expected {self.input_count} input bits, got {len(inputs)}")
        return {index: bit & 1 for index, bit in enumerate(inputs)}

    def evaluate(self, alice_bits: list[int], bob_bits: list[int]) -> list[int]:
        inputs = list(alice_bits) + list(bob_bits) + list(self.public_inputs)
        wire_values = self._initial_wire_values(inputs)
        for gate in self.gates:
            operand_bits = [wire_values[wire] for wire in gate.inputs]
            wire_values[gate.output] = _apply_plain_gate(gate.op, operand_bits)
        return [wire_values[wire] for wire in self.outputs]


@dataclass(frozen=True)
class CircuitGateTrace:
    gate_id: str
    op: str
    inputs: tuple[int, ...]
    output: int
    output_bit: int
    note: str


@dataclass(frozen=True)
class SecureEvalResult:
    output_bits: list[int]
    gate_log: list[CircuitGateTrace]
    ot_calls: int


def _bits_from_int(value: int, width: int) -> list[int]:
    return [(value >> shift) & 1 for shift in range(width - 1, -1, -1)]


def _int_from_bits(bits: list[int]) -> int:
    result = 0
    for bit in bits:
        result = (result << 1) | (bit & 1)
    return result


def _apply_plain_gate(op: str, bits: list[int]) -> int:
    op = op.upper()
    if op == "AND":
        if len(bits) != 2:
            raise ValueError("AND expects 2 inputs")
        return bits[0] & bits[1]
    if op == "XOR":
        result = 0
        for bit in bits:
            result ^= bit & 1
        return result
    if op == "NOT":
        if len(bits) != 1:
            raise ValueError("NOT expects 1 input")
        return 1 - (bits[0] & 1)
    raise ValueError(f"Unsupported gate op: {op}")


def _next_wire_index(circuit: Circuit) -> int:
    return circuit.input_count + len(circuit.gates)


def _build_comparison_gate_sequence(n: int) -> tuple[list[CircuitGate], tuple[int, ...]]:
    x = list(range(n))
    y = list(range(n, 2 * n))
    zero = 2 * n
    one = 2 * n + 1

    gates: list[CircuitGate] = []
    next_wire = 2 * n + 2
    gt = zero
    eq = one

    for xi, yi in zip(x, y):
        not_y = next_wire
        gates.append(CircuitGate(f"not_y_{xi}", "NOT", (yi,), not_y))
        next_wire += 1

        x_and_not_y = next_wire
        gates.append(CircuitGate(f"x_and_not_y_{xi}", "AND", (xi, not_y), x_and_not_y))
        next_wire += 1

        xor_xy = next_wire
        gates.append(CircuitGate(f"xor_xy_{xi}", "XOR", (xi, yi), xor_xy))
        next_wire += 1

        not_xor = next_wire
        gates.append(CircuitGate(f"not_xor_{xi}", "NOT", (xor_xy,), not_xor))
        next_wire += 1

        gt_term = next_wire
        gates.append(CircuitGate(f"gt_term_{xi}", "AND", (eq, x_and_not_y), gt_term))
        next_wire += 1

        gt_xor = next_wire
        gates.append(CircuitGate(f"gt_xor_{xi}", "XOR", (gt, gt_term), gt_xor))
        next_wire += 1

        gt_and = next_wire
        gates.append(CircuitGate(f"gt_and_{xi}", "AND", (gt, gt_term), gt_and))
        next_wire += 1

        gt_next = next_wire
        gates.append(CircuitGate(f"gt_next_{xi}", "XOR", (gt_xor, gt_and), gt_next))
        next_wire += 1
        gt = gt_next

        eq_next = next_wire
        gates.append(CircuitGate(f"eq_next_{xi}", "AND", (eq, not_xor), eq_next))
        next_wire += 1
        eq = eq_next

    return gates, (gt,)


def build_millionaire_circuit(n: int) -> Circuit:
    gates, outputs = _build_comparison_gate_sequence(n)
    return Circuit(
        name=f"millionaire_{n}",
        num_alice_inputs=n,
        num_bob_inputs=n,
        public_inputs=(0, 1),
        gates=gates,
        outputs=outputs,
    )


def build_equality_circuit(n: int) -> Circuit:
    x = list(range(n))
    y = list(range(n, 2 * n))
    one = 2 * n

    gates: list[CircuitGate] = []
    next_wire = 2 * n + 1
    eq = one

    for xi, yi in zip(x, y):
        xor_xy = next_wire
        gates.append(CircuitGate(f"xor_xy_{xi}", "XOR", (xi, yi), xor_xy))
        next_wire += 1

        not_xor = next_wire
        gates.append(CircuitGate(f"not_xor_{xi}", "NOT", (xor_xy,), not_xor))
        next_wire += 1

        eq_next = next_wire
        gates.append(CircuitGate(f"eq_next_{xi}", "AND", (eq, not_xor), eq_next))
        next_wire += 1
        eq = eq_next

    return Circuit(
        name=f"equality_{n}",
        num_alice_inputs=n,
        num_bob_inputs=n,
        public_inputs=(1,),
        gates=gates,
        outputs=(eq,),
    )


def build_addition_circuit(n: int) -> Circuit:
    x = list(range(n))
    y = list(range(n, 2 * n))
    zero = 2 * n

    gates: list[CircuitGate] = []
    next_wire = 2 * n + 1
    carry = zero
    sum_outputs: list[int] = []

    for xi, yi in zip(reversed(x), reversed(y)):
        xor_xy = next_wire
        gates.append(CircuitGate(f"xor_xy_{xi}", "XOR", (xi, yi), xor_xy))
        next_wire += 1

        sum_bit = next_wire
        gates.append(CircuitGate(f"sum_{xi}", "XOR", (xor_xy, carry), sum_bit))
        next_wire += 1
        sum_outputs.append(sum_bit)

        and_xy = next_wire
        gates.append(CircuitGate(f"and_xy_{xi}", "AND", (xi, yi), and_xy))
        next_wire += 1

        and_carry = next_wire
        gates.append(CircuitGate(f"and_carry_{xi}", "AND", (carry, xor_xy), and_carry))
        next_wire += 1

        carry_next = next_wire
        gates.append(CircuitGate(f"carry_{xi}", "XOR", (and_xy, and_carry), carry_next))
        next_wire += 1
        carry = carry_next

    return Circuit(
        name=f"addition_{n}",
        num_alice_inputs=n,
        num_bob_inputs=n,
        public_inputs=(0,),
        gates=gates,
        outputs=tuple(reversed(sum_outputs)),
    )


def secure_eval_circuit(circuit: Circuit, alice_bits: list[int], bob_bits: list[int]) -> SecureEvalResult:
    inputs = list(alice_bits) + list(bob_bits) + list(circuit.public_inputs)
    wire_values = circuit._initial_wire_values(inputs)
    gate_log: list[CircuitGateTrace] = []
    ot_calls = 0

    for gate in circuit.gates:
        operands = [wire_values[wire] for wire in gate.inputs]
        if gate.op == "AND":
            result = secure_and_with_transcript(operands[0], operands[1])
            wire_values[gate.output] = result.output_bit
            ot_calls += 1
            gate_log.append(
                CircuitGateTrace(
                    gate_id=gate.gate_id,
                    op=gate.op,
                    inputs=gate.inputs,
                    output=gate.output,
                    output_bit=result.output_bit,
                    note="OT-backed secure AND",
                )
            )
            continue

        if gate.op == "XOR":
            result = secure_xor(operands[0], operands[1])
            wire_values[gate.output] = result
            gate_log.append(
                CircuitGateTrace(
                    gate_id=gate.gate_id,
                    op=gate.op,
                    inputs=gate.inputs,
                    output=gate.output,
                    output_bit=result,
                    note="free local XOR",
                )
            )
            continue

        if gate.op == "NOT":
            result = secure_not(operands[0])
            wire_values[gate.output] = result
            gate_log.append(
                CircuitGateTrace(
                    gate_id=gate.gate_id,
                    op=gate.op,
                    inputs=gate.inputs,
                    output=gate.output,
                    output_bit=result,
                    note="free local NOT",
                )
            )
            continue

        raise ValueError(f"Unsupported gate op: {gate.op}")

    return SecureEvalResult(output_bits=[wire_values[wire] for wire in circuit.outputs], gate_log=gate_log, ot_calls=ot_calls)


def millionaire_problem(alice_value: int, bob_value: int, bits: int = 8) -> tuple[int, SecureEvalResult]:
    circuit = build_millionaire_circuit(bits)
    result = secure_eval_circuit(circuit, _bits_from_int(alice_value, bits), _bits_from_int(bob_value, bits))
    return result.output_bits[0], result


def secure_equality(alice_value: int, bob_value: int, bits: int = 8) -> tuple[int, SecureEvalResult]:
    circuit = build_equality_circuit(bits)
    result = secure_eval_circuit(circuit, _bits_from_int(alice_value, bits), _bits_from_int(bob_value, bits))
    return result.output_bits[0], result


def secure_addition(alice_value: int, bob_value: int, bits: int = 8) -> tuple[int, SecureEvalResult]:
    circuit = build_addition_circuit(bits)
    result = secure_eval_circuit(circuit, _bits_from_int(alice_value, bits), _bits_from_int(bob_value, bits))
    return _int_from_bits(result.output_bits), result


class PA20(AssignmentModule):
    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA20",
            title="All 2-Party Secure Computation",
            part="Universal Garbled Circuits",
        )

    def deliverables(self) -> list[str]:
        return [
            "Implement a Circuit DAG with AND/XOR/NOT gates",
            "Implement secure circuit evaluation using PA19 gate primitives",
            "Implement millionaire, equality, and modular addition circuits",
            "Report OT usage and a lineage-preserving gate trace",
        ]

    def run_demo(self) -> str:
        millionaire_result = millionaire_problem(7, 12, 8)
        equality_result = secure_equality(42, 42, 8)
        addition_result = secure_addition(19, 27, 8)

        return "\n".join([
            "PA20 demo active",
            "",
            "  Millionaire circuit (8-bit sample):",
            f"    x=7, y=12 -> richer party = {'Alice' if millionaire_result[0] == 1 else 'Bob'}",
            f"    OT calls = {millionaire_result[1].ot_calls}",
            "",
            "  Equality circuit (8-bit sample):",
            f"    x=42, y=42 -> equal = {equality_result[0]}",
            f"    OT calls = {equality_result[1].ot_calls}",
            "",
            "  Addition circuit (8-bit sample):",
            f"    x=19, y=27 -> sum mod 2^8 = {addition_result[0]}",
            f"    OT calls = {addition_result[1].ot_calls}",
            "",
            "  Lineage trace for one AND gate:",
            "    PA20 secure AND -> PA19 secure AND -> PA18 OT -> PA16 ElGamal -> PA11 safe-prime group -> PA13 Miller-Rabin",
            "",
            "  Sample gate log (millionaire circuit):",
            *[f"    {step.gate_id}: {step.op} -> {step.output_bit} ({step.note})" for step in millionaire_result[1].gate_log[:6]],
            "",
            "  Conclusion:",
            "    The circuit evaluator uses PA19 primitives for AND/XOR/NOT and",
            "    supports the three required MPC showcase circuits.",
        ])
