from __future__ import annotations

import hashlib
import math
import random
from .base import AssignmentInfo, AssignmentModule


def _to_int(value: int | bytes | str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = "".join(ch for ch in cleaned if ch in "0123456789abcdef")
    if not cleaned:
        return 0
    return int(cleaned, 16)


def _is_probable_prime(candidate: int) -> bool:
    if candidate < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
    for prime in small_primes:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Deterministic bases for 32-bit integers.
    for base in (2, 3, 5, 7, 11):
        if base >= candidate:
            continue
        x = pow(base, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False

    return True


def _find_safe_prime(start_q: int = 1 << 30) -> tuple[int, int]:
    q = start_q | 1
    while True:
        if _is_probable_prime(q):
            p = 2 * q + 1
            if _is_probable_prime(p):
                return p, q
        q += 2


def _derive_generator(p: int, q: int) -> int:
    for h in range(2, p - 1):
        g = pow(h, 2, p)
        if g == 1:
            continue
        if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
            return g
    raise ValueError("Failed to derive generator for prime-order subgroup")


def _bits_to_hex(bits: str) -> str:
    if not bits:
        return ""
    pad = (4 - (len(bits) % 4)) % 4
    padded = bits + ("0" * pad)
    return f"{int(padded, 2):0{len(padded) // 4}x}"


def _chi_square_sf_approx(chi_square: float, dof: int) -> float:
    if chi_square <= 0:
        return 1.0
    if dof <= 0:
        return 0.0

    z = ((chi_square / dof) ** (1.0 / 3.0) - (1.0 - (2.0 / (9.0 * dof)))) / math.sqrt(
        2.0 / (9.0 * dof)
    )
    p_value = 0.5 * math.erfc(z / math.sqrt(2.0))
    return max(0.0, min(1.0, p_value))


class DLPBasedOWF:
    _cached_params: tuple[int, int, int] | None = None

    def __init__(self) -> None:
        if DLPBasedOWF._cached_params is None:
            p, q = _find_safe_prime()
            g = _derive_generator(p, q)
            DLPBasedOWF._cached_params = (p, q, g)
        self.p, self.q, self.g = DLPBasedOWF._cached_params

    def evaluate(self, x: int | bytes | str) -> int:
        exponent = _to_int(x) % self.q
        return pow(self.g, exponent, self.p)

    def evaluate_hex(self, x: int | bytes | str) -> str:
        out = self.evaluate(x)
        width = (self.p.bit_length() + 7) // 8
        return out.to_bytes(width, "big").hex()

    def verify_hardness(self, trials: int = 64) -> dict[str, float | int]:
        random_successes = 0
        for _ in range(trials):
            x = random.randrange(0, self.q)
            y = self.evaluate(x)
            guess = random.randrange(0, self.q)
            if self.evaluate(guess) == y:
                random_successes += 1

        empirical = random_successes / trials if trials else 0.0
        return {
            "trials": trials,
            "successes": random_successes,
            "empirical_success_rate": empirical,
            "expected_random_success_rate": 1.0 / self.q,
            "q": self.q,
        }


class OWFPRG:
    def __init__(self, owf: DLPBasedOWF, seed_bits: int = 64) -> None:
        self._owf = owf
        self.seed_bits = seed_bits
        self._mask = (1 << seed_bits) - 1
        self._state: int | None = None
        self._buffer = ""

    def _normalize_seed(self, seed_value: int | bytes | str) -> int:
        return _to_int(seed_value) & self._mask

    def _hardcore_bit(self, state: int) -> str:
        state_bytes = state.to_bytes((self._owf.q.bit_length() + 7) // 8, "big")
        digest = hashlib.blake2s(state_bytes, digest_size=16).digest()
        return "1" if (digest[-1] & 1) else "0"

    def seed(self, seed_value: int | bytes | str) -> None:
        self._state = self._normalize_seed(seed_value)
        self._buffer = ""

    def next_bits(self, n: int) -> str:
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return ""
        if self._state is None:
            raise ValueError("PRG is not seeded. Call seed(s) first.")

        while len(self._buffer) < n:
            self._state = self._owf.evaluate(self._state)
            self._buffer += self._hardcore_bit(self._state)

        out = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return out

    def expand(self, seed_value: int | bytes | str, extra_bits: int) -> str:
        if extra_bits < 0:
            raise ValueError("extra_bits must be non-negative")

        normalized_seed = self._normalize_seed(seed_value)
        self.seed(normalized_seed)
        seed_prefix = f"{normalized_seed:0{self.seed_bits}b}"
        return seed_prefix + self.next_bits(extra_bits)


class NistLikeSuite:
    ALPHA = 0.01

    @staticmethod
    def frequency_monobit(bits: str) -> dict[str, float | bool | str]:
        n = len(bits)
        if n == 0:
            return {"name": "frequency", "p_value": 0.0, "pass": False, "ones_ratio": 0.0}

        ones = bits.count("1")
        zeros = n - ones
        s_obs = abs(ones - zeros)
        p_value = math.erfc(s_obs / math.sqrt(2.0 * n))
        return {
            "name": "frequency",
            "p_value": p_value,
            "pass": p_value >= NistLikeSuite.ALPHA,
            "ones_ratio": ones / n,
        }

    @staticmethod
    def runs(bits: str) -> dict[str, float | bool | str]:
        n = len(bits)
        if n < 2:
            return {"name": "runs", "p_value": 0.0, "pass": False}

        pi = bits.count("1") / n
        tau = 2.0 / math.sqrt(n)
        if abs(pi - 0.5) >= tau:
            return {"name": "runs", "p_value": 0.0, "pass": False}

        transitions = sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
        v_obs = transitions + 1
        numerator = abs(v_obs - 2.0 * n * pi * (1.0 - pi))
        denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
        p_value = math.erfc(numerator / denominator) if denominator else 0.0
        return {"name": "runs", "p_value": p_value, "pass": p_value >= NistLikeSuite.ALPHA}

    @staticmethod
    def serial(bits: str) -> dict[str, float | bool | str]:
        n = len(bits)
        if n < 4:
            return {"name": "serial", "p_value": 0.0, "pass": False}

        wrapped = bits + bits[0]
        counts = {"00": 0, "01": 0, "10": 0, "11": 0}
        for i in range(n):
            counts[wrapped[i : i + 2]] += 1

        expected = n / 4.0
        chi_square = sum(((count - expected) ** 2) / expected for count in counts.values())
        p_value = _chi_square_sf_approx(chi_square, dof=3)
        return {
            "name": "serial",
            "p_value": p_value,
            "pass": p_value >= NistLikeSuite.ALPHA,
        }

    @staticmethod
    def run_all(bits: str) -> list[dict[str, float | bool | str]]:
        return [
            NistLikeSuite.frequency_monobit(bits),
            NistLikeSuite.runs(bits),
            NistLikeSuite.serial(bits),
        ]


class PA01(AssignmentModule):
    def __init__(self) -> None:
        self.owf = DLPBasedOWF()
        self.prg = OWFPRG(self.owf, seed_bits=64)

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA01",
            title="One-way functions and pseudorandom generators",
            part="Part A + Part B",
        )

    def deliverables(self) -> list[str]:
        return [
            "DLP-based OWF with evaluate(x) and hardness demo",
            "PRG from OWF exposing seed(s) and next_bits(n)",
            "OWF-from-PRG demonstration with bounded inversion adversary",
            "NIST-like monobit, runs, and serial statistical tests",
            "Stable black-box interface for PA02 consumption",
        ]

    def evaluate(self, x: int | bytes | str) -> int:
        return self.owf.evaluate(x)

    def verify_hardness(self, trials: int = 64) -> dict[str, float | int]:
        return self.owf.verify_hardness(trials=trials)

    def seed(self, s: int | bytes | str) -> None:
        self.prg.seed(s)

    def next_bits(self, n: int) -> str:
        return self.prg.next_bits(n)

    def prg_output(self, seed_value: int | bytes | str, l_bits: int) -> dict[str, str | int]:
        full_bits = self.prg.expand(seed_value, l_bits)
        return {
            "seed_bits": self.prg.seed_bits,
            "extra_bits": l_bits,
            "output_bits": full_bits,
            "output_hex": _bits_to_hex(full_bits),
        }

    def randomness_tests(self, seed_value: int | bytes | str, l_bits: int = 1024) -> dict[str, object]:
        full_bits = self.prg.expand(seed_value, l_bits)
        stream_bits = full_bits[self.prg.seed_bits :]
        return {
            "tested_bits": len(stream_bits),
            "tests": NistLikeSuite.run_all(stream_bits),
        }

    def owf_from_prg(self, seed_value: int | bytes | str, extra_bits: int | None = None) -> str:
        # If PRG output on random seeds were easy to invert, the inverter would recover seed preimages,
        # contradicting the one-wayness style reduction used in the construction.
        l_bits = self.prg.seed_bits if extra_bits is None else extra_bits
        return self.prg.expand(seed_value, l_bits)

    def verify_prg_as_owf(
        self,
        seed_bits: int = 20,
        trials: int = 6,
        search_budget: int = 4096,
    ) -> dict[str, float | int]:
        toy_prg = OWFPRG(self.owf, seed_bits=seed_bits)
        seed_space = 1 << seed_bits
        successes = 0

        for _ in range(trials):
            seed = random.randrange(seed_space)
            target = toy_prg.expand(seed, seed_bits)
            recovered: int | None = None

            for guess in range(search_budget):
                if toy_prg.expand(guess, seed_bits) == target:
                    recovered = guess
                    break

            if recovered == seed:
                successes += 1

        empirical = successes / trials if trials else 0.0
        expected = min(1.0, search_budget / seed_space)
        return {
            "seed_bits": seed_bits,
            "seed_space": seed_space,
            "search_budget": search_budget,
            "trials": trials,
            "successes": successes,
            "empirical_success_rate": empirical,
            "budget_over_space": expected,
        }

    def run_demo(self) -> str:
        seed = random.getrandbits(self.prg.seed_bits)
        prg_info = self.prg_output(seed, l_bits=512)
        hardness = self.verify_hardness(trials=64)
        nist = self.randomness_tests(seed, l_bits=1024)
        inverse_demo = self.verify_prg_as_owf(seed_bits=20, trials=6, search_budget=4096)

        lines = [
            "PA01 demo active",
            f"- OWF: DLP exponentiation in subgroup mod p={self.owf.p}",
            f"- Parameters: q={self.owf.q}, g={self.owf.g}",
            f"- Seed bits: {self.prg.seed_bits}",
            f"- Sample seed (hex): {seed:016x}",
            f"- PRG output bits: {prg_info['seed_bits'] + prg_info['extra_bits']}",
            f"- PRG output hex (prefix): {str(prg_info['output_hex'])[:64]}...",
            "- Hardness demo (random inversion adversary):",
            (
                "  "
                f"success={hardness['successes']}/{hardness['trials']} "
                f"({hardness['empirical_success_rate']:.6f}), "
                f"expected~{hardness['expected_random_success_rate']:.6e}"
            ),
            "- NIST-like tests on PRG stream bits:",
        ]

        for test in nist["tests"]:
            outcome = "PASS" if test["pass"] else "FAIL"
            lines.append(
                f"  {test['name']}: {outcome}, p-value={float(test['p_value']):.6f}"
            )

        lines.extend(
            [
                "- OWF-from-PRG bounded inversion demo:",
                (
                    "  "
                    f"success={inverse_demo['successes']}/{inverse_demo['trials']} "
                    f"({inverse_demo['empirical_success_rate']:.6f}), "
                    f"budget/space={inverse_demo['budget_over_space']:.6f}"
                ),
            ]
        )

        return "\n".join(lines)
