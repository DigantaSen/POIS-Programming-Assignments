from __future__ import annotations

import math
import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa08 import PA08


def _fmt_bytes(x: int) -> bytes:
    return x.to_bytes(8, "big")


class BirthdayAttack:
    """Birthday attacks against PA08 truncated outputs."""

    def __init__(self, pa08: PA08) -> None:
        self._pa08 = pa08

    def _h_n(self, x: int, n_bits: int) -> int:
        return self._pa08.hash_nbits(_fmt_bytes(x), n_bits)

    def naive(self, n_bits: int, max_trials: int = 200_000) -> dict[str, object]:
        """
        O(k) space birthday attack using a hash table.

        Returns first pair x1 != x2 such that H_n(x1) = H_n(x2).
        """
        seen: dict[int, int] = {}

        for i in range(1, max_trials + 1):
            x = secrets.randbits(64)
            y = self._h_n(x, n_bits)

            prev = seen.get(y)
            if prev is not None and prev != x:
                return {
                    "found": True,
                    "steps": i,
                    "x1": prev,
                    "x2": x,
                    "digest": y,
                }

            seen[y] = x

        return {"found": False, "steps": max_trials}

    def floyd(self, n_bits: int, seed: int | None = None) -> dict[str, object]:
        """
        O(1) space collision search via Floyd cycle detection.

        We iterate x_{i+1} = H_n(x_i) over n-bit states.
        If x_mu = x_{mu+lambda}, then predecessors satisfy
        H_n(x_{mu-1}) = H_n(x_{mu+lambda-1}) and form a collision.
        """
        mask = (1 << n_bits) - 1

        def f(v: int) -> int:
            return self._h_n(v, n_bits) & mask

        x0 = (seed if seed is not None else secrets.randbits(n_bits)) & mask

        tortoise = f(x0)
        hare = f(f(x0))
        meet_steps = 1
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(f(hare))
            meet_steps += 1
            if meet_steps > (1 << (n_bits + 2)):
                return {"found": False, "reason": "no cycle meeting within bound"}

        mu = 0
        tortoise = x0
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(hare)
            mu += 1

        lam = 1
        hare = f(tortoise)
        while tortoise != hare:
            hare = f(hare)
            lam += 1

        if mu == 0:
            # Retry from a shifted seed to obtain predecessor nodes.
            return self.floyd(n_bits, seed=(x0 + 1) & mask)

        a = x0
        for _ in range(mu - 1):
            a = f(a)

        b = x0
        for _ in range(mu + lam - 1):
            b = f(b)

        ha = f(a)
        hb = f(b)

        return {
            "found": a != b and ha == hb,
            "steps": meet_steps + mu + lam,
            "x1": a,
            "x2": b,
            "digest": ha,
            "mu": mu,
            "lambda": lam,
        }


class PA09(AssignmentModule):
    """PA09: Birthday attack on truncated PA08 hash."""

    N_VALUES = [8, 10, 12, 14, 16]

    def __init__(self) -> None:
        self.pa08 = PA08()
        self.attack = BirthdayAttack(self.pa08)

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA09",
            title="Birthday Attack on Truncated Hash",
            part="Naive + Floyd variants",
        )

    def deliverables(self) -> list[str]:
        return [
            "Naive birthday collision search (hash table, O(k) memory)",
            "Floyd cycle-based collision search (O(1) memory)",
            "Experiments for n in {8,10,12,14,16}",
            "Empirical comparison against birthday scaling O(2^(n/2))",
            "Collision witness pairs x1 != x2 with H_n(x1)=H_n(x2)",
        ]

    def _theoretical_k50(self, n_bits: int) -> float:
        # Solve 1 - exp(-k^2/2^(n+1)) = 0.5.
        return math.sqrt((2 ** (n_bits + 1)) * math.log(2.0))

    def run_demo(self) -> str:
        lines = [
            "PA09 demo active",
            "",
            "  Birthday attack experiments on PA08 truncated outputs:",
        ]

        for n in self.N_VALUES:
            naive = self.attack.naive(n_bits=n)
            floyd = self.attack.floyd(n_bits=n)
            k50 = self._theoretical_k50(n)

            lines.extend([
                "",
                f"  n = {n} bits",
                f"    Theoretical k@50% collision ≈ {k50:.1f}",
                (
                    f"    Naive: steps={naive['steps']}, found={naive['found']}, "
                    f"digest={naive.get('digest', 0):0{max(1, n // 4)}x}"
                ),
                (
                    f"    Floyd: steps={floyd.get('steps', 0)}, found={floyd.get('found', False)}, "
                    f"digest={floyd.get('digest', 0):0{max(1, n // 4)}x}"
                ),
            ])

        lines.extend([
            "",
            "  Observation:",
            "    Collision effort grows near 2^(n/2), matching the birthday bound.",
            "    Floyd uses constant memory while still finding practical collisions",
            "    for toy output sizes.",
        ])

        return "\n".join(lines)


