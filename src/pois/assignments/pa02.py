from __future__ import annotations

import random
from .base import AssignmentInfo, AssignmentModule
from .pa01 import DLPBasedOWF, OWFPRG, NistLikeSuite, _to_int, _bits_to_hex


# ---------------------------------------------------------------------------
# GGM PRF (PA#2a — forward direction)
# ---------------------------------------------------------------------------

class GGMPRF:
    """
    GGM PRF from PA#1's length-doubling PRG (Goldreich–Goldwasser–Micali).

    Construction:
        Given G : {0,1}^n → {0,1}^{2n}, split G(s) = G_0(s) ‖ G_1(s).

        F_k(b_1 b_2 … b_n) = G_{b_n}(… G_{b_1}(k) …)

        Evaluation cost: n OWF-PRG calls (one root-to-leaf path).

    Security:
        Adv_PRF(A) ≤ q · Adv_PRG(B)  for any PPT adversary making q queries.
    """

    SEED_BITS = 64

    def __init__(self) -> None:
        self._owf = DLPBasedOWF()
        self._prg = OWFPRG(self._owf, seed_bits=self.SEED_BITS)
        self._mask = (1 << self.SEED_BITS) - 1

    # ------------------------------------------------------------------
    # Internal: length-doubling PRG split
    # ------------------------------------------------------------------

    def _expand(self, seed: int) -> tuple[int, int]:
        """G(s) → (G_0(s), G_1(s)):  two n-bit half-outputs."""
        self._prg.seed(seed)
        bits = self._prg.next_bits(2 * self.SEED_BITS)
        g0 = int(bits[: self.SEED_BITS], 2)
        g1 = int(bits[self.SEED_BITS :], 2)
        return g0, g1

    # ------------------------------------------------------------------
    # PRF evaluation
    # ------------------------------------------------------------------

    def evaluate(self, key: int | bytes | str, query_bits: str) -> int:
        """
        F_k(b_1 … b_n): root-to-leaf GGM tree traversal.

        Args:
            key: seed for the root node (int / hex str / bytes).
            query_bits: binary string of length n, e.g. '1010'.

        Returns:
            Integer leaf value — the PRF output.
        """
        state = _to_int(key) & self._mask
        for bit in query_bits:
            g0, g1 = self._expand(state)
            state = g1 if bit == "1" else g0
        return state

    def evaluate_hex(self, key: int | bytes | str, query_bits: str) -> str:
        return f"{self.evaluate(key, query_bits):016x}"

    def F(self, k: int | bytes | str, x: int | bytes | str) -> int:
        """
        Drop-in interface (PA#3, PA#4, PA#5): F(k, x).

        x is interpreted as a SEED_BITS-wide integer and converted to a
        binary string for the tree traversal.
        """
        k_int = _to_int(k) & self._mask
        x_int = _to_int(x) & self._mask
        x_bits = f"{x_int:0{self.SEED_BITS}b}"
        return self.evaluate(k_int, x_bits)

    def F_hex(self, k: int | bytes | str, x: int | bytes | str) -> str:
        return f"{self.F(k, x):016x}"

    # ------------------------------------------------------------------
    # Full tree (for visualization / demo)
    # ------------------------------------------------------------------

    def build_tree(self, key: int, depth: int) -> dict[str, int]:
        """
        Build all 2^(depth+1) - 1 node values for visualisation.

        Returns:
            {path_string: node_value}  where '' = root, '0' = left child, etc.
        """
        nodes: dict[str, int] = {"": _to_int(key) & self._mask}
        queue: list[tuple[str, int]] = [("", nodes[""])]
        while queue:
            path, value = queue.pop(0)
            if len(path) >= depth:
                continue
            g0, g1 = self._expand(value)
            nodes[path + "0"] = g0
            nodes[path + "1"] = g1
            queue.extend([(path + "0", g0), (path + "1", g1)])
        return nodes

    # ------------------------------------------------------------------
    # Distinguishing game demo
    # ------------------------------------------------------------------

    def distinguishing_game(
        self,
        queries: int = 100,
        depth: int = 4,
    ) -> dict[str, object]:
        """
        Queries PRF and a truly random oracle on the same inputs.
        No efficient adversary should find a statistical difference.
        """
        key = random.getrandbits(self.SEED_BITS)
        rng_oracle: dict[str, int] = {}
        prf_bits = ""
        rnd_bits = ""

        for _ in range(queries):
            x = "".join(random.choice("01") for _ in range(depth))
            prf_val = self.evaluate(key, x)
            prf_bits += f"{prf_val:0{self.SEED_BITS}b}"
            if x not in rng_oracle:
                rng_oracle[x] = random.getrandbits(self.SEED_BITS)
            rnd_bits += f"{rng_oracle[x]:0{self.SEED_BITS}b}"

        prf_ratio = prf_bits.count("1") / len(prf_bits)
        rnd_ratio = rnd_bits.count("1") / len(rnd_bits)
        prf_pval = float(NistLikeSuite.frequency_monobit(prf_bits)["p_value"])
        rnd_pval = float(NistLikeSuite.frequency_monobit(rnd_bits)["p_value"])

        return {
            "queries": queries,
            "depth": depth,
            "prf_ones_ratio": prf_ratio,
            "random_ones_ratio": rnd_ratio,
            "statistical_distance": abs(prf_ratio - rnd_ratio),
            "prf_freq_pvalue": prf_pval,
            "random_freq_pvalue": rnd_pval,
            "indistinguishable": abs(prf_ratio - rnd_ratio) < 0.05,
        }


# ---------------------------------------------------------------------------
# AES plug-in PRF (one allowed external primitive per spec)
# ---------------------------------------------------------------------------

class AESPRF:
    """
    AES-128 PRF: F_k(x) = AES_k(x)  (ECB mode, one block).

    Uses the OS cryptographic primitive via the `cryptography` package —
    the one external primitive explicitly allowed by the PA spec.
    Falls back gracefully if the package is absent.
    """

    def __init__(self) -> None:
        self._ok = False
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            self._Cipher = Cipher
            self._algo = algorithms
            self._modes = modes
            self._backend = default_backend()
            self._ok = True
        except Exception:
            pass

    @property
    def available(self) -> bool:
        return self._ok

    @staticmethod
    def _to16(v: int | bytes | str) -> bytes:
        if isinstance(v, int):
            return v.to_bytes(16, "big")
        if isinstance(v, str):
            s = v.strip().lower().replace("0x", "").replace(" ", "")
            # Accept bit-string or hex
            if set(s) <= {"0", "1"} and len(s) > 16:
                return int(s.zfill(128)[:128], 2).to_bytes(16, "big")
            return bytes.fromhex(s.zfill(32)[:32])
        return (v + b"\x00" * 16)[:16]

    def evaluate(self, k: int | bytes | str, x: int | bytes | str) -> bytes:
        if not self._ok:
            raise RuntimeError("cryptography package not installed — AESPRF unavailable")
        c = self._Cipher(
            self._algo.AES(self._to16(k)),
            self._modes.ECB(),
            backend=self._backend,
        )
        enc = c.encryptor()
        return enc.update(self._to16(x)) + enc.finalize()

    def evaluate_hex(self, k: int | bytes | str, x: int | bytes | str) -> str:
        return self.evaluate(k, x).hex()

    def F(self, k: int | bytes | str, x: int | bytes | str) -> int:
        return int.from_bytes(self.evaluate(k, x), "big")

    def F_hex(self, k: int | bytes | str, x: int | bytes | str) -> str:
        return self.evaluate_hex(k, x)


# ---------------------------------------------------------------------------
# PRG from PRF (PA#2b — backward direction)
# ---------------------------------------------------------------------------

class PRGFromPRF:
    """
    PA#2b:  G(s) = F_s(0^n) ‖ F_s(1^n)  — a length-doubling PRG.

    Security argument: any distinguisher for G yields a PRF distinguisher.
    """

    def __init__(self, prf: GGMPRF) -> None:
        self._prf = prf
        self.seed_bits = prf.SEED_BITS

    def expand(self, seed: int | bytes | str) -> str:
        """Returns 2n pseudorandom bits from an n-bit seed."""
        s = _to_int(seed) & ((1 << self.seed_bits) - 1)
        f0 = f"{self._prf.evaluate(s, '0' * self.seed_bits):0{self.seed_bits}b}"
        f1 = f"{self._prf.evaluate(s, '1' * self.seed_bits):0{self.seed_bits}b}"
        return f0 + f1

    def generate(self, seed: int | bytes | str, total_bits: int = 2048) -> str:
        """Chain expand() to produce `total_bits` of pseudorandom output."""
        s = _to_int(seed) & ((1 << self.seed_bits) - 1)
        bits = ""
        while len(bits) < total_bits:
            chunk = self.expand(s)
            bits += chunk
            s = int(chunk[: self.seed_bits], 2)
        return bits[:total_bits]

    def statistical_tests(self, seed: int | bytes | str) -> dict[str, object]:
        bits = self.generate(seed, 2048)
        return {"bits_tested": len(bits), "tests": NistLikeSuite.run_all(bits)}


# ---------------------------------------------------------------------------
# PA02 module
# ---------------------------------------------------------------------------

class PA02(AssignmentModule):

    def __init__(self) -> None:
        self.ggm = GGMPRF()
        self.aes = AESPRF()
        self.prg = PRGFromPRF(self.ggm)

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA02",
            title="Pseudorandom Functions via GGM Tree",
            part="Part A (GGM PRF from PRG) + Part B (PRG from PRF)",
        )

    def deliverables(self) -> list[str]:
        return [
            "GGM PRF: F_k(x) via root-to-leaf tree traversal using PA#1 PRG",
            "AES-128 plug-in PRF with identical F(k, x) interface",
            "PRG from PRF: G(s) = F_s(0^n) ‖ F_s(1^n), NIST-tested",
            "Distinguishing game: PRF vs truly random oracle (q=100 inputs)",
            "Drop-in F(k, x) interface for PA#3, PA#4, PA#5",
        ]

    # Public drop-in interface
    def F(self, k: int | bytes | str, x: int | bytes | str) -> int:
        return self.ggm.F(k, x)

    def F_hex(self, k: int | bytes | str, x: int | bytes | str) -> str:
        return self.ggm.F_hex(k, x)

    def run_demo(self) -> str:
        key = random.getrandbits(GGMPRF.SEED_BITS)
        depth = 4
        query = "".join(random.choice("01") for _ in range(depth))
        result = self.ggm.evaluate(key, query)
        prg_tests = self.prg.statistical_tests(key)
        dist = self.ggm.distinguishing_game(queries=100, depth=depth)

        lines = [
            "PA02 demo active",
            f"  GGM PRF  depth={depth}",
            f"  key     = {key:016x}",
            f"  query   = {query}  (binary)",
            f"  F_k(x)  = {result:016x}",
            "",
            "  PRG-from-PRF statistical tests (2048 bits):",
        ]
        for t in prg_tests["tests"]:
            outcome = "PASS" if t["pass"] else "FAIL"
            lines.append(f"    {t['name']}: {outcome}, p={float(t['p_value']):.6f}")

        lines += [
            "",
            f"  Distinguishing game (q={dist['queries']}, depth={dist['depth']}):",
            f"    PRF 1-ratio  = {dist['prf_ones_ratio']:.4f}",
            f"    RNG 1-ratio  = {dist['random_ones_ratio']:.4f}",
            f"    |delta| = {dist['statistical_distance']:.4f}",
            f"    Verdict: {'INDISTINGUISHABLE (PRF secure)' if dist['indistinguishable'] else 'DISTINGUISHABLE (check params)'}",
        ]

        if self.aes.available:
            aes_out = self.aes.evaluate_hex(key.to_bytes(16, "big"), 0)
            lines.append(f"\n  AES plug-in: F_k(0) = {aes_out}")
        else:
            lines.append("\n  AES plug-in: install cryptography package to enable")

        return "\n".join(lines)
