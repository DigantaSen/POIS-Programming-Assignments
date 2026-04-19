from __future__ import annotations

import random
from .base import AssignmentInfo, AssignmentModule
from .pa02 import GGMPRF, _to_int

# ---------------------------------------------------------------------------
# Parameters — must match the TypeScript enc.ts counterpart
# ---------------------------------------------------------------------------
PRF_DEPTH = 8      # GGM tree depth: 8-bit query → 256 leaves
BLOCK_BYTES = 4    # 4 bytes per ciphertext block (lower 32 bits of PRF output)
NONCE_MOD = 256    # 8-bit nonce space (matches PRF depth)
_MASK32 = (1 << 32) - 1


# ---------------------------------------------------------------------------
# CPA-Secure Encryption: Enc-then-PRF
# ---------------------------------------------------------------------------

class CPAEncryption:
    """
    CPA-secure stream encryption using PA#2's GGM PRF.

    Enc(k, m):
        1. Sample r <- {0,1}^8 uniformly at random (fresh per call).
        2. For block i:  c_i = m_i XOR F_k( (r+i) mod 256 )
        3. Output C = (r, c_0 || c_1 || ...)

    Dec(k, r, c):
        1. For block i:  m_i = c_i XOR F_k( (r+i) mod 256 )
        2. Remove PKCS7 padding -> plaintext

    Security: IND-CPA secure if F_k (from PA#2) is a PRF,
              provided r is freshly sampled each encryption.
    """

    def __init__(self) -> None:
        self._prf = GGMPRF()

    # ------------------------------------------------------------------
    # Internal PRF evaluation for one block
    # ------------------------------------------------------------------

    def _prf_block(self, key_int: int, nonce: int) -> int:
        """F_k(nonce) -> 32-bit keystream block."""
        query_bits = f"{nonce & 0xFF:0{PRF_DEPTH}b}"
        return self._prf.evaluate(key_int, query_bits) & _MASK32

    # ------------------------------------------------------------------
    # Padding
    # ------------------------------------------------------------------

    @staticmethod
    def _pad(data: bytes) -> bytes:
        pad_len = BLOCK_BYTES - (len(data) % BLOCK_BYTES)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        if not data:
            raise ValueError("Empty ciphertext")
        pad_len = data[-1]
        if pad_len == 0 or pad_len > BLOCK_BYTES:
            raise ValueError(f"Invalid PKCS7 padding byte: {pad_len}")
        return data[:-pad_len]

    # ------------------------------------------------------------------
    # Encrypt / Decrypt
    # ------------------------------------------------------------------

    def encrypt(
        self,
        key: int | bytes | str,
        message: bytes,
        fixed_nonce: int | None = None,
    ) -> tuple[int, bytes]:
        """
        Enc(k, m) -> (nonce, ciphertext).

        Args:
            key: 64-bit key (int / hex / bytes).
            message: plaintext bytes.
            fixed_nonce: if set, use this 8-bit nonce instead of random
                         (ONLY for the broken-mode demonstration).
        """
        key_int = _to_int(key) & ((1 << GGMPRF.SEED_BITS) - 1)
        padded = self._pad(message)
        n_blocks = len(padded) // BLOCK_BYTES

        nonce = (
            fixed_nonce & 0xFF
            if fixed_nonce is not None
            else random.randint(0, NONCE_MOD - 1)
        )

        ct = bytearray()
        for i in range(n_blocks):
            ks = self._prf_block(key_int, (nonce + i) % NONCE_MOD)
            pt_int = int.from_bytes(padded[i * BLOCK_BYTES : (i + 1) * BLOCK_BYTES], "big")
            ct += ((pt_int ^ ks) & _MASK32).to_bytes(BLOCK_BYTES, "big")

        return nonce, bytes(ct)

    def decrypt(
        self,
        key: int | bytes | str,
        nonce: int,
        ciphertext: bytes,
    ) -> bytes:
        """Dec(k, r, c) -> plaintext bytes."""
        key_int = _to_int(key) & ((1 << GGMPRF.SEED_BITS) - 1)
        n_blocks = len(ciphertext) // BLOCK_BYTES

        pt = bytearray()
        for i in range(n_blocks):
            ks = self._prf_block(key_int, (nonce + i) % NONCE_MOD)
            ct_int = int.from_bytes(
                ciphertext[i * BLOCK_BYTES : (i + 1) * BLOCK_BYTES], "big"
            )
            pt += ((ct_int ^ ks) & _MASK32).to_bytes(BLOCK_BYTES, "big")

        return self._unpad(bytes(pt))

    # ------------------------------------------------------------------
    # Public interface for PA#6
    # ------------------------------------------------------------------

    def Enc(self, k: int | bytes | str, m: bytes | str) -> tuple[int, bytes]:
        """Enc(k, m) -> (r, c)  — drop-in for PA#6."""
        msg = m.encode() if isinstance(m, str) else m
        return self.encrypt(k, msg)

    def Dec(self, k: int | bytes | str, r: int, c: bytes) -> bytes:
        """Dec(k, r, c) -> m  — drop-in for PA#6."""
        return self.decrypt(k, r, c)


# ---------------------------------------------------------------------------
# IND-CPA Security Game
# ---------------------------------------------------------------------------

class INDCPAGame:
    """
    IND-CPA game simulator.

    Protocol:
        1. Challenger generates key k.
        2. Adversary submits (m0, m1) with |m0| = |m1|.
        3. Challenger samples b <- {0,1}, returns C* = Enc_k(m_b).
        4. Adversary outputs guess b'.
        5. Adversary wins iff b' = b.

    Advantage = 2 * |Pr[win] - 1/2|.  (ranges 0..1)
    CPA security requires Adv -> 0.
    """

    def __init__(self, enc: CPAEncryption, reuse_nonce: bool = False) -> None:
        self._enc = enc
        self._reuse_nonce = reuse_nonce
        self._key = random.getrandbits(GGMPRF.SEED_BITS)
        self._fixed_nonce: int | None = random.randint(0, 255) if reuse_nonce else None
        self._b: int | None = None
        self._rounds = 0
        self._wins = 0

    def challenge(self, m0: bytes, m1: bytes) -> tuple[int, bytes]:
        """Challenger picks b, returns C* = Enc_k(m_b)."""
        if len(m0) != len(m1):
            raise ValueError("Messages must have equal byte length")
        self._b = random.randint(0, 1)
        chosen = m0 if self._b == 0 else m1
        nonce, ct = self._enc.encrypt(
            self._key, chosen, fixed_nonce=self._fixed_nonce
        )
        self._rounds += 1
        return nonce, ct

    def guess(self, b_prime: int) -> dict[str, object]:
        """Adversary submits guess; returns round result dict."""
        correct = b_prime == self._b
        if correct:
            self._wins += 1
        return {
            "correct": correct,
            "b": self._b,
            "b_prime": b_prime,
            "rounds": self._rounds,
            "wins": self._wins,
            "advantage": self.advantage,
        }

    @property
    def advantage(self) -> float:
        if self._rounds == 0:
            return 0.0
        return 2.0 * abs(self._wins / self._rounds - 0.5)


# ---------------------------------------------------------------------------
# Broken variant — nonce reuse
# ---------------------------------------------------------------------------

class NonceReuseAttack:
    """
    Demonstrates the catastrophic nonce-reuse attack.

    With a fixed nonce:
        ct0 = F_k(r) XOR m0
        ct1 = F_k(r) XOR m1
        ct0 XOR ct1 = m0 XOR m1   (F_k(r) cancels!)

    An adversary who knows m0 XOR m1 can trivially distinguish.
    """

    def __init__(self, enc: CPAEncryption) -> None:
        self._enc = enc
        self._key = random.getrandbits(GGMPRF.SEED_BITS)
        self._fixed_nonce = random.randint(0, 255)

    def demonstrate(self, m0: bytes, m1: bytes) -> dict[str, object]:
        _, ct0 = self._enc.encrypt(self._key, m0, fixed_nonce=self._fixed_nonce)
        _, ct1 = self._enc.encrypt(self._key, m1, fixed_nonce=self._fixed_nonce)

        # XOR ciphertexts — cancels the keystream, reveals m0 XOR m1
        l = min(len(ct0), len(ct1))
        ct_xor = bytes(a ^ b for a, b in zip(ct0[:l], ct1[:l]))
        m_xor = bytes(a ^ b for a, b in zip(m0[:l], m1[:l]))

        attack_ok = ct_xor[: len(m_xor)] == m_xor[: len(ct_xor)]
        return {
            "nonce": self._fixed_nonce,
            "ct0_hex": ct0.hex(),
            "ct1_hex": ct1.hex(),
            "ct_xor_hex": ct_xor.hex(),
            "m_xor_hex": m_xor.hex(),
            "attack_succeeds": attack_ok,
        }

    def smart_adversary_advantage(self, m0: bytes, m1: bytes, rounds: int = 20) -> float:
        """
        Adversary strategy with nonce reuse:
        1. Learn ct0 = Enc(m0) [query oracle once].
        2. For each challenge C*: if C* == ct0 -> guess b=0, else b=1.
        This gives advantage -> 1 (full break).
        """
        _, reference_ct0 = self._enc.encrypt(self._key, m0, fixed_nonce=self._fixed_nonce)

        wins = 0
        for _ in range(rounds):
            b = random.randint(0, 1)
            chosen = m0 if b == 0 else m1
            _, challenge_ct = self._enc.encrypt(
                self._key, chosen, fixed_nonce=self._fixed_nonce
            )
            b_guess = 0 if challenge_ct == reference_ct0 else 1
            if b_guess == b:
                wins += 1

        return 2.0 * abs(wins / rounds - 0.5)


# ---------------------------------------------------------------------------
# PA03 module
# ---------------------------------------------------------------------------

class PA03(AssignmentModule):

    def __init__(self) -> None:
        self.enc = CPAEncryption()
        self.attack = NonceReuseAttack(self.enc)

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA03",
            title="CPA-Secure Symmetric Encryption",
            part="Enc-then-PRF + IND-CPA Game + Nonce-Reuse Attack",
        )

    def deliverables(self) -> list[str]:
        return [
            "Enc(k,m) and Dec(k,r,c) using Enc-then-PRF with PA02 GGM PRF",
            "Multi-block counter-mode extension with PKCS7 padding",
            "IND-CPA game simulation (advantage converges to ~0)",
            "Broken nonce-reuse variant with full-advantage attack",
            "Drop-in Enc/Dec interface for PA06",
        ]

    # Public interface for PA#6
    def Enc(self, k: int | bytes | str, m: bytes | str) -> tuple[int, bytes]:
        return self.enc.Enc(k, m)

    def Dec(self, k: int | bytes | str, r: int, c: bytes) -> bytes:
        return self.enc.Dec(k, r, c)

    def run_demo(self) -> str:
        key = random.getrandbits(GGMPRF.SEED_BITS)
        msg = b"hello POIS"
        nonce, ct = self.enc.encrypt(key, msg)
        recovered = self.enc.decrypt(key, nonce, ct)

        m0, m1 = b"msg_zero", b"msg_one!"  # 8 bytes each

        # Secure mode (random adversary)
        secure_game = INDCPAGame(self.enc, reuse_nonce=False)
        for _ in range(50):
            secure_game.challenge(m0, m1)
            secure_game.guess(random.randint(0, 1))

        # Broken mode (smart adversary with nonce reuse)
        broken_adv = self.attack.smart_adversary_advantage(m0, m1, rounds=50)

        # Nonce-reuse XOR attack
        xor_demo = self.attack.demonstrate(m0, m1)

        # Spec item 4: "queries two equal messages and detects identical ciphertexts"
        fixed_r = self.attack._fixed_nonce
        _, ct_same_1 = self.enc.encrypt(self.attack._key, m0, fixed_nonce=fixed_r)
        _, ct_same_2 = self.enc.encrypt(self.attack._key, m0, fixed_nonce=fixed_r)
        identical = ct_same_1 == ct_same_2

        # Contrast: with fresh nonces the same message produces different ciphertexts
        _, ct_fresh_1 = self.enc.encrypt(self.attack._key, m0)
        _, ct_fresh_2 = self.enc.encrypt(self.attack._key, m0)
        differ = ct_fresh_1 != ct_fresh_2

        return "\n".join([
            "PA03 demo active",
            "",
            "  Enc/Dec roundtrip:",
            f"    plaintext  = {msg!r}",
            f"    nonce      = {nonce}",
            f"    ciphertext = {ct.hex()}",
            f"    recovered  = {recovered!r}",
            f"    correct: {recovered == msg}",
            "",
            "  IND-CPA game (50 rounds, random adversary):",
            f"    advantage  = {secure_game.advantage:.4f}  (expected <= 0.1)",
            "",
            "  Broken mode (nonce reuse, smart adversary):",
            f"    advantage  = {broken_adv:.4f}  (expected = 1.0)",
            "",
            "  Deterministic encryption test (nonce reuse):",
            f"    Enc(m0, r={fixed_r}) = {ct_same_1.hex()}",
            f"    Enc(m0, r={fixed_r}) = {ct_same_2.hex()}",
            f"    Identical ciphertexts: {identical}  (broken: adversary detects equal messages!)",
            "",
            "  Fresh nonces (same message, different ciphertexts):",
            f"    Enc(m0, fresh_r1) = {ct_fresh_1.hex()}",
            f"    Enc(m0, fresh_r2) = {ct_fresh_2.hex()}",
            f"    Different ciphertexts: {differ}  (secure: adversary learns nothing)",
            "",
            "  Nonce-reuse XOR attack:",
            f"    ct0 XOR ct1 = {xor_demo['ct_xor_hex']}",
            f"    m0  XOR m1  = {xor_demo['m_xor_hex']}",
            f"    Attack succeeded: {xor_demo['attack_succeeds']}",
        ])
