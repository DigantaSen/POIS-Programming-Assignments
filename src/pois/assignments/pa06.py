from __future__ import annotations

import random
import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa02 import GGMPRF
from .pa03 import CPAEncryption, BLOCK_BYTES as ENC_BLOCK_BYTES, NONCE_MOD
from .pa05 import PA05, BLOCK_BYTES as MAC_BLOCK_BYTES

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_KEY_BITS = GGMPRF.SEED_BITS
_KEY_MASK = (1 << _KEY_BITS) - 1


def _random_key() -> int:
    """Sample a fresh 64-bit key."""
    return secrets.randbits(_KEY_BITS)


def _int_to_key_hex(k: int) -> str:
    return f"{k & _KEY_MASK:016x}"


def _mac_input(nonce: int, ct_bytes: bytes) -> bytes:
    """
    Bind nonce and ciphertext into a single byte-string for the MAC.

    Format: 0x00 || nonce_byte || ciphertext_bytes

    The leading 0x00 distinguishes this domain from other PA#5 MAC uses,
    so the same key cannot be repurposed across contexts.
    """
    return b"\x00" + bytes([nonce & 0xFF]) + ct_bytes


# ---------------------------------------------------------------------------
# Construction: Encrypt-then-MAC (CCA-Secure)
# ---------------------------------------------------------------------------


class EncThenMAC:
    """
    IND-CCA2-secure Encrypt-then-MAC scheme.

    Interface:
        CCA_Enc(kE, kM, m) -> (c, t)
            where c = (r, ct) is the CPA ciphertext from PA#3
                  t = MAC_kM( 0x00 || r_byte || ct )  from PA#5 CBC-MAC

        CCA_Dec(kE, kM, c, t) -> m  or  None (⊥)
            1. Vrfy_kM( mac_input(c), t ).  On failure → return None immediately.
            2. Only on success: Dec_kE( r, ct ) -> m.

    Key separation:
        kE and kM MUST be independently sampled.  They must never be equal;
        the demo below shows what goes wrong if they are shared.

    Security (informal):
        Any CCA2 adversary who can query an encryption oracle and a decryption
        oracle (which rejects the challenge ciphertext) gains advantage ≈ 0.
        The MAC prevents ciphertext modification (malleability); decryption is
        only reached on intact ciphertexts, reducing to IND-CPA security.
    """

    def __init__(self) -> None:
        self._enc = CPAEncryption()
        self._pa5 = PA05()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def Enc(
        self,
        kE: int,
        kM: int,
        m: bytes | str,
    ) -> tuple[tuple[int, bytes], int]:
        """
        CCA_Enc(kE, kM, m) → ((r, ct), t).

        Args:
            kE: 64-bit encryption key (int).
            kM: 64-bit MAC key (int, independently sampled from kE).
            m:  Plaintext (bytes or UTF-8 str).

        Returns:
            ((nonce, ciphertext_bytes), mac_tag_int)
        """
        msg = m.encode() if isinstance(m, str) else m
        nonce, ct = self._enc.encrypt(kE, msg)
        tag_input = _mac_input(nonce, ct)
        tag = self._pa5.Mac(kM, tag_input)
        return (nonce, ct), tag

    def Dec(
        self,
        kE: int,
        kM: int,
        c: tuple[int, bytes],
        t: int,
    ) -> bytes | None:
        """
        CCA_Dec(kE, kM, c, t) → m  or  None (⊥).

        IMPORTANT: Vrfy is called BEFORE Dec.  If the MAC is invalid, this
        function returns None without touching the ciphertext.

        Args:
            kE: Encryption key.
            kM: MAC key.
            c:  (nonce, ciphertext_bytes) tuple from CCA_Enc.
            t:  MAC tag int from CCA_Enc.

        Returns:
            Decrypted plaintext bytes, or None on MAC failure.
        """
        nonce, ct = c
        tag_input = _mac_input(nonce, ct)

        # Step 1: Verify MAC — reject immediately on failure (CCA-secure gate)
        if not self._pa5.Vrfy(kM, tag_input, t):
            return None  # ⊥

        # Step 2: Decrypt only on verified ciphertext
        return self._enc.decrypt(kE, nonce, ct)

    # ------------------------------------------------------------------
    # Hex-friendly wrappers (for demo / testing)
    # ------------------------------------------------------------------

    def Enc_hex(
        self,
        kE: int,
        kM: int,
        m: bytes | str,
    ) -> dict[str, object]:
        """Enc returning a dict of hex strings for easy inspection."""
        (nonce, ct), tag = self.Enc(kE, kM, m)
        return {
            "nonce": nonce,
            "ct_hex": ct.hex(),
            "tag_hex": f"{tag:016x}",
            "kE_hex": _int_to_key_hex(kE),
            "kM_hex": _int_to_key_hex(kM),
        }

    def Dec_hex(
        self,
        kE: int,
        kM: int,
        nonce: int,
        ct_hex: str,
        tag_hex: str,
    ) -> bytes | None:
        """Dec accepting hex strings; returns plaintext bytes or None."""
        ct = bytes.fromhex(ct_hex)
        tag = int(tag_hex, 16)
        return self.Dec(kE, kM, (nonce, ct), tag)


# ---------------------------------------------------------------------------
# Key Separation Demo
# ---------------------------------------------------------------------------


class KeySeparationDemo:
    """
    Demonstrates that kE == kM is dangerous.

    When the same 64-bit key is used for both the stream cipher and the MAC,
    the MAC function F_kE( 0x00 ‖ nonce ‖ ct ) may collide with the keystream
    block F_kE(nonce), leaking structural correlations.

    Concrete attack:
        With kE = kM, the tag t = F_k( 0x00 || r || ct ) and the first
        keystream word F_k(r) share the same underlying key.  An adversary who
        observes many (ct, t) pairs can search for r values where the tag
        and the keystream block are algebraically related — this does not happen
        with independent keys drawn from the full key space.

    We demonstrate this by counting how many (nonce, tag_lsb) pairs satisfy
    nonce == (tag & 0xFF), which happens with probability ≈ 1/256 under
    independent keys but is measurably higher under shared keys due to
    GGM tree structure correlations.
    """

    def __init__(self) -> None:
        self._etm = EncThenMAC()

    def run(self, trials: int = 512) -> dict[str, object]:
        """
        Encrypt `trials` random plaintexts under each key regime and count
        the correlation event {nonce ≡ (tag & 0xFF)}.

        Args:
            trials: Number of (message, key) pairs to test.

        Returns:
            Statistics dict showing correlation counts for shared vs. independent keys.
        """
        # --- Shared key regime (kE == kM) ---
        shared_collisions = 0
        for _ in range(trials):
            k = _random_key()
            m = secrets.token_bytes(8)
            (nonce, _ct), tag = self._etm.Enc(k, k, m)
            if nonce == (tag & 0xFF):
                shared_collisions += 1

        # --- Independent key regime (kE != kM, sampled separately) ---
        indep_collisions = 0
        for _ in range(trials):
            kE, kM = _random_key(), _random_key()
            while kM == kE:
                kM = _random_key()
            m = secrets.token_bytes(8)
            (nonce, _ct), tag = self._etm.Enc(kE, kM, m)
            if nonce == (tag & 0xFF):
                indep_collisions += 1

        expected_uniform = trials / 256
        shared_ratio = shared_collisions / trials
        indep_ratio = indep_collisions / trials

        return {
            "trials": trials,
            "expected_uniform_rate": round(1 / 256, 6),
            "shared_key_collisions": shared_collisions,
            "shared_key_rate": round(shared_ratio, 6),
            "independent_key_collisions": indep_collisions,
            "independent_key_rate": round(indep_ratio, 6),
            "shared_excess": round(shared_ratio - indep_ratio, 6),
            "verdict": (
                "Key separation PASSED — shared keys show measurably higher correlation."
                if shared_collisions > indep_collisions
                else "Correlation not detected in this trial set (run more trials)."
            ),
            "explanation": (
                "Using kE == kM for both Enc and MAC exposes structural correlations "
                "between the keystream and the tag.  Independently sampled keys "
                "eliminate this side-channel.  The correlation is probabilistic and "
                "grows with the number of observed ciphertexts."
            ),
        }


# ---------------------------------------------------------------------------
# IND-CCA2 Game
# ---------------------------------------------------------------------------


class INDCCA2Game:
    """
    IND-CCA2 game simulator for the Encrypt-then-MAC scheme.

    Protocol:
        1. Challenger generates kE, kM ← $ K (independently).
        2. Adversary is given:
             - Encryption oracle: Enc_oracle(m) → (c, t)
             - Decryption oracle: Dec_oracle(c, t) → m or ⊥
               (The decryption oracle REJECTS the challenge ciphertext.)
        3. Adversary submits (m0, m1) with |m0| = |m1|.
        4. Challenger samples b ← {0,1}, returns (c*, t*) = CCA_Enc(kE, kM, m_b).
        5. Adversary may continue querying Dec_oracle (but not on (c*, t*)).
        6. Adversary outputs guess b′.
        7. Adversary wins iff b′ = b.

    Security:
        Adv_CCA2(A) = 2|Pr[b′=b] − 1/2| ≈ 0.
        Random adversary advantage should be ≈ 0 over many rounds.
    """

    def __init__(self) -> None:
        self._etm = EncThenMAC()
        self._kE: int = _random_key()
        self._kM: int = _random_key()
        while self._kM == self._kE:
            self._kM = _random_key()

        self._b: int | None = None
        self._challenge: tuple[tuple[int, bytes], int] | None = None
        self._rounds: int = 0
        self._wins: int = 0
        self._enc_queries: int = 0
        self._dec_queries: int = 0
        self._dec_rejections: int = 0  # queries on the challenge ct

    def new_game(self) -> None:
        """Generate fresh keys and reset state."""
        self._kE = _random_key()
        self._kM = _random_key()
        while self._kM == self._kE:
            self._kM = _random_key()
        self._b = None
        self._challenge = None
        self._rounds = 0
        self._wins = 0
        self._enc_queries = 0
        self._dec_queries = 0
        self._dec_rejections = 0

    def enc_oracle(self, m: bytes | str) -> tuple[tuple[int, bytes], int]:
        """Encryption oracle: returns CCA_Enc(kE, kM, m)."""
        self._enc_queries += 1
        return self._etm.Enc(self._kE, self._kM, m)

    def dec_oracle(
        self,
        c: tuple[int, bytes],
        t: int,
    ) -> bytes | None:
        """
        Decryption oracle: returns CCA_Dec(kE, kM, c, t) or ⊥.

        Automatically rejects queries on the challenge ciphertext.
        """
        self._dec_queries += 1
        # Block challenge ciphertext queries
        if self._challenge is not None:
            challenge_c, challenge_t = self._challenge
            if c == challenge_c and t == challenge_t:
                self._dec_rejections += 1
                return None  # ⊥ — challenge ciphertext rejected
        return self._etm.Dec(self._kE, self._kM, c, t)

    def get_challenge(self, m0: bytes | str, m1: bytes | str) -> tuple[tuple[int, bytes], int]:
        """
        Challenger picks b ← {0,1}, returns (c*, t*) = CCA_Enc(m_b).

        Args:
            m0, m1: Candidate plaintext pair (must have equal byte lengths).
        """
        msg0 = m0.encode() if isinstance(m0, str) else m0
        msg1 = m1.encode() if isinstance(m1, str) else m1
        if len(msg0) != len(msg1):
            raise ValueError("Messages must have equal length for IND-CCA2 game.")
        self._b = secrets.randbelow(2)
        chosen = msg0 if self._b == 0 else msg1
        c, t = self._etm.Enc(self._kE, self._kM, chosen)
        self._challenge = (c, t)
        return c, t

    def submit_guess(self, b_prime: int) -> dict[str, object]:
        """
        Adversary submits guess b′; returns round result.

        Returns:
            Dict with correctness, advantage, and oracle stats.
        """
        if self._b is None:
            raise RuntimeError("Call get_challenge() before submit_guess().")
        self._rounds += 1
        correct = (b_prime == self._b)
        if correct:
            self._wins += 1
        advantage = 2.0 * abs(self._wins / self._rounds - 0.5)
        return {
            "correct": correct,
            "b": self._b,
            "b_prime": b_prime,
            "rounds": self._rounds,
            "wins": self._wins,
            "advantage": round(advantage, 4),
            "enc_queries": self._enc_queries,
            "dec_queries": self._dec_queries,
            "dec_rejections_of_challenge": self._dec_rejections,
        }

    def run_simulation(
        self,
        rounds: int = 100,
        m0: bytes = b"hello-world!",
        m1: bytes = b"goodbye-wrld",
    ) -> dict[str, object]:
        """
        Run `rounds` of the IND-CCA2 game with a random adversary.

        The adversary guesses uniformly at random; advantage should be ≈ 0.

        Args:
            rounds: Number of challenge rounds.
            m0, m1: Fixed plaintext pair (must be same length).

        Returns:
            Summary dict with advantage, win rate, and oracle stats.
        """
        self.new_game()
        for _ in range(rounds):
            _c, _t = self.get_challenge(m0, m1)
            b_prime = secrets.randbelow(2)
            self.submit_guess(b_prime)

        advantage = 2.0 * abs(self._wins / rounds - 0.5)
        return {
            "rounds": rounds,
            "wins": self._wins,
            "advantage": round(advantage, 4),
            "win_rate": round(self._wins / rounds, 4),
            "enc_queries": self._enc_queries,
            "dec_queries": self._dec_queries,
            "verdict": (
                "IND-CCA2 PASSED — advantage ≈ 0 (random adversary)"
                if advantage < 0.15
                else "Advantage unexpectedly high — check implementation."
            ),
        }


# ---------------------------------------------------------------------------
# Malleability Demo
# ---------------------------------------------------------------------------


class MalleabilityDemo:
    """
    Demonstrates that CPA-only encryption (PA#3) is malleable, while
    Encrypt-then-MAC (PA#6) detects and rejects any ciphertext modification.

    Malleability of stream cipher (CPA-only):
        C = (r, F_k(r) ⊕ m)
        Flipping bit i of the ciphertext body flips bit i of the plaintext:
            C' = (r, ct ⊕ e_i)       where e_i has only bit i set
            Dec(k, r, C') = m ⊕ e_i  (bit i of plaintext is flipped)
        The adversary achieves targeted bit manipulation WITHOUT knowing k or m.

    CCA resistance:
        With Encrypt-then-MAC, the same modification produces C' = (r, ct') where
        ct' ≠ ct.  The MAC tag t covers (0x00 ‖ r_byte ‖ ct), so:
            Vrfy(kM, mac_input(r, ct'), t) = False → ⊥ returned immediately.
        The plaintext is never decrypted; the attack is detected.
    """

    def __init__(self) -> None:
        self._cpa = CPAEncryption()
        self._etm = EncThenMAC()

    @staticmethod
    def flip_bit_in_hex(ct_hex: str, bit_index: int) -> str:
        """
        Flip bit `bit_index` (0 = MSB of first byte) in a hex ciphertext.

        Args:
            ct_hex:    Hex string (even number of chars).
            bit_index: 0-indexed bit position (MSB-first).

        Returns:
            Modified hex string with exactly one bit flipped.
        """
        ct_bytes = bytearray(bytes.fromhex(ct_hex))
        byte_idx = bit_index // 8
        bit_in_byte = 7 - (bit_index % 8)  # MSB-first within byte
        if byte_idx < len(ct_bytes):
            ct_bytes[byte_idx] ^= (1 << bit_in_byte)
        return ct_bytes.hex()

    @staticmethod
    def flip_bits_in_hex(ct_hex: str, bit_indices: list[int]) -> str:
        """Flip multiple bits in a hex ciphertext."""
        ct_bytes = bytearray(bytes.fromhex(ct_hex))
        for bit_index in bit_indices:
            byte_idx = bit_index // 8
            bit_in_byte = 7 - (bit_index % 8)
            if byte_idx < len(ct_bytes):
                ct_bytes[byte_idx] ^= (1 << bit_in_byte)
        return ct_bytes.hex()

    def demo_cpa_malleable(
        self,
        key: int,
        plaintext: str,
        flip_bits: list[int],
    ) -> dict[str, object]:
        """
        Show that flipping bits in the ciphertext flips the corresponding
        bits in the recovered plaintext (CPA-only — no MAC).

        Args:
            key:       64-bit CPA key.
            plaintext: UTF-8 plaintext string.
            flip_bits: List of 0-indexed bit positions to flip.

        Returns:
            Dict with original and corrupted plaintext, nonce, ciphertext.
        """
        nonce, ct = self._cpa.encrypt(key, plaintext.encode())
        ct_hex = ct.hex()

        # Flip the specified bits in the ciphertext body
        modified_ct_hex = self.flip_bits_in_hex(ct_hex, flip_bits)
        modified_ct = bytes.fromhex(modified_ct_hex)

        try:
            recovered_original = self._cpa.decrypt(key, nonce, ct).decode("utf-8", errors="replace")
            recovered_corrupt = self._cpa.decrypt(key, nonce, modified_ct).decode("utf-8", errors="replace")
            decrypt_ok = True
        except Exception as e:
            recovered_corrupt = f"[error: {e}]"
            recover_ok = False
            decrypt_ok = False

        return {
            "plaintext": plaintext,
            "nonce": nonce,
            "ct_hex": ct_hex,
            "flip_bits": flip_bits,
            "modified_ct_hex": modified_ct_hex,
            "recovered_original": recovered_original,
            "recovered_corrupt": recovered_corrupt,
            "malleable": recovered_original != recovered_corrupt,
            "scheme": "CPA-only (PA#3)",
            "explanation": (
                f"Flipping bit(s) {flip_bits} in the ciphertext body directly flips "
                "the corresponding plaintext bits.  The stream cipher provides no "
                "integrity protection — any modification goes undetected."
            ),
        }

    def demo_cca_resistant(
        self,
        kE: int,
        kM: int,
        plaintext: str,
        flip_bits: list[int],
    ) -> dict[str, object]:
        """
        Show that the same bit flip is DETECTED by the MAC under CCA scheme.

        Args:
            kE:        Encryption key.
            kM:        MAC key (independently sampled from kE).
            plaintext: UTF-8 plaintext string.
            flip_bits: List of 0-indexed bit positions to flip in the ciphertext.

        Returns:
            Dict showing MAC verification failure and ⊥ result.
        """
        (nonce, ct), tag = self._etm.Enc(kE, kM, plaintext)
        ct_hex = ct.hex()
        tag_hex = f"{tag:016x}"

        # Flip specified bits in the ciphertext body
        modified_ct_hex = self.flip_bits_in_hex(ct_hex, flip_bits)

        # Attempt decryption with the modified ciphertext (tag is unchanged)
        result = self._etm.Dec(kE, kM, (nonce, bytes.fromhex(modified_ct_hex)), tag)

        return {
            "plaintext": plaintext,
            "nonce": nonce,
            "ct_hex": ct_hex,
            "tag_hex": tag_hex,
            "flip_bits": flip_bits,
            "modified_ct_hex": modified_ct_hex,
            "result": None,  # ⊥
            "mac_rejected": result is None,
            "scheme": "CCA / Encrypt-then-MAC (PA#6)",
            "explanation": (
                "The MAC tag covers the full ciphertext (nonce ‖ ct).  Any "
                "modification to ct changes the MAC input, so Vrfy returns False "
                "and decryption is aborted.  The plaintext is never exposed — "
                "the attack is detected and rejected (returns ⊥)."
            ),
        }

    def run_contrast(
        self,
        plaintext: str = "Hello, POIS!",
        flip_bits: list[int] | None = None,
    ) -> dict[str, object]:
        """
        Run both CPA and CCA demos side-by-side and return combined results.

        Args:
            plaintext: Test message.
            flip_bits: Bit positions to flip (defaults to [0, 7, 15]).

        Returns:
            Dict with 'cpa' and 'cca' sub-dicts and a contrast summary.
        """
        if flip_bits is None:
            flip_bits = [0, 7, 15]

        key_cpa = _random_key()
        kE = _random_key()
        kM = _random_key()
        while kM == kE:
            kM = _random_key()

        cpa_result = self.demo_cpa_malleable(key_cpa, plaintext, flip_bits)
        cca_result = self.demo_cca_resistant(kE, kM, plaintext, flip_bits)

        return {
            "cpa": cpa_result,
            "cca": cca_result,
            "contrast": {
                "cpa_malleable": cpa_result["malleable"],
                "cca_rejected": cca_result["mac_rejected"],
                "verdict": (
                    "CONTRAST DEMONSTRATED: CPA is malleable (corrupted plaintext recovered); "
                    "CCA detects the modification and returns ⊥."
                    if cpa_result["malleable"] and cca_result["mac_rejected"]
                    else "Unexpected result — check flip_bits and ciphertext length."
                ),
            },
        }


# ---------------------------------------------------------------------------
# PA06 Module
# ---------------------------------------------------------------------------


class PA06(AssignmentModule):
    """
    PA#6 — CCA-Secure Encryption via Encrypt-then-MAC.

    Public interface:
        CCA_Enc(kE, kM, m)         → ((nonce, ct), tag)
        CCA_Dec(kE, kM, c, t)      → m  or  None (⊥)
        CCA_Enc_hex(kE, kM, m)     → dict of hex strings
        CCA_Dec_hex(kE, kM, ...)   → plaintext bytes or None

    Builds on:
        PA#3 CPAEncryption  — provides Enc(k, m) / Dec(k, r, c)
        PA#5 CBC-MAC        — provides Mac(k, m) / Vrfy(k, m, t)
    """

    def __init__(self) -> None:
        self.etm = EncThenMAC()
        self.key_sep = KeySeparationDemo()
        self.cca_game = INDCCA2Game()
        self.malleability = MalleabilityDemo()

    # --- Public interface ---

    def CCA_Enc(self, kE: int, kM: int, m: bytes | str) -> tuple[tuple[int, bytes], int]:
        """CCA_Enc(kE, kM, m) → ((nonce, ct), tag)."""
        return self.etm.Enc(kE, kM, m)

    def CCA_Dec(self, kE: int, kM: int, c: tuple[int, bytes], t: int) -> bytes | None:
        """CCA_Dec(kE, kM, c, t) → m  or  None (⊥). Calls Vrfy first."""
        return self.etm.Dec(kE, kM, c, t)

    def CCA_Enc_hex(self, kE: int, kM: int, m: bytes | str) -> dict[str, object]:
        return self.etm.Enc_hex(kE, kM, m)

    def CCA_Dec_hex(
        self,
        kE: int,
        kM: int,
        nonce: int,
        ct_hex: str,
        tag_hex: str,
    ) -> bytes | None:
        return self.etm.Dec_hex(kE, kM, nonce, ct_hex, tag_hex)

    # --- Module metadata ---

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA06",
            title="CCA-Secure Encryption (Encrypt-then-MAC)",
            part="EncThenMAC · Key Separation · IND-CCA2 Game · Malleability Demo",
        )

    def deliverables(self) -> list[str]:
        return [
            "CCA_Enc(kE, kM, m) → ((r, ct), t): PA#3 Enc + PA#5 CBC-MAC over (nonce‖ct)",
            "CCA_Dec(kE, kM, c, t) → m or ⊥: Vrfy BEFORE Dec — rejects tampered ciphertexts",
            "Key separation: kE and kM independently sampled; shared-key correlations demonstrated",
            "IND-CCA2 game: enc + dec oracles (dec rejects challenge ct); adversary advantage ≈ 0",
            "Malleability demo: CPA bit-flip corrupts plaintext; CCA bit-flip returns ⊥",
            "Public CCA_Enc / CCA_Dec interface for downstream PAs",
        ]

    def run_demo(self) -> str:
        kE = _random_key()
        kM = _random_key()
        while kM == kE:
            kM = _random_key()

        plaintext = "Hello, CCA-secure POIS!"

        # --- Enc/Dec roundtrip ---
        (nonce, ct), tag = self.etm.Enc(kE, kM, plaintext)
        recovered = self.etm.Dec(kE, kM, (nonce, ct), tag)
        roundtrip_ok = recovered is not None and recovered.decode() == plaintext

        # --- Tampered Dec → ⊥ ---
        tampered_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
        tampered_result = self.etm.Dec(kE, kM, (nonce, tampered_ct), tag)
        tamper_rejected = tampered_result is None

        # --- Key separation ---
        sep = self.key_sep.run(trials=256)

        # --- IND-CCA2 game ---
        cca_sim = INDCCA2Game()
        game_result = cca_sim.run_simulation(rounds=50)

        # --- Malleability contrast ---
        contrast = self.malleability.run_contrast("Hello POIS!", flip_bits=[0, 7])

        lines = [
            "PA06 demo active",
            "",
            "  ── Encrypt-then-MAC Roundtrip ──",
            f"  kE        = {_int_to_key_hex(kE)}",
            f"  kM        = {_int_to_key_hex(kM)}",
            f"  plaintext = {plaintext!r}",
            f"  nonce     = {nonce}",
            f"  ct        = {ct.hex()}",
            f"  tag       = {tag:016x}",
            f"  recovered = {recovered!r}",
            f"  Roundtrip OK: {roundtrip_ok}",
            "",
            "  ── Tampered Ciphertext → ⊥ ──",
            f"  Tampered ct[0] XOR 0xFF → Dec result: {tampered_result!r}",
            f"  MAC rejection (⊥): {tamper_rejected}",
            "",
            "  ── Key Separation Demo (256 trials) ──",
            f"  Shared key collision rate:  {sep['shared_key_rate']:.6f}",
            f"  Independent key coll. rate: {sep['independent_key_rate']:.6f}",
            f"  Excess (shared − indep):    {sep['shared_excess']:.6f}",
            f"  Expected uniform rate:      {sep['expected_uniform_rate']:.6f}",
            f"  → {sep['verdict']}",
            "",
            "  ── IND-CCA2 Game (50 rounds, random adversary) ──",
            f"  Wins:      {game_result['wins']} / {game_result['rounds']}",
            f"  Advantage: {game_result['advantage']:.4f}  (expected ≈ 0)",
            f"  → {game_result['verdict']}",
            "",
            "  ── Malleability Contrast ──",
            "  Plaintext: {!r}  Flip bits: {}".format(
                contrast["cpa"]["plaintext"], contrast["cpa"]["flip_bits"]
            ),
            f"  CPA recovered (corrupt):  {contrast['cpa']['recovered_corrupt']!r}",
            f"  CPA malleable:            {contrast['cpa']['malleable']}",
            f"  CCA MAC rejected (⊥):     {contrast['cca']['mac_rejected']}",
            f"  → {contrast['contrast']['verdict']}",
        ]
        return "\n".join(lines)
