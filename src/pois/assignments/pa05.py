from __future__ import annotations

import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa01 import _to_int
from .pa02 import GGMPRF


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

BLOCK_BYTES = 8  # 64 bits — matches GGMPRF.SEED_BITS
BLOCK_MASK = (1 << (8 * BLOCK_BYTES)) - 1


def _to_bytes8(v: int | bytes) -> bytes:
    """Coerce an int or bytes value to exactly 8 bytes (big-endian)."""
    if isinstance(v, bytes):
        return (v + b"\x00" * BLOCK_BYTES)[:BLOCK_BYTES]
    return (v & BLOCK_MASK).to_bytes(BLOCK_BYTES, "big")


def _xor8(a: bytes, b: bytes) -> bytes:
    """XOR two sequences of bytes (up to 8 bytes each)."""
    return bytes(x ^ y for x, y in zip(a[:BLOCK_BYTES], b[:BLOCK_BYTES]))


def _pkcs8_pad(data: bytes) -> bytes:
    """Pad data to a multiple of BLOCK_BYTES using PKCS-style padding."""
    pad = BLOCK_BYTES - (len(data) % BLOCK_BYTES)
    return data + bytes([pad] * pad)


# ---------------------------------------------------------------------------
# Construction 1: PRF-MAC  (fixed-length)
# ---------------------------------------------------------------------------


class PRFMAC:
    """
    PRF-MAC for fixed-length messages (exactly one 64-bit block).

    Construction:
        Mac_k(m)   = F_k(m)               [t = F_k(m)]
        Vrfy_k(m, t) = (Mac_k(m) == t)

    The PRF F_k is the GGM PRF from PA#2 (GGMPRF.F).

    Security (PRF → MAC):
        Any EUF-CMA forger A against this MAC yields a PRF distinguisher D
        with Adv_PRF(D) ≥ Adv_MAC(A) − q/2^n,  q = signing queries.
        Intuitively: a forger must guess F_k on a new query, which is as hard
        as distinguishing F_k from a uniformly random function.
    """

    BLOCK_BITS = GGMPRF.SEED_BITS
    KEY_MASK = (1 << GGMPRF.SEED_BITS) - 1

    def __init__(self) -> None:
        self._prf = GGMPRF()

    def Mac(self, k: int | bytes, m: int | bytes) -> int:
        """
        Produce tag t = F_k(m) for a single-block message.

        Args:
            k: MAC key (64-bit int or 8 bytes).
            m: Message (64-bit int or 8 bytes; exactly one block).

        Returns:
            64-bit integer tag.
        """
        k_int = _to_int(k) & self.KEY_MASK
        m_int = _to_int(m) & self.KEY_MASK
        return self._prf.F(k_int, m_int)

    def Vrfy(self, k: int | bytes, m: int | bytes, t: int) -> bool:
        """Return True iff t is a valid tag for m under key k."""
        return self.Mac(k, m) == t

    def Mac_hex(self, k: int | bytes, m: int | bytes) -> str:
        return f"{self.Mac(k, m):016x}"


# ---------------------------------------------------------------------------
# Construction 2: CBC-MAC  (variable-length)
# ---------------------------------------------------------------------------


class CBCMAC:
    """
    CBC-MAC for arbitrary-length messages via the GGM PRF from PA#2.

    Construction:
        Pad m to a multiple of 8 bytes (PKCS-style, which is prefix-free).
        Split into blocks M_1, …, M_l.
        t_0 = 0^64
        t_i = F_k( t_{i-1} ⊕ M_i )
        Tag = t_l

    Security:
        Inherits from PRF security of F_k.  PKCS padding ensures the encoding
        is prefix-free, preventing extension attacks on the chained tag.
        (Without prefix-freeness, an adversary could forge on m ‖ tag(m).)
    """

    KEY_MASK = (1 << GGMPRF.SEED_BITS) - 1

    def __init__(self) -> None:
        self._prf = GGMPRF()

    def _chain(self, k_int: int, data: bytes) -> int:
        """Core CBC-MAC computation on already-prepared byte data."""
        padded = _pkcs8_pad(data)
        state = 0
        for i in range(0, len(padded), BLOCK_BYTES):
            block = padded[i : i + BLOCK_BYTES]
            xored_int = _to_int(_xor8(_to_bytes8(state), block)) & self.KEY_MASK
            state = self._prf.F(k_int, xored_int)
        return state

    def Mac(self, k: int | bytes, m: bytes | str) -> int:
        """
        Variable-length CBC-MAC.

        Args:
            k: Key (64-bit int or 8 bytes).
            m: Message (bytes or UTF-8 str; arbitrary length).

        Returns:
            64-bit integer tag.
        """
        if isinstance(m, str):
            m = m.encode("utf-8")
        k_int = _to_int(k) & self.KEY_MASK
        return self._chain(k_int, m)

    def Vrfy(self, k: int | bytes, m: bytes | str, t: int) -> bool:
        """Return True iff t is a valid tag for m under key k."""
        return self.Mac(k, m) == t

    def Mac_hex(self, k: int | bytes, m: bytes | str) -> str:
        return f"{self.Mac(k, m):016x}"


# ---------------------------------------------------------------------------
# Construction 3: HMAC stub  (forward pointer → PA#10)
# ---------------------------------------------------------------------------


def hmac_stub(k: bytes, m: bytes) -> bytes:
    """
    HMAC stub — NOT IMPLEMENTED until PA#10.

    Formula (for reference):
        HMAC_k(m) = H( (k ⊕ opad) ‖ H( (k ⊕ ipad) ‖ m ) )

    Where H is a collision-resistant hash, opad = 0x5c5c…, ipad = 0x3636….

    NOTE: Do NOT use Python's hmac module here or in PA#10.
          The PA#10 implementation must build H from scratch using PA#8's CRHF.

    Raises:
        NotImplementedError: always — stub for PA#10.
    """
    raise NotImplementedError(
        "HMAC is a forward-pointer stub (due: PA#10). "
        "Do NOT call a library HMAC — implement H((k⊕opad)‖H((k⊕ipad)‖m)) "
        "from scratch using the PA#8 hash in PA#10."
    )


# ---------------------------------------------------------------------------
# MAC ⇒ PRF witness  (backward direction demo)
# ---------------------------------------------------------------------------


class MACPRFWitness:
    """
    Demonstrates that PRF-MAC, queried on uniformly random inputs,
    is indistinguishable from a random oracle — concretely witnessing MAC ⇒ PRF.

    We run a statistical test identical to PA#2's distinguishing game, but
    using the MAC oracle as the keyed function.  The results should be
    indistinguishable from those of a truly random function.
    """

    def __init__(self) -> None:
        self._mac = PRFMAC()

    def run(self, queries: int = 100) -> dict[str, object]:
        """
        Query PRF-MAC and a random oracle on the same uniform random inputs.
        Compare bit distributions — no PPT adversary should distinguish them.

        Args:
            queries: Number of random inputs to test.

        Returns:
            Statistics dict with ones ratios and indistinguishability verdict.
        """
        key = secrets.randbits(GGMPRF.SEED_BITS)
        rnd_oracle: dict[int, int] = {}
        mac_bits = ""
        rnd_bits = ""

        for _ in range(queries):
            m = secrets.randbits(GGMPRF.SEED_BITS)
            mac_out = self._mac.Mac(key, m)
            mac_bits += f"{mac_out:064b}"
            if m not in rnd_oracle:
                rnd_oracle[m] = secrets.randbits(GGMPRF.SEED_BITS)
            rnd_bits += f"{rnd_oracle[m]:064b}"

        mac_ratio = mac_bits.count("1") / len(mac_bits)
        rnd_ratio = rnd_bits.count("1") / len(rnd_bits)
        delta = abs(mac_ratio - rnd_ratio)

        return {
            "queries": queries,
            "mac_ones_ratio": round(mac_ratio, 5),
            "random_ones_ratio": round(rnd_ratio, 5),
            "statistical_distance": round(delta, 6),
            "indistinguishable": delta < 0.05,
            "verdict": "MAC ⇒ PRF witness PASSED" if delta < 0.05 else "FAILED (check PRF)",
        }


# ---------------------------------------------------------------------------
# EUF-CMA Forgery Game
# ---------------------------------------------------------------------------


class EUFCMAGame:
    """
    EUF-CMA (Existential Unforgeability under Chosen-Message Attack) game.

    Setup:
        Challenger picks k ←$ K, keeps it hidden.

    Adversary phase:
        Adversary queries signing oracle up to `max_queries` times:
            (m_i, Mac_k(m_i))  for chosen messages m_i.

    Forgery:
        Adversary submits (m*, t*) where m* ∉ {m_i}.
        If Vrfy_k(m*, t*) = 1, the adversary wins.

    Security guarantee:
        Adv_EUF-CMA(A) ≤ Adv_PRF(D) + q/2^n  which is negligible for our GGM PRF.
        Graders expect 0 forgery successes in ≥ 20 attempts.
    """

    _WORD_BANK = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
        "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
        "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
        "victor", "whiskey", "xray", "yankee", "zulu", "aegis", "beacon",
        "cipher", "delta2", "epsilon", "falcon", "gamma", "hydra", "iris",
        "janus", "kappa", "lambda", "morpheus", "nexus", "oracle", "prism",
        "quantum", "raven", "sigma", "theta", "umbra", "vortex", "warden",
        "xenon", "yield", "zenith",
    ]

    def __init__(self, mac_scheme: str = "PRF-MAC") -> None:
        self._scheme = mac_scheme
        self._prf_mac = PRFMAC()
        self._cbc_mac = CBCMAC()
        self._key: int = 0
        self._signed: dict[str, str] = {}   # msg_text → tag_hex
        self.attempts: int = 0
        self.successes: int = 0
        self.new_game()

    def new_game(self) -> None:
        """Start a fresh game: generate new hidden key, clear all state."""
        self._key = secrets.randbits(GGMPRF.SEED_BITS)
        self._signed = {}
        self.attempts = 0
        self.successes = 0

    def _sign(self, msg: str) -> str:
        """Sign a text message; return tag hex string."""
        m_bytes = msg.encode("utf-8")
        if self._scheme == "PRF-MAC":
            m_int = int.from_bytes(
                (m_bytes + b"\x00" * BLOCK_BYTES)[:BLOCK_BYTES], "big"
            )
            tag = self._prf_mac.Mac(self._key, m_int)
        else:
            tag = self._cbc_mac.Mac(self._key, m_bytes)
        return f"{tag:016x}"

    def get_signed_pairs(self, n: int = 50) -> list[dict[str, str]]:
        """
        Generate up to n (message, tag) pairs using the hidden key.
        Each word is from a fixed word bank; overflow uses msg-NNNN format.

        Returns:
            List of {msg: str, tag: str} dicts.
        """
        idx = 0
        while len(self._signed) < n:
            msg = self._WORD_BANK[idx] if idx < len(self._WORD_BANK) else f"msg-{idx:04d}"
            idx += 1
            if msg not in self._signed:
                self._signed[msg] = self._sign(msg)
        return [{"msg": m, "tag": t} for m, t in list(self._signed.items())[:n]]

    def submit_forgery(self, msg: str, tag_hex: str) -> dict[str, object]:
        """
        Adversary submits a forgery attempt (msg*, tag*).

        Args:
            msg:     Candidate new message (must not be in signed set).
            tag_hex: Proposed tag (16 hex characters).

        Returns:
            {accepted: bool, attempts: int, successes: int, reason: str}
        """
        self.attempts += 1

        if msg in self._signed:
            return {
                "accepted": False,
                "attempts": self.attempts,
                "successes": self.successes,
                "reason": "Message already in signed set — not a new-message forgery.",
            }

        real_tag = self._sign(msg)
        accepted = tag_hex.strip().lower() == real_tag
        if accepted:
            self.successes += 1

        return {
            "accepted": accepted,
            "attempts": self.attempts,
            "successes": self.successes,
            "reason": (
                "Forgery accepted! (unexpected — PRF security may be broken)"
                if accepted
                else f"Forgery rejected. Real tag = {real_tag}."
            ),
        }


# ---------------------------------------------------------------------------
# Toy Merkle-Damgård hash + length-extension demo
# ---------------------------------------------------------------------------


class ToyMDHash:
    """
    Toy Merkle-Damgård hash using the GGM PRF as compression function.

    Compression: compress(state, block) = F_{FIXED_KEY}(state ⊕ block)
    where FIXED_KEY is a public constant.

    This deliberately mirrors real MD constructions (MD5/SHA-1 family) and
    suffers from genuine length-extension attacks, motivating HMAC's nesting.

    It is NOT a secure hash — it is a pure educational Merkle-Damgård model.
    """

    IV: int = 0xDEADBEEFCAFE1234          # public initial value
    FIXED_KEY: int = 0xA5B4C3D2E1F09817   # public compression key (not secret MAC key)

    def __init__(self) -> None:
        self._prf = GGMPRF()
        self._mask = (1 << GGMPRF.SEED_BITS) - 1

    def _compress(self, state: int, block: int) -> int:
        """One-call compression: F_{FIXED_KEY}(state ⊕ block)."""
        inp = (state ^ block) & self._mask
        return self._prf.F(self.FIXED_KEY, inp)

    def _md_pad(self, data: bytes, prefix_len: int = 0) -> bytes:
        """
        Merkle-Damgård padding.
        Append 0x80, then zero bytes until len ≡ 0 (mod 8), then 8-byte
        big-endian encoding of the total bit-length (including any hidden prefix).
        """
        total_bits = (len(data) + prefix_len) * 8
        padded = data + b"\x80"
        while len(padded) % BLOCK_BYTES != 0:
            padded += b"\x00"
        padded += total_bits.to_bytes(BLOCK_BYTES, "big")
        # Final length must be a multiple of BLOCK_BYTES
        if len(padded) % BLOCK_BYTES != 0:
            padded += b"\x00" * (BLOCK_BYTES - len(padded) % BLOCK_BYTES)
        return padded

    def digest(self, padded_data: bytes, initial_state: int | None = None) -> int:
        """
        Compress padded_data block-by-block from initial_state (or IV).
        `padded_data` must already be MD-padded.
        """
        state = self.IV if initial_state is None else initial_state
        for i in range(0, len(padded_data), BLOCK_BYTES):
            block_bytes = padded_data[i : i + BLOCK_BYTES]
            block_int = int.from_bytes(block_bytes, "big") & self._mask
            state = self._compress(state, block_int)
        return state

    def hash(self, data: bytes) -> int:
        """Public interface: hash raw data (pads internally)."""
        return self.digest(self._md_pad(data))

    def hash_hex(self, data: bytes) -> str:
        return f"{self.hash(data):016x}"


class LengthExtensionDemo:
    """
    Demonstrates the length-extension vulnerability in naive H(k ‖ m).

    Naive MAC:  t = H(k ‖ m)   using the toy Merkle-Damgård hash.

    Attack (Adversary knows m, t, and |k|):
        1. Compute the padding that H appended to k ‖ m  (call it pad).
        2. Resume hashing from state t (the final chaining value of H(k‖m‖pad)).
        3. Hash a chosen suffix:  t' = H_resume(suffix_with_new_pad).
        4. t' is a valid MAC of  (m ‖ pad ‖ suffix)  under the SAME key k,
           without ever seeing k.

    This is a real structural attack on Merkle-Damgård.
    HMAC fixes it by nesting:  H((k⊕opad) ‖ H((k⊕ipad) ‖ m)).
    """

    def __init__(self) -> None:
        self._hash = ToyMDHash()
        self._key: int = secrets.randbits(GGMPRF.SEED_BITS)
        self._key_len: int = BLOCK_BYTES   # Key length is publicly known

    def new_key(self) -> None:
        self._key = secrets.randbits(GGMPRF.SEED_BITS)

    def naive_mac(self, m: bytes | str) -> str:
        """
        Naive MAC: t = H(k ‖ m).  VULNERABLE to length-extension.

        Args:
            m: Message bytes or UTF-8 string.

        Returns:
            16-hex-char tag.
        """
        if isinstance(m, str):
            m = m.encode("utf-8")
        k_bytes = self._key.to_bytes(BLOCK_BYTES, "big")
        combined = k_bytes + m
        padded = self._hash._md_pad(combined)
        tag = self._hash.digest(padded)
        return f"{tag:016x}"

    def extend(
        self,
        original_m: bytes | str,
        original_tag_hex: str,
        suffix: bytes | str,
    ) -> dict[str, object]:
        """
        Length-extension attack: forge a valid tag for (m ‖ pad ‖ suffix)
        using only (m, t = H(k‖m), |k|) — no knowledge of k.

        Args:
            original_m:     Original message m.
            original_tag_hex: Hex tag t = H(k ‖ m).
            suffix:         Attacker-chosen suffix bytes.

        Returns:
            Dict with extended message, extended tag, and verification result.
        """
        if isinstance(original_m, str):
            original_m = original_m.encode("utf-8")
        if isinstance(suffix, str):
            suffix = suffix.encode("utf-8")

        # The glue padding is what the hash appended to (k ‖ m).
        # The attacker knows |k| (= self._key_len), so they can reconstruct it.
        full_kp_m = b"\x00" * self._key_len + original_m   # k unknown → use zeros for padding calc
        glue_pad = self._hash._md_pad(full_kp_m)[len(full_kp_m):]

        # Extended message the adversary presents (k prefix is hidden from challenger)
        extended_m = original_m + glue_pad + suffix

        # The full input that was hashed to produce t is: (k ‖ m ‖ glue_pad)
        # After that: state = t.  Now hash suffix with a fresh padding that
        # counts total bytes = len(k ‖ m ‖ glue_pad ‖ suffix).
        prefix_len = self._key_len + len(original_m) + len(glue_pad)
        suffix_padded = self._hash._md_pad(suffix, prefix_len=prefix_len)

        resume_state = int(original_tag_hex, 16)
        extended_tag = self._hash.digest(suffix_padded, initial_state=resume_state)
        extended_tag_hex = f"{extended_tag:016x}"

        # Challenger verification: compute H(k ‖ extended_m) from scratch
        k_bytes = self._key.to_bytes(BLOCK_BYTES, "big")
        full_extended = k_bytes + extended_m
        full_extended_padded = self._hash._md_pad(full_extended)
        expected = self._hash.digest(full_extended_padded)
        expected_hex = f"{expected:016x}"
        verified = extended_tag_hex == expected_hex

        return {
            "original_msg_text": original_m.decode("utf-8", errors="replace"),
            "original_msg_hex": original_m.hex(),
            "original_tag_hex": original_tag_hex,
            "glue_pad_hex": glue_pad.hex(),
            "suffix_text": suffix.decode("utf-8", errors="replace"),
            "suffix_hex": suffix.hex(),
            "extended_msg_hex": extended_m.hex(),
            "extended_tag_hex": extended_tag_hex,
            "verified": verified,
            "explanation": (
                "The attacker resumed hashing from state t = H(k ‖ m ‖ pad) "
                "and computed a valid tag for (m ‖ pad ‖ suffix) WITHOUT knowing k. "
                "HMAC prevents this: outer hash wraps the inner hash output, so "
                "there is no reachable intermediate chaining state to resume from."
            ),
        }


# ---------------------------------------------------------------------------
# PA05 module
# ---------------------------------------------------------------------------


class PA05(AssignmentModule):
    """
    PA#5 — Message Authentication Codes (MACs).

    Public interface for PA#6 and later:
        Mac(k, m)         → int tag
        Mac_hex(k, m)     → hex str tag
        Vrfy(k, m, t)     → bool

    The default scheme is CBC-MAC (variable-length).
    """

    def __init__(self) -> None:
        self.prf_mac = PRFMAC()
        self.cbc_mac = CBCMAC()
        self.euf_cma = EUFCMAGame(mac_scheme="CBC-MAC")
        self.len_ext = LengthExtensionDemo()
        self.witness = MACPRFWitness()

    # --- Public interface for PA#6 ---

    def Mac(self, k: int | bytes, m: bytes | str) -> int:
        """Variable-length CBC-MAC (default scheme). Interface for PA#6."""
        return self.cbc_mac.Mac(k, m)

    def Mac_hex(self, k: int | bytes, m: bytes | str) -> str:
        return self.cbc_mac.Mac_hex(k, m)

    def Vrfy(self, k: int | bytes, m: bytes | str, t: int) -> bool:
        return self.cbc_mac.Vrfy(k, m, t)

    # --- Module metadata ---

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA05",
            title="Message Authentication Codes (MACs)",
            part="PRF-MAC · CBC-MAC · HMAC stub · EUF-CMA · Length-Extension",
        )

    def deliverables(self) -> list[str]:
        return [
            "PRF-MAC: Mac_k(m) = F_k(m), Vrfy_k(m, t) — fixed-length, uses PA#2 GGM PRF",
            "CBC-MAC: chain F_k over PKCS-padded blocks — variable-length",
            "HMAC stub: raises NotImplementedError with formula reference (→ PA#10)",
            "MAC ⇒ PRF witness: PRF-MAC on random inputs passes PA#2 frequency test",
            "EUF-CMA game: ≥20 forgery attempts expect 0 successes",
            "Length-extension demo: naive H(k‖m) is forgeable without k",
            "Public Mac(k,m) / Mac_hex(k,m) / Vrfy(k,m,t) interface for PA#6",
        ]

    def run_demo(self) -> str:
        key = secrets.randbits(GGMPRF.SEED_BITS)
        msg_short = b"hello-mac"
        msg_long = b"variable-length-cbc-mac-demo"

        prf_tag = self.prf_mac.Mac_hex(
            key,
            int.from_bytes((msg_short + b"\x00" * BLOCK_BYTES)[:BLOCK_BYTES], "big"),
        )
        cbc_tag = self.cbc_mac.Mac_hex(key, msg_long)

        prf_vrfy = self.prf_mac.Vrfy(
            key,
            int.from_bytes((msg_short + b"\x00" * BLOCK_BYTES)[:BLOCK_BYTES], "big"),
            int(prf_tag, 16),
        )
        cbc_vrfy = self.cbc_mac.Vrfy(key, msg_long, int(cbc_tag, 16))

        # MAC ⇒ PRF witness
        witness = self.witness.run(queries=100)

        # EUF-CMA: generate 5 pairs, try a random forgery
        game = EUFCMAGame(mac_scheme="PRF-MAC")
        pairs = game.get_signed_pairs(5)
        new_msg = "forgery-attempt-999"
        random_tag = f"{secrets.randbits(64):016x}"
        forge_result = game.submit_forgery(new_msg, random_tag)

        # Length-extension demo
        demo_m = "secret-body"
        orig_tag = self.len_ext.naive_mac(demo_m)
        ext_result = self.len_ext.extend(demo_m, orig_tag, "appended-suffix")

        lines = [
            "PA05 demo active",
            "",
            "  ── Construction 1: PRF-MAC ──",
            f"  key     = {key:016x}",
            f"  msg     = {msg_short!r}",
            f"  tag     = {prf_tag}",
            f"  Vrfy    = {prf_vrfy}",
            "",
            "  ── Construction 2: CBC-MAC ──",
            f"  msg     = {msg_long!r}",
            f"  tag     = {cbc_tag}",
            f"  Vrfy    = {cbc_vrfy}",
            "",
            "  ── MAC ⇒ PRF Witness (100 queries) ──",
            f"  MAC 1-ratio  = {witness['mac_ones_ratio']:.5f}",
            f"  RNG 1-ratio  = {witness['random_ones_ratio']:.5f}",
            f"  |Δ|          = {witness['statistical_distance']:.6f}",
            f"  Verdict      = {witness['verdict']}",
            "",
            "  ── EUF-CMA Game ──",
            "  Signed pairs (first 5):",
        ]
        for p in pairs:
            lines.append(f"    [{p['msg']:12s}]  {p['tag']}")
        lines += [
            f"  Forgery attempt: msg={new_msg!r}  tag={random_tag}",
            f"  Result: {forge_result['reason']}",
            f"  Attempts={forge_result['attempts']}  Successes={forge_result['successes']}",
            "",
            "  ── Length-Extension Demo ──",
            f"  original msg  = {ext_result['original_msg_text']!r}",
            f"  original tag  = {ext_result['original_tag_hex']}",
            f"  glue padding  = {ext_result['glue_pad_hex']}",
            f"  suffix        = {ext_result['suffix_text']!r}",
            f"  extended tag  = {ext_result['extended_tag_hex']}",
            f"  Verified (no k needed): {ext_result['verified']}",
            f"  → {ext_result['explanation'][:80]}…",
            "",
            "  ── HMAC stub ──",
            "  hmac_stub(k, m) raises NotImplementedError (→ PA#10)",
        ]
        return "\n".join(lines)
