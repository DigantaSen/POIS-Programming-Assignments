from __future__ import annotations

import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa07 import MerkleDamgard


def _coerce_message(message: bytes | str) -> bytes:
    if isinstance(message, bytes):
        return message
    return message.encode("utf-8")


class DLPCompressionCRHF:
    """
    PA08 hash family: Merkle-Damgard with DLP-style compression.

    Compression template:
        h(z, M) = g^x * h_hat^y (mod p), then truncated to n bits.

    Toy parameters are intentionally small for interactive demos.
    """

    BLOCK_SIZE = 8
    DIGEST_SIZE = 4
    IV = b"\x00" * DIGEST_SIZE

    # Small toy safe prime p = 2q + 1.
    P = 2_147_483_647
    G = 5
    H_HAT = 7

    def __init__(self) -> None:
        self._md = MerkleDamgard(
            compress=self.compress,
            iv=self.IV,
            block_size=self.BLOCK_SIZE,
        )

    def compress(self, state: bytes, block: bytes) -> bytes:
        if len(state) != self.DIGEST_SIZE:
            raise ValueError("state must be 4 bytes")
        if len(block) != self.BLOCK_SIZE:
            raise ValueError("block must be 8 bytes")

        x = int.from_bytes(state, "big")
        y = int.from_bytes(block, "big")

        # DLP-style compression: h(z, M) = g^x * h_hat^y mod p.
        v = (pow(self.G, x, self.P) * pow(self.H_HAT, y, self.P)) % self.P
        return v.to_bytes(8, "big")[-self.DIGEST_SIZE :]

    def md_pad(self, message: bytes | str, prefix_len: int = 0) -> bytes:
        msg = _coerce_message(message)
        bit_len = (len(msg) + prefix_len) * 8
        padded = bytearray(msg)
        padded.append(0x80)
        while (len(padded) + 8) % self.BLOCK_SIZE != 0:
            padded.append(0x00)
        padded.extend(bit_len.to_bytes(8, "big"))
        return bytes(padded)

    def digest_padded(self, padded: bytes, initial_state: bytes | None = None) -> bytes:
        if len(padded) % self.BLOCK_SIZE != 0:
            raise ValueError("padded input length must be a multiple of block size")

        state = self.IV if initial_state is None else initial_state
        if len(state) != self.DIGEST_SIZE:
            raise ValueError("initial_state must be 4 bytes")

        for i in range(0, len(padded), self.BLOCK_SIZE):
            state = self.compress(state, padded[i : i + self.BLOCK_SIZE])
        return state

    def hash_bytes(self, message: bytes | str) -> bytes:
        return self._md.hash(message)

    def hash_hex(self, message: bytes | str) -> str:
        return self.hash_bytes(message).hex()

    def hash_nbits(self, message: bytes | str, n_bits: int) -> int:
        if n_bits <= 0 or n_bits > self.DIGEST_SIZE * 8:
            raise ValueError("n_bits must be in [1, 32]")
        full = int.from_bytes(self.hash_bytes(message), "big")
        return full & ((1 << n_bits) - 1)


class PA08(AssignmentModule):
    """PA08: CRHF from MD transform + DLP-style compression."""

    def __init__(self) -> None:
        self.crhf = DLPCompressionCRHF()

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA08",
            title="Collision-Resistant Hash via DLP Compression",
            part="Merkle-Damgard + DLP-style compression",
        )

    def deliverables(self) -> list[str]:
        return [
            "DLP-style compression h(z,M)=g^x * h_hat^y mod p (toy parameters)",
            "Merkle-Damgard domain extension via PA07 framework",
            "Truncated n-bit digest interface for birthday experiments",
            "State-resume helpers for PA10 length-extension demonstration",
            "Demo output with collision-resistance claim mapping to DLP hardness",
        ]

    def hash(self, message: bytes | str) -> bytes:
        return self.crhf.hash_bytes(message)

    def hash_hex(self, message: bytes | str) -> str:
        return self.crhf.hash_hex(message)

    def hash_nbits(self, message: bytes | str, n_bits: int) -> int:
        return self.crhf.hash_nbits(message, n_bits)

    def run_demo(self) -> str:
        m1 = b"PA08-message-one"
        m2 = b"PA08-message-two"
        m3 = secrets.token_bytes(12)

        d1 = self.hash_hex(m1)
        d2 = self.hash_hex(m2)
        d3 = self.hash_hex(m3)

        t16_1 = self.hash_nbits(m1, 16)
        t16_2 = self.hash_nbits(m2, 16)

        return "\n".join([
            "PA08 demo active",
            "",
            "  DLP compression parameters (toy):",
            f"    p={self.crhf.P}",
            f"    g={self.crhf.G}, h_hat={self.crhf.H_HAT}",
            f"    block_size={self.crhf.BLOCK_SIZE} bytes, digest_size={self.crhf.DIGEST_SIZE} bytes",
            "",
            "  Sample digests:",
            f"    H('PA08-message-one') = {d1}",
            f"    H('PA08-message-two') = {d2}",
            f"    H(random-12-bytes)   = {d3}",
            "",
            "  16-bit truncation examples (for PA09):",
            f"    H16(m1) = {t16_1:04x}",
            f"    H16(m2) = {t16_2:04x}",
            "",
            "  Security claim (informal):",
            "    Any efficient collision finder for this MD hash yields a collision",
            "    in the DLP-style compression function; under DLP hardness this is infeasible",
            "    for full-size outputs (toy truncations are intentionally breakable).",
        ])


