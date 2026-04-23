from __future__ import annotations

from typing import Callable

from .base import AssignmentInfo, AssignmentModule

CompressionFn = Callable[[bytes, bytes], bytes]


def _coerce_message(message: bytes | str) -> bytes:
    if isinstance(message, bytes):
        return message
    return message.encode("utf-8")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class MerkleDamgard:
    """
    Generic Merkle-Damgard domain extension.

    Given a compression function h: {0,1}^{n+b} -> {0,1}^n,
    this class builds a hash for arbitrary-length messages using
    MD-strengthening padding.
    """

    def __init__(self, compress: CompressionFn, iv: bytes, block_size: int) -> None:
        if block_size <= 0:
            raise ValueError("block_size must be positive")
        if not iv:
            raise ValueError("iv must be non-empty")

        self.compress = compress
        self.iv = iv
        self.block_size = block_size
        self.state_size = len(iv)

    def md_strengthen_pad(self, message: bytes | str) -> bytes:
        msg = _coerce_message(message)
        bit_len = len(msg) * 8
        if bit_len >= (1 << 64):
            raise ValueError("message too long for 64-bit MD length field")

        padded = bytearray(msg)
        padded.append(0x80)
        while (len(padded) + 8) % self.block_size != 0:
            padded.append(0x00)
        padded.extend(bit_len.to_bytes(8, "big"))
        return bytes(padded)

    def _split_blocks(self, data: bytes) -> list[bytes]:
        return [data[i : i + self.block_size] for i in range(0, len(data), self.block_size)]

    def hash(self, message: bytes | str) -> bytes:
        padded = self.md_strengthen_pad(message)
        z = self.iv
        for block in self._split_blocks(padded):
            z_next = self.compress(z, block)
            if not isinstance(z_next, bytes) or len(z_next) != self.state_size:
                raise ValueError("compression function must return bytes of length n")
            z = z_next
        return z

    def trace(self, message: bytes | str) -> dict[str, object]:
        msg = _coerce_message(message)
        padded = self.md_strengthen_pad(msg)
        blocks = self._split_blocks(padded)

        chain = [self.iv]
        z = self.iv
        for block in blocks:
            z = self.compress(z, block)
            chain.append(z)

        return {
            "message_hex": msg.hex(),
            "padded_hex": padded.hex(),
            "blocks_hex": [blk.hex() for blk in blocks],
            "chain_hex": [v.hex() for v in chain],
            "digest_hex": chain[-1].hex(),
        }


def toy_xor_compression(state: bytes, block: bytes) -> bytes:
    """
    Toy compression h: {0,1}^{n+b} -> {0,1}^n for PA07 testing.

    Toy parameters:
      n = 4 bytes (state/digest)
      b = 8 bytes (block)

    h(z, M) = z XOR M_left XOR M_right
    """
    if len(state) != 4:
        raise ValueError("toy compression expects 4-byte state")
    if len(block) != 8:
        raise ValueError("toy compression expects 8-byte block")

    left = block[:4]
    right = block[4:]
    return _xor_bytes(_xor_bytes(state, left), right)


def hash(message: bytes | str, compression_fn: CompressionFn) -> bytes:
    """Required PA07 interface: hash(message, compression_fn) -> digest."""
    md = MerkleDamgard(compress=compression_fn, iv=b"\x00" * 4, block_size=8)
    return md.hash(message)


class PA07(AssignmentModule):
    BLOCK_SIZE = 8
    DIGEST_SIZE = 4
    IV = b"\x00" * DIGEST_SIZE

    def __init__(self) -> None:
        self.md = MerkleDamgard(
            compress=toy_xor_compression,
            iv=self.IV,
            block_size=self.BLOCK_SIZE,
        )

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA07",
            title="Merkle-Damgard Transform",
            part="Domain extension with MD strengthening",
        )

    def deliverables(self) -> list[str]:
        return [
            "Generic MerkleDamgard(compress, IV, block_size) framework",
            "Correct MD-strengthening padding with 64-bit big-endian length",
            "Toy XOR compression plug-in with n=4 bytes, b=8 bytes",
            "Collision propagation demo from compression collision to MD collision",
            "Public hash(message, compression_fn) interface for PA08",
        ]

    def hash(
        self,
        message: bytes | str,
        compression_fn: CompressionFn | None = None,
    ) -> bytes:
        if compression_fn is None:
            return self.md.hash(message)
        return MerkleDamgard(
            compress=compression_fn,
            iv=self.IV,
            block_size=self.BLOCK_SIZE,
        ).hash(message)

    def _collision_pair_for_toy_compression(self) -> tuple[bytes, bytes, bytes]:
        # m1 and m2 differ but satisfy h(IV, m1) == h(IV, m2).
        m1_left = bytes.fromhex("00112233")
        m1_right = bytes.fromhex("44556677")
        delta = bytes.fromhex("deadbeef")

        m2_left = _xor_bytes(m1_left, delta)
        m2_right = _xor_bytes(m1_right, delta)

        m1 = m1_left + m1_right
        m2 = m2_left + m2_right

        c = toy_xor_compression(self.IV, m1)
        return m1, m2, c

    def run_demo(self) -> str:
        empty = b""
        one_block = b"ABCDEFGH"
        multi_block = b"POIS-PA07-MERKLE-DAMGARD"

        d_empty = self.hash(empty)
        d_one = self.hash(one_block)
        d_multi = self.hash(multi_block)

        t_empty = self.md.trace(empty)
        t_one = self.md.trace(one_block)
        t_multi = self.md.trace(multi_block)

        m1, m2, comp_collision = self._collision_pair_for_toy_compression()
        h1 = self.hash(m1)
        h2 = self.hash(m2)

        return "\n".join([
            "PA07 demo active",
            "",
            "  Toy parameters:",
            f"    block_size = {self.BLOCK_SIZE} bytes",
            f"    digest_size = {self.DIGEST_SIZE} bytes",
            f"    iv = {self.IV.hex()}",
            "",
            "  Boundary checks:",
            f"    empty message digest      = {d_empty.hex()} (len={len(d_empty)})",
            f"    one-block message digest  = {d_one.hex()} (len={len(d_one)})",
            f"    multi-block message digest= {d_multi.hex()} (len={len(d_multi)})",
            f"    padded blocks (empty/one/multi) = "
            f"{len(t_empty['blocks_hex'])}/{len(t_one['blocks_hex'])}/{len(t_multi['blocks_hex'])}",
            "",
            "  MD-strengthening sanity:",
            f"    empty length field (64-bit BE) = {t_empty['blocks_hex'][-1][-16:]}",
            f"    one-block length field          = {t_one['blocks_hex'][-1][-16:]}",
            "",
            "  Collision propagation demo:",
            f"    m1 = {m1.hex()}",
            f"    m2 = {m2.hex()}",
            f"    m1 != m2: {m1 != m2}",
            f"    h_toy(IV, m1) = h_toy(IV, m2) = {comp_collision.hex()}",
            f"    H_MD(m1) = {h1.hex()}",
            f"    H_MD(m2) = {h2.hex()}",
            f"    collision propagated: {h1 == h2}",
            "",
            "  PA08 plug-in interface:",
            "    hash(message, compression_fn) -> digest",
        ])
