from __future__ import annotations

import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa01 import _to_int
from .pa02 import GGMPRF


ModePayload = dict[str, str]


def _to_bytes(msg: bytes | str) -> bytes:
    return msg if isinstance(msg, bytes) else msg.encode("utf-8")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class ToyPRP32:
    """
    Tiny 32-bit PRP built via a Feistel network with PA02's PRF as round function.

    This gives us both E_k and D_k needed by CBC while keeping the implementation
    self-contained and fast for assignment demos.
    """

    BLOCK_BYTES = 4
    HALF_BITS = 16
    ROUNDS = 6

    def __init__(self) -> None:
        self._prf = GGMPRF()

    def _round_f(self, key: int, round_idx: int, right_half: int) -> int:
        query = ((round_idx & 0xFF) << self.HALF_BITS) | (right_half & 0xFFFF)
        return self._prf.F(key, query) & 0xFFFF

    def encrypt_block(self, key: int | bytes | str, block: bytes) -> bytes:
        if len(block) != self.BLOCK_BYTES:
            raise ValueError("encrypt_block expects a 4-byte block")

        k = _to_int(key) & ((1 << GGMPRF.SEED_BITS) - 1)
        x = int.from_bytes(block, "big")
        left = (x >> self.HALF_BITS) & 0xFFFF
        right = x & 0xFFFF

        for r in range(self.ROUNDS):
            left, right = right, left ^ self._round_f(k, r, right)

        y = ((left & 0xFFFF) << self.HALF_BITS) | (right & 0xFFFF)
        return y.to_bytes(self.BLOCK_BYTES, "big")

    def decrypt_block(self, key: int | bytes | str, block: bytes) -> bytes:
        if len(block) != self.BLOCK_BYTES:
            raise ValueError("decrypt_block expects a 4-byte block")

        k = _to_int(key) & ((1 << GGMPRF.SEED_BITS) - 1)
        y = int.from_bytes(block, "big")
        left = (y >> self.HALF_BITS) & 0xFFFF
        right = y & 0xFFFF

        for r in range(self.ROUNDS - 1, -1, -1):
            left, right = right ^ self._round_f(k, r, left), left

        x = ((left & 0xFFFF) << self.HALF_BITS) | (right & 0xFFFF)
        return x.to_bytes(self.BLOCK_BYTES, "big")


class ModesOfOperation:
    MODES = {"CBC", "OFB", "CTR"}

    def __init__(self, prp: ToyPRP32 | None = None) -> None:
        self.prp = prp or ToyPRP32()
        self.block_bytes = self.prp.BLOCK_BYTES
        self.block_mask = (1 << (8 * self.block_bytes)) - 1

    def _pad(self, data: bytes) -> bytes:
        pad_len = self.block_bytes - (len(data) % self.block_bytes)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("Invalid padded data")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.block_bytes:
            raise ValueError("Invalid PKCS7 padding")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid PKCS7 padding bytes")
        return data[:-pad_len]

    def _iter_chunks(self, data: bytes) -> list[bytes]:
        return [data[i : i + self.block_bytes] for i in range(0, len(data), self.block_bytes)]

    def cbc_encrypt(
        self,
        key: int | bytes | str,
        plaintext: bytes,
        iv: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        iv_bytes = iv if iv is not None else secrets.token_bytes(self.block_bytes)
        if len(iv_bytes) != self.block_bytes:
            raise ValueError("CBC IV must be one block")

        prev = iv_bytes
        out = bytearray()
        for block in self._iter_chunks(self._pad(plaintext)):
            mixed = _xor_bytes(block, prev)
            c = self.prp.encrypt_block(key, mixed)
            out.extend(c)
            prev = c
        return iv_bytes, bytes(out)

    def cbc_decrypt(self, key: int | bytes | str, iv: bytes, ciphertext: bytes) -> bytes:
        if len(iv) != self.block_bytes:
            raise ValueError("CBC IV must be one block")
        if len(ciphertext) % self.block_bytes != 0:
            raise ValueError("CBC ciphertext length must be multiple of block size")

        prev = iv
        out = bytearray()
        for c in self._iter_chunks(ciphertext):
            x = self.prp.decrypt_block(key, c)
            p = _xor_bytes(x, prev)
            out.extend(p)
            prev = c
        return self._unpad(bytes(out))

    def ofb_crypt(
        self,
        key: int | bytes | str,
        data: bytes,
        iv: bytes,
    ) -> bytes:
        if len(iv) != self.block_bytes:
            raise ValueError("OFB IV must be one block")

        state = iv
        out = bytearray()
        for chunk in self._iter_chunks(data):
            state = self.prp.encrypt_block(key, state)
            out.extend(_xor_bytes(chunk, state[: len(chunk)]))
        return bytes(out)

    def ofb_encrypt(
        self,
        key: int | bytes | str,
        plaintext: bytes,
        iv: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        iv_bytes = iv if iv is not None else secrets.token_bytes(self.block_bytes)
        return iv_bytes, self.ofb_crypt(key, plaintext, iv_bytes)

    def ofb_decrypt(self, key: int | bytes | str, iv: bytes, ciphertext: bytes) -> bytes:
        return self.ofb_crypt(key, ciphertext, iv)

    def ctr_crypt(self, key: int | bytes | str, data: bytes, nonce: bytes) -> bytes:
        if len(nonce) != self.block_bytes:
            raise ValueError("CTR nonce must be one block")

        n0 = int.from_bytes(nonce, "big")
        out = bytearray()
        for i, chunk in enumerate(self._iter_chunks(data)):
            counter = (n0 + i) & self.block_mask
            ks = self.prp.encrypt_block(key, counter.to_bytes(self.block_bytes, "big"))
            out.extend(_xor_bytes(chunk, ks[: len(chunk)]))
        return bytes(out)

    def ctr_encrypt(
        self,
        key: int | bytes | str,
        plaintext: bytes,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        nonce_bytes = nonce if nonce is not None else secrets.token_bytes(self.block_bytes)
        return nonce_bytes, self.ctr_crypt(key, plaintext, nonce_bytes)

    def ctr_decrypt(self, key: int | bytes | str, nonce: bytes, ciphertext: bytes) -> bytes:
        return self.ctr_crypt(key, ciphertext, nonce)

    def ctr_keystream_blocks(
        self,
        key: int | bytes | str,
        nonce: bytes,
        n_blocks: int,
    ) -> list[str]:
        n0 = int.from_bytes(nonce, "big")
        return [
            self.prp.encrypt_block(
                key,
                ((n0 + i) & self.block_mask).to_bytes(self.block_bytes, "big"),
            ).hex()
            for i in range(n_blocks)
        ]

    def Encrypt(self, mode: str, key: int | bytes | str, message: bytes | str) -> ModePayload:
        m = _to_bytes(message)
        mode_u = mode.upper()
        if mode_u not in self.MODES:
            raise ValueError(f"Unsupported mode: {mode}")

        if mode_u == "CBC":
            iv, ct = self.cbc_encrypt(key, m)
            return {"mode": "CBC", "iv": iv.hex(), "ct": ct.hex()}
        if mode_u == "OFB":
            iv, ct = self.ofb_encrypt(key, m)
            return {"mode": "OFB", "iv": iv.hex(), "ct": ct.hex()}

        nonce, ct = self.ctr_encrypt(key, m)
        return {"mode": "CTR", "nonce": nonce.hex(), "ct": ct.hex()}

    def Decrypt(self, mode: str, key: int | bytes | str, payload: ModePayload) -> bytes:
        mode_u = mode.upper()
        if mode_u not in self.MODES:
            raise ValueError(f"Unsupported mode: {mode}")

        ct = bytes.fromhex(payload["ct"])
        if mode_u == "CBC":
            return self.cbc_decrypt(key, bytes.fromhex(payload["iv"]), ct)
        if mode_u == "OFB":
            return self.ofb_decrypt(key, bytes.fromhex(payload["iv"]), ct)
        return self.ctr_decrypt(key, bytes.fromhex(payload["nonce"]), ct)


class PA04(AssignmentModule):
    def __init__(self) -> None:
        self.modes = ModesOfOperation()

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA04",
            title="Modes of Operation",
            part="CBC, OFB, and randomized CTR",
        )

    def deliverables(self) -> list[str]:
        return [
            "CBC Enc/Dec with random IV and PKCS7 padding",
            "OFB Enc/Dec (identical operation) with pre-computable keystream",
            "Randomized CTR Enc/Dec with nonce and parallel keystream blocks",
            "Unified Encrypt(mode,k,M) / Decrypt(mode,k,C) routing API",
            "CBC IV-reuse and OFB keystream-reuse attack demonstrations",
            "Correctness checks for short, one-block, and multi-block messages",
        ]

    def _correctness_tests(self, key: int) -> list[tuple[str, bool]]:
        tests = {
            "short": b"abc",
            "one_block": b"ABCD",
            "multi_block": b"modes-of-operation-demo",
        }
        results: list[tuple[str, bool]] = []

        for mode in ("CBC", "OFB", "CTR"):
            ok_all = True
            for msg in tests.values():
                payload = self.modes.Encrypt(mode, key, msg)
                recovered = self.modes.Decrypt(mode, key, payload)
                ok_all = ok_all and (recovered == msg)
            results.append((mode, ok_all))
        return results

    def _cbc_iv_reuse_demo(self, key: int) -> dict[str, object]:
        iv = secrets.token_bytes(self.modes.block_bytes)

        # Same first plaintext block leaks under IV reuse (C1 matches).
        m1 = b"HEADAAAA_tail_one"
        m2 = b"HEADAAAA_tail_two"

        _, c1 = self.modes.cbc_encrypt(key, m1, iv=iv)
        _, c2 = self.modes.cbc_encrypt(key, m2, iv=iv)
        b = self.modes.block_bytes
        return {
            "iv": iv.hex(),
            "c1_block1": c1[:b].hex(),
            "c2_block1": c2[:b].hex(),
            "leak_detected": c1[:b] == c2[:b],
        }

    def _ofb_reuse_demo(self, key: int) -> dict[str, object]:
        iv = secrets.token_bytes(self.modes.block_bytes)
        m1 = b"ofb-message-one"
        m2 = b"ofb-message-two"

        _, c1 = self.modes.ofb_encrypt(key, m1, iv=iv)
        _, c2 = self.modes.ofb_encrypt(key, m2, iv=iv)

        l = min(len(c1), len(c2), len(m1), len(m2))
        cx = _xor_bytes(c1[:l], c2[:l])
        mx = _xor_bytes(m1[:l], m2[:l])
        return {
            "iv": iv.hex(),
            "ct_xor": cx.hex(),
            "pt_xor": mx.hex(),
            "attack_succeeds": cx == mx,
        }

    def _ofb_precompute_demo(self, key: int) -> bool:
        iv = secrets.token_bytes(self.modes.block_bytes)
        msg = b"precompute-ofb-stream"
        blocks = self.modes._iter_chunks(msg)

        # Precompute keystream before seeing plaintext.
        state = iv
        keystream: list[bytes] = []
        for _ in blocks:
            state = self.modes.prp.encrypt_block(key, state)
            keystream.append(state)

        ct_manual = b"".join(
            _xor_bytes(blocks[i], keystream[i][: len(blocks[i])]) for i in range(len(blocks))
        )
        _, ct_api = self.modes.ofb_encrypt(key, msg, iv=iv)
        return ct_manual == ct_api

    def _ctr_parallel_demo(self, key: int) -> dict[str, object]:
        msg = b"ctr-parallel-block-demo"
        nonce, ct = self.modes.ctr_encrypt(key, msg)
        n_blocks = len(self.modes._iter_chunks(msg))
        ks = self.modes.ctr_keystream_blocks(key, nonce, n_blocks)

        return {
            "nonce": nonce.hex(),
            "n_blocks": n_blocks,
            "keystream_blocks": ks,
            "ct_hex": ct.hex(),
            "roundtrip_ok": self.modes.ctr_decrypt(key, nonce, ct) == msg,
        }

    def run_demo(self) -> str:
        key = secrets.randbits(GGMPRF.SEED_BITS)

        correctness = self._correctness_tests(key)
        cbc_attack = self._cbc_iv_reuse_demo(key)
        ofb_attack = self._ofb_reuse_demo(key)
        ofb_precompute_ok = self._ofb_precompute_demo(key)
        ctr_parallel = self._ctr_parallel_demo(key)

        lines = [
            "PA04 demo active",
            "",
            "  Correctness checks (Dec(k, Enc(k, M)) = M):",
        ]
        for mode, ok in correctness:
            lines.append(f"    {mode}: {ok}")

        lines += [
            "",
            "  CBC IV-reuse leakage demo:",
            f"    iv            = {cbc_attack['iv']}",
            f"    C1(msg1)      = {cbc_attack['c1_block1']}",
            f"    C1(msg2)      = {cbc_attack['c2_block1']}",
            f"    block leak    = {cbc_attack['leak_detected']}",
            "",
            "  OFB keystream-reuse attack demo:",
            f"    iv            = {ofb_attack['iv']}",
            f"    ct1 XOR ct2   = {ofb_attack['ct_xor']}",
            f"    m1  XOR m2    = {ofb_attack['pt_xor']}",
            f"    attack works  = {ofb_attack['attack_succeeds']}",
            "",
            "  OFB pre-computable keystream:",
            f"    manual_stream_matches_encrypt = {ofb_precompute_ok}",
            "",
            "  CTR parallelization demo:",
            f"    nonce         = {ctr_parallel['nonce']}",
            f"    blocks        = {ctr_parallel['n_blocks']}",
            f"    ks[0..]       = {', '.join(ctr_parallel['keystream_blocks'])}",
            f"    roundtrip_ok  = {ctr_parallel['roundtrip_ok']}",
            "",
            "  Unified API:",
            "    Encrypt(mode, k, M) and Decrypt(mode, k, payload)",
        ]
        return "\n".join(lines)
