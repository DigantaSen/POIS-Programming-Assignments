from __future__ import annotations

from hmac import compare_digest
import secrets

from .base import AssignmentInfo, AssignmentModule
from .pa03 import CPAEncryption
from .pa08 import PA08


def _coerce_message(message: bytes | str) -> bytes:
    if isinstance(message, bytes):
        return message
    return message.encode("utf-8")


class HMACPA08:
    """HMAC over the PA08 hash implementation."""

    BLOCK_BYTES = 8
    IPAD_BYTE = 0x36
    OPAD_BYTE = 0x5C

    def __init__(self, pa08: PA08) -> None:
        self.pa08 = pa08

    def _normalize_key(self, key: bytes) -> bytes:
        k = key
        if len(k) > self.BLOCK_BYTES:
            k = self.pa08.hash(k)
        if len(k) < self.BLOCK_BYTES:
            k = k + b"\x00" * (self.BLOCK_BYTES - len(k))
        return k

    def tag(self, key: bytes, message: bytes | str) -> bytes:
        msg = _coerce_message(message)
        k0 = self._normalize_key(key)
        ipad = bytes([self.IPAD_BYTE] * self.BLOCK_BYTES)
        opad = bytes([self.OPAD_BYTE] * self.BLOCK_BYTES)

        inner = self.pa08.hash(bytes(a ^ b for a, b in zip(k0, ipad)) + msg)
        return self.pa08.hash(bytes(a ^ b for a, b in zip(k0, opad)) + inner)

    def verify(self, key: bytes, message: bytes | str, tag: bytes) -> bool:
        expected = self.tag(key, message)
        return compare_digest(expected, tag)


class NaiveHashMAC:
    """Vulnerable MAC: Tag = H(k || m)."""

    def __init__(self, pa08: PA08) -> None:
        self.pa08 = pa08

    def tag(self, key: bytes, message: bytes | str) -> bytes:
        msg = _coerce_message(message)
        return self.pa08.hash(key + msg)

    def verify(self, key: bytes, message: bytes | str, tag: bytes) -> bool:
        return compare_digest(self.tag(key, message), tag)


class LengthExtensionAttack:
    """Length-extension attack on naive H(k||m) using PA08 internals."""

    def __init__(self, pa08: PA08) -> None:
        self.pa08 = pa08

    def forge(
        self,
        original_message: bytes,
        original_tag: bytes,
        append_data: bytes,
        key_len: int,
    ) -> dict[str, object]:
        # Glue padding for hidden prefix (k || m).
        glue = self.pa08.crhf.md_pad(b"\x00" * key_len + original_message)[key_len + len(original_message) :]

        # Resume from original chaining state for the appended suffix.
        prefix_len = key_len + len(original_message) + len(glue)
        suffix_padded = self.pa08.crhf.md_pad(append_data, prefix_len=prefix_len)
        forged_tag = self.pa08.crhf.digest_padded(suffix_padded, initial_state=original_tag)

        return {
            "forged_message": original_message + glue + append_data,
            "forged_tag": forged_tag,
            "glue_padding": glue,
        }


class EncryptThenHMAC:
    """CCA-style Encrypt-then-HMAC wrapper around PA03 encryption."""

    def __init__(self, pa08: PA08) -> None:
        self.enc = CPAEncryption()
        self.hmac = HMACPA08(pa08)

    def _aad(self, nonce: int, ciphertext: bytes) -> bytes:
        return bytes([nonce & 0xFF]) + ciphertext

    def enc_then_mac(self, k_enc: int, k_mac: bytes, message: bytes | str) -> tuple[tuple[int, bytes], bytes]:
        msg = _coerce_message(message)
        nonce, ciphertext = self.enc.encrypt(k_enc, msg)
        tag = self.hmac.tag(k_mac, self._aad(nonce, ciphertext))
        return (nonce, ciphertext), tag

    def dec_then_verify(self, k_enc: int, k_mac: bytes, c: tuple[int, bytes], t: bytes) -> bytes | None:
        nonce, ciphertext = c
        if not self.hmac.verify(k_mac, self._aad(nonce, ciphertext), t):
            return None
        return self.enc.decrypt(k_enc, nonce, ciphertext)


class PA10(AssignmentModule):
    """PA10: HMAC and Encrypt-then-HMAC."""

    def __init__(self) -> None:
        self.pa08 = PA08()
        self.hmac = HMACPA08(self.pa08)
        self.naive = NaiveHashMAC(self.pa08)
        self.ext = LengthExtensionAttack(self.pa08)
        self.etm = EncryptThenHMAC(self.pa08)

    def info(self) -> AssignmentInfo:
        return AssignmentInfo(
            task_id="PA10",
            title="HMAC and HMAC-Based CCA Encryption",
            part="CRHF to MAC and Encrypt-then-HMAC",
        )

    def deliverables(self) -> list[str]:
        return [
            "HMAC over PA08 hash: H((k xor opad) || H((k xor ipad) || m))",
            "Constant-time tag comparison in verifier",
            "Length-extension break of naive H(k || m)",
            "Demonstration that HMAC resists the same extension attempt",
            "Encrypt-then-HMAC CCA wrapper over PA03 encryption",
        ]

    def run_demo(self) -> str:
        key_mac = secrets.token_bytes(8)
        key_enc = secrets.randbits(64)

        m = b"amount=100&to=bob"
        suffix = b"&admin=true"

        # Naive vulnerable MAC.
        naive_tag = self.naive.tag(key_mac, m)
        forged = self.ext.forge(m, naive_tag, suffix, key_len=len(key_mac))
        naive_valid = self.naive.verify(key_mac, forged["forged_message"], forged["forged_tag"])

        # HMAC robust against extension.
        h_tag = self.hmac.tag(key_mac, m)
        hmac_forged_valid = self.hmac.verify(key_mac, forged["forged_message"], forged["forged_tag"])

        # Encrypt-then-HMAC CCA-style check.
        c, t = self.etm.enc_then_mac(key_enc, key_mac, b"transfer=42")
        dec_ok = self.etm.dec_then_verify(key_enc, key_mac, c, t)

        tampered_ct = bytearray(c[1])
        tampered_ct[0] ^= 0x01
        dec_tampered = self.etm.dec_then_verify(key_enc, key_mac, (c[0], bytes(tampered_ct)), t)

        return "\n".join([
            "PA10 demo active",
            "",
            "  HMAC construction:",
            "    tag = H((k xor opad) || H((k xor ipad) || m))",
            f"    sample HMAC tag = {h_tag.hex()}",
            "",
            "  Length-extension attack on naive H(k||m):",
            f"    original tag = {naive_tag.hex()}",
            f"    forged tag   = {forged['forged_tag'].hex()}",
            f"    forged message valid under naive MAC: {naive_valid}",
            f"    same forgery valid under HMAC: {hmac_forged_valid}",
            "",
            "  Encrypt-then-HMAC (CCA style):",
            f"    decrypt(valid)   -> {dec_ok!r}",
            f"    decrypt(tampered)-> {dec_tampered!r} (expected None/⊥)",
        ])


