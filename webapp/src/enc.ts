/**
 * PA#3 — CPA-Secure Encryption (TypeScript, browser demo)
 *
 * Enc-then-PRF construction:
 *   Enc(k, m) = (r,  F_k(r) XOR m)    r fresh random nonce
 *   Dec(k, r, c) =   F_k(r) XOR c
 *
 * Multi-block (counter mode):
 *   block i → keystream = F_k( (r + i) mod 256 )  (8-bit nonce space)
 *
 * Parameters match pa03.py:
 *   - PRF_DEPTH = 8  (GGM tree depth = 8 bits → 256 leaves)
 *   - BLOCK_BYTES = 4  (lower 32 bits of PRF output)
 */

import { ggmEvaluate } from "./ggm";

const PRF_DEPTH = 8;
const BLOCK_BYTES = 4;
const MASK32 = 0xffff_ffffn;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Evaluate GGM PRF with an 8-bit nonce, return lower 32 bits. */
function prfBlock(keyHex: string, nonce: number): number {
  const bits = (nonce & 0xff).toString(2).padStart(PRF_DEPTH, "0");
  const out = ggmEvaluate(keyHex, bits);
  return Number(out & MASK32);
}

/** PKCS7 pad to BLOCK_BYTES boundary. */
function pkcs7Pad(data: Uint8Array): Uint8Array {
  const padLen = BLOCK_BYTES - (data.length % BLOCK_BYTES);
  const result = new Uint8Array(data.length + padLen);
  result.set(data);
  result.fill(padLen, data.length);
  return result;
}

/** Remove PKCS7 padding. */
function pkcs7Unpad(data: Uint8Array): Uint8Array {
  const padLen = data[data.length - 1];
  return data.slice(0, data.length - padLen);
}

/** Convert Uint8Array → hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Convert hex string → Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
  const h = hex.length % 2 ? "0" + hex : hex;
  return new Uint8Array((h.match(/../g) ?? []).map((b) => parseInt(b, 16)));
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

export interface Ciphertext {
  /** 8-bit nonce (0–255) */
  nonce: number;
  /** Raw ciphertext bytes as hex */
  ctHex: string;
}

/**
 * Enc(k, m):  encrypt UTF-8 plaintext → Ciphertext.
 *
 * @param keyHex   Hex string for the 64-bit GGM key.
 * @param plaintext  UTF-8 plaintext string.
 * @param fixedNonce  If set, use this nonce instead of random (broken-mode demo).
 */
export function encryptText(
  keyHex: string,
  plaintext: string,
  fixedNonce?: number,
): Ciphertext {
  const ptBytes = pkcs7Pad(new TextEncoder().encode(plaintext));
  const nBlocks = ptBytes.length / BLOCK_BYTES;

  const nonce =
    fixedNonce !== undefined
      ? fixedNonce & 0xff
      : crypto.getRandomValues(new Uint8Array(1))[0] & 0xff;

  const ct = new Uint8Array(ptBytes.length);
  const dv = new DataView(ct.buffer);
  for (let i = 0; i < nBlocks; i++) {
    const ks = prfBlock(keyHex, (nonce + i) % 256);
    const ptBlock = new DataView(ptBytes.buffer, i * BLOCK_BYTES, BLOCK_BYTES).getUint32(0);
    dv.setUint32(i * BLOCK_BYTES, ptBlock ^ ks);
  }

  return { nonce, ctHex: bytesToHex(ct) };
}

/**
 * Dec(k, r, c):  decrypt Ciphertext → UTF-8 plaintext.
 */
export function decryptText(
  keyHex: string,
  nonce: number,
  ctHex: string,
): string {
  const ctBytes = hexToBytes(ctHex);
  const nBlocks = ctBytes.length / BLOCK_BYTES;
  const pt = new Uint8Array(ctBytes.length);
  const ptDv = new DataView(pt.buffer);

  for (let i = 0; i < nBlocks; i++) {
    const ks = prfBlock(keyHex, (nonce + i) % 256);
    const ctBlock = new DataView(ctBytes.buffer, i * BLOCK_BYTES, BLOCK_BYTES).getUint32(0);
    ptDv.setUint32(i * BLOCK_BYTES, ctBlock ^ ks);
  }

  return new TextDecoder().decode(pkcs7Unpad(pt));
}

// ---------------------------------------------------------------------------
// Nonce-reuse XOR attack helper
// ---------------------------------------------------------------------------

/**
 * XOR two hex strings of equal length → hex result.
 * ct0 XOR ct1 = m0 XOR m1  (keystream cancels with nonce reuse).
 */
export function xorHex(hex0: string, hex1: string): string {
  const len = Math.min(hex0.length, hex1.length);
  let result = "";
  for (let i = 0; i < len - 1; i += 2) {
    const b = parseInt(hex0.slice(i, i + 2), 16) ^ parseInt(hex1.slice(i, i + 2), 16);
    result += b.toString(16).padStart(2, "0");
  }
  return result;
}

/** UTF-8 string → hex (for displaying XOR of two plaintexts). */
export function textToHex(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}
