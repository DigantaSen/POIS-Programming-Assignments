/**
 * PA#6 — CCA-Secure Encryption: Encrypt-then-MAC (TypeScript, browser demo)
 *
 * Construction:
 *   CCA_Enc(kE, kM, m):
 *     1. (r, ct) = CPA_Enc(kE, m)          [PA#3 stream cipher]
 *     2. tagInput = [0x00, r_byte, ...ct]   [domain-separated binding]
 *     3. t = CBC-MAC_kM(tagInput)           [PA#5 variable-length MAC]
 *     4. return { nonce: r, ctHex, tagHex }
 *
 *   CCA_Dec(kE, kM, nonce, ctHex, tagHex):
 *     1. tagInput = [0x00, r_byte, ...ct]
 *     2. if !CBC-MAC_kM.Vrfy(tagInput, t) → return null (⊥)
 *     3. return CPA_Dec(kE, nonce, ctHex)
 *
 * Key separation:
 *   kE and kM are always independently sampled 8-byte hex strings.
 *   Using the same key for both creates exploitable correlations (see demo).
 *
 * Matches pa06.py exactly.
 */

import { encryptText, decryptText, hexToBytes, bytesToHex } from "./enc";
import { cbcMacTag, cbcMacVerify } from "./mac";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CCAResult {
  /** 8-bit nonce used for the CPA layer */
  nonce: number;
  /** CPA ciphertext hex (body only, without nonce) */
  ctHex: string;
  /** CBC-MAC tag hex (16 chars) over (0x00 || nonce_byte || ct_bytes) */
  tagHex: string;
}

// ---------------------------------------------------------------------------
// Internal: MAC input binding
// ---------------------------------------------------------------------------

/**
 * Build the MAC input: 0x00 || nonce_byte || ct_bytes.
 *
 * The leading 0x00 domain-separates this from other PA#5 MAC uses so that
 * the same kM key cannot be repurposed across different scheme contexts.
 */
function buildMacInput(nonce: number, ctHex: string): Uint8Array {
  const ctBytes = hexToBytes(ctHex);
  const buf = new Uint8Array(2 + ctBytes.length);
  buf[0] = 0x00; // domain separator
  buf[1] = nonce & 0xff;
  buf.set(ctBytes, 2);
  return buf;
}

/** Convert Uint8Array to the UTF-8-like string the MAC functions use internally. */
function macInputToText(buf: Uint8Array): string {
  // cbcMacTag expects a UTF-8 string; we encode the raw bytes as Latin-1
  // (each byte → its Unicode code point), which is lossless for 0x00–0xFF.
  return String.fromCharCode(...buf);
}

// ---------------------------------------------------------------------------
// CCA_Enc / CCA_Dec
// ---------------------------------------------------------------------------

/**
 * CCA_Enc(kEHex, kMHex, plaintext) → CCAResult.
 *
 * @param kEHex    16-hex-char encryption key (64-bit).
 * @param kMHex    16-hex-char MAC key (64-bit, independently sampled).
 * @param plaintext UTF-8 plaintext string.
 */
export function ccaEncrypt(
  kEHex: string,
  kMHex: string,
  plaintext: string,
): CCAResult {
  // Step 1: CPA encryption (PA#3)
  const { nonce, ctHex } = encryptText(kEHex, plaintext);

  // Step 2: Compute MAC over bound input
  const macInputBytes = buildMacInput(nonce, ctHex);
  const macInputStr = macInputToText(macInputBytes);
  const tagHex = cbcMacTag(kMHex, macInputStr);

  return { nonce, ctHex, tagHex };
}

/**
 * CCA_Dec(kEHex, kMHex, nonce, ctHex, tagHex) → plaintext string | null (⊥).
 *
 * Calls Vrfy BEFORE Dec.  Returns null on MAC failure without touching
 * the ciphertext — this is the CCA2-security gate.
 *
 * @param kEHex   16-hex-char encryption key.
 * @param kMHex   16-hex-char MAC key.
 * @param nonce   8-bit nonce from CCA_Enc.
 * @param ctHex   Ciphertext hex from CCA_Enc.
 * @param tagHex  MAC tag hex (16 chars) from CCA_Enc.
 * @returns Decrypted plaintext or null (⊥) on verification failure.
 */
export function ccaDecrypt(
  kEHex: string,
  kMHex: string,
  nonce: number,
  ctHex: string,
  tagHex: string,
): string | null {
  // Step 1: Vrfy — reject tampered ciphertexts immediately
  const macInputBytes = buildMacInput(nonce, ctHex);
  const macInputStr = macInputToText(macInputBytes);

  if (!cbcMacVerify(kMHex, macInputStr, tagHex)) {
    return null; // ⊥
  }

  // Step 2: Decrypt only on valid MAC
  return decryptText(kEHex, nonce, ctHex);
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/** Generate two independently sampled 16-hex-char keys (kE ≠ kM). */
export function generateKeyPair(): { kEHex: string; kMHex: string } {
  const randomKey = () =>
    bytesToHex(crypto.getRandomValues(new Uint8Array(8)));

  let kEHex = randomKey();
  let kMHex = randomKey();
  while (kMHex === kEHex) {
    kMHex = randomKey();
  }
  return { kEHex, kMHex };
}

// ---------------------------------------------------------------------------
// Bit-flip helper (malleability demo)
// ---------------------------------------------------------------------------

/**
 * Flip bit `bitIndex` (0 = MSB of first byte) in a hex ciphertext.
 *
 * @param ctHex    Hex string of the ciphertext body.
 * @param bitIndex 0-indexed bit position, MSB-first within each byte.
 * @returns Modified hex string with exactly one bit flipped.
 */
export function flipBit(ctHex: string, bitIndex: number): string {
  const bytes = hexToBytes(ctHex);
  const byteIdx = Math.floor(bitIndex / 8);
  const bitInByte = 7 - (bitIndex % 8); // MSB-first within byte
  if (byteIdx < bytes.length) {
    bytes[byteIdx] ^= 1 << bitInByte;
  }
  return bytesToHex(bytes);
}

/**
 * Flip multiple bits in a hex ciphertext.
 *
 * @param ctHex      Hex string of the ciphertext body.
 * @param bitIndices Array of 0-indexed bit positions to flip.
 * @returns Modified hex string with the specified bits flipped.
 */
export function flipBits(ctHex: string, bitIndices: number[]): string {
  const bytes = hexToBytes(ctHex);
  for (const bitIndex of bitIndices) {
    const byteIdx = Math.floor(bitIndex / 8);
    const bitInByte = 7 - (bitIndex % 8);
    if (byteIdx < bytes.length) {
      bytes[byteIdx] ^= 1 << bitInByte;
    }
  }
  return bytesToHex(bytes);
}

// ---------------------------------------------------------------------------
// IND-CCA2 game simulation (browser-side)
// ---------------------------------------------------------------------------

export interface CCA2RoundResult {
  correct: boolean;
  b: number;
  bPrime: number;
  rounds: number;
  wins: number;
  advantage: number;
}

export interface CCA2GameState {
  kEHex: string;
  kMHex: string;
  challengeResult: CCAResult | null;
  b: number | null;
  rounds: number;
  wins: number;
}

/** Create a fresh IND-CCA2 game state. */
export function newCCA2Game(): CCA2GameState {
  const { kEHex, kMHex } = generateKeyPair();
  return {
    kEHex,
    kMHex,
    challengeResult: null,
    b: null,
    rounds: 0,
    wins: 0,
  };
}

/**
 * Encryption oracle: Enc_oracle(m) → CCAResult.
 * Adversary can call this as many times as they want before/after the challenge.
 */
export function encOracle(game: CCA2GameState, plaintext: string): CCAResult {
  return ccaEncrypt(game.kEHex, game.kMHex, plaintext);
}

/**
 * Decryption oracle: Dec_oracle(nonce, ctHex, tagHex) → string | null.
 * Automatically rejects the challenge ciphertext.
 */
export function decOracle(
  game: CCA2GameState,
  nonce: number,
  ctHex: string,
  tagHex: string,
): string | null {
  // Block queries on the challenge ciphertext
  if (game.challengeResult) {
    const ch = game.challengeResult;
    if (nonce === ch.nonce && ctHex === ch.ctHex && tagHex === ch.tagHex) {
      return null; // ⊥ — challenge ciphertext rejected
    }
  }
  return ccaDecrypt(game.kEHex, game.kMHex, nonce, ctHex, tagHex);
}

/**
 * Issue the challenge: challenger picks b ∈ {0,1}, returns CCA_Enc(m_b).
 *
 * @param game The current game state (mutated in-place).
 * @param m0   Message 0 (must equal |m1|).
 * @param m1   Message 1.
 */
export function issueChallenge(
  game: CCA2GameState,
  m0: string,
  m1: string,
): CCAResult {
  game.b = crypto.getRandomValues(new Uint8Array(1))[0] & 1;
  const chosen = game.b === 0 ? m0 : m1;
  game.challengeResult = ccaEncrypt(game.kEHex, game.kMHex, chosen);
  return game.challengeResult;
}

/**
 * Submit adversary's guess b′.
 *
 * @param game    Game state.
 * @param bPrime  Adversary's guess (0 or 1).
 * @returns Round result with updated advantage.
 */
export function submitGuess(
  game: CCA2GameState,
  bPrime: number,
): CCA2RoundResult {
  game.rounds++;
  const correct = bPrime === game.b;
  if (correct) game.wins++;
  const advantage = 2 * Math.abs(game.wins / game.rounds - 0.5);
  return {
    correct,
    b: game.b ?? 0,
    bPrime,
    rounds: game.rounds,
    wins: game.wins,
    advantage: Math.round(advantage * 10000) / 10000,
  };
}
