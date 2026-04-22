/**
 * PA#5 — Message Authentication Codes (MACs)
 *
 * Implements:
 *   1. PRF-MAC (fixed-length): tag = F_k(m) using GGM PRF from PA#2
 *   2. CBC-MAC (variable-length): chain F_k over 8-byte PKCS-padded blocks
 *   3. Toy Merkle-Damgård hash for length-extension demo
 *   4. EUF-CMA game helpers (browser-side)
 *
 * Block size: 8 bytes (64 bits), matching GGMPRF.SEED_BITS in Python.
 */

import { ggmEvaluate } from "./ggm";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BLOCK_BYTES = 8;
const BLOCK_MASK = (1n << 64n) - 1n;

// Fixed public IV and compression key for the toy Merkle-Damgård hash.
// These match the Python ToyMDHash constants.
const TOY_MD_IV = 0xdeadbeefcafe1234n;
const TOY_MD_KEY_HEX = "a5b4c3d2e1f09817"; // FIXED_KEY as hex

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a hex string to a BigInt (safe for 64-bit values). */
function hexToBigInt(hex: string): bigint {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "") || "0";
  return BigInt("0x" + clean);
}

/** Convert a BigInt to a zero-padded 16-char hex string. */
function bigIntToHex16(v: bigint): string {
  return (v & BLOCK_MASK).toString(16).padStart(16, "0");
}

/** Convert a Uint8Array to a BigInt (big-endian). */
function bytesToBigInt(bytes: Uint8Array, fromOffset = 0): bigint {
  let v = 0n;
  for (let i = fromOffset; i < fromOffset + BLOCK_BYTES && i < bytes.length; i++) {
    v = (v << 8n) | BigInt(bytes[i] ?? 0);
  }
  return v;
}

/** XOR two BigInt values, truncated to 64 bits. */
function xor64(a: bigint, b: bigint): bigint {
  return (a ^ b) & BLOCK_MASK;
}

/** Encode text as UTF-8 bytes. */
function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Convert Uint8Array to hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Convert a BigInt key / number to a 16-char query bit string (64 bits). */
function bigIntToQueryBits(v: bigint): string {
  return (v & BLOCK_MASK).toString(2).padStart(64, "0");
}

// ---------------------------------------------------------------------------
// GGM PRF wrapper  (F_k(x) → bigint)
// ---------------------------------------------------------------------------

/**
 * Evaluate the GGM PRF: F_k(x).
 * @param keyHex  16-hex-char key string
 * @param x       64-bit input (bigint)
 */
function prfEval(keyHex: string, x: bigint): bigint {
  const queryBits = bigIntToQueryBits(x);
  return ggmEvaluate(keyHex, queryBits);
}

// ---------------------------------------------------------------------------
// PKCS-style padding to 8-byte boundary
// ---------------------------------------------------------------------------

function pkcs8Pad(data: Uint8Array): Uint8Array {
  const pad = BLOCK_BYTES - (data.length % BLOCK_BYTES);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

// ---------------------------------------------------------------------------
// 1. PRF-MAC  (fixed-length)
// ---------------------------------------------------------------------------

/**
 * PRF-MAC: tag = F_k(m).
 * Message m is treated as a 64-bit integer (first 8 bytes of UTF-8 encoding,
 * zero-padded if shorter).
 *
 * @param keyHex  16-hex-char key
 * @param msgText UTF-8 message (≤ 8 bytes for single-block; longer messages are truncated for PRF-MAC)
 * @returns 16-char hex tag
 */
export function prfMacTag(keyHex: string, msgText: string): string {
  const mBytes = textToBytes(msgText);
  // Fit into a single 8-byte block (zero-padded big-endian)
  const block = new Uint8Array(BLOCK_BYTES);
  block.set(mBytes.slice(0, BLOCK_BYTES));
  const m = bytesToBigInt(block);
  const tag = prfEval(keyHex, m);
  return bigIntToHex16(tag);
}

/**
 * PRF-MAC verification.
 * @returns true iff F_k(m) === tagHex
 */
export function prfMacVerify(keyHex: string, msgText: string, tagHex: string): boolean {
  return prfMacTag(keyHex, msgText) === tagHex.toLowerCase().padStart(16, "0");
}

// ---------------------------------------------------------------------------
// 2. CBC-MAC  (variable-length)
// ---------------------------------------------------------------------------

/**
 * CBC-MAC: chain F_k over PKCS-padded 8-byte blocks.
 *
 *   state = 0
 *   for each block M_i:  state = F_k(state ⊕ M_i)
 *   tag = state
 *
 * @param keyHex  16-hex-char key
 * @param msgText UTF-8 message (arbitrary length)
 * @returns 16-char hex tag
 */
export function cbcMacTag(keyHex: string, msgText: string): string {
  const mBytes = pkcs8Pad(textToBytes(msgText));
  let state = 0n;
  for (let i = 0; i < mBytes.length; i += BLOCK_BYTES) {
    const blockVal = bytesToBigInt(mBytes, i);
    const inp = xor64(state, blockVal);
    state = prfEval(keyHex, inp);
  }
  return bigIntToHex16(state);
}

/**
 * CBC-MAC verification.
 * @returns true iff cbcMacTag(k, m) === tagHex
 */
export function cbcMacVerify(keyHex: string, msgText: string, tagHex: string): boolean {
  return cbcMacTag(keyHex, msgText) === tagHex.toLowerCase().padStart(16, "0");
}

// ---------------------------------------------------------------------------
// 3. Toy Merkle-Damgård hash (for length-extension demo)
// ---------------------------------------------------------------------------

/**
 * Toy Merkle-Damgård compression:
 *   compress(state, block) = F_{FIXED_KEY}(state ⊕ block)
 */
function toyCompress(state: bigint, blockVal: bigint): bigint {
  return prfEval(TOY_MD_KEY_HEX, xor64(state, blockVal));
}

/**
 * Merkle-Damgård padding for the toy hash.
 * Appends 0x80, zero bytes to align, then 8-byte big-endian bit-length
 * (including any hidden prefix of `prefixLen` bytes).
 *
 * Returns the padded Uint8Array.
 */
export function toyMdPad(data: Uint8Array, prefixLen = 0): Uint8Array {
  const totalBits = BigInt((data.length + prefixLen) * 8);

  // Append 0x80 + zeros until length is a multiple of BLOCK_BYTES
  let padded = new Uint8Array(data.length + 1);
  padded.set(data);
  padded[data.length] = 0x80;

  while (padded.length % BLOCK_BYTES !== 0) {
    const tmp = new Uint8Array(padded.length + 1);
    tmp.set(padded);
    padded = tmp;
  }

  // Append 8-byte big-endian bit-length
  const lenBytes = new Uint8Array(BLOCK_BYTES);
  let rem = totalBits;
  for (let i = BLOCK_BYTES - 1; i >= 0; i--) {
    lenBytes[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  const result = new Uint8Array(padded.length + BLOCK_BYTES);
  result.set(padded);
  result.set(lenBytes, padded.length);
  return result;
}

/**
 * Toy Merkle-Damgård hash (compresses already-padded data).
 * Call with `toyMdPad(data)` as input for a full hash.
 *
 * @param paddedData  Pre-padded byte array
 * @param initialState  Starting chaining value (defaults to TOY_MD_IV)
 * @returns 64-bit digest as bigint
 */
function toyMdDigest(paddedData: Uint8Array, initialState = TOY_MD_IV): bigint {
  let state = initialState;
  for (let i = 0; i < paddedData.length; i += BLOCK_BYTES) {
    const blockVal = bytesToBigInt(paddedData, i);
    state = toyCompress(state, blockVal);
  }
  return state & BLOCK_MASK;
}

/**
 * Full toy hash: pads then digests.
 * @returns 16-char hex digest
 */
export function toyMdHash(data: Uint8Array): string {
  return bigIntToHex16(toyMdDigest(toyMdPad(data)));
}

// ---------------------------------------------------------------------------
// Naive MAC:  t = H(k ‖ m)
// ---------------------------------------------------------------------------

/**
 * Naive MAC: t = H( k_bytes ‖ m_bytes ).
 * VULNERABLE to length-extension attacks — provided for the demo.
 *
 * @param keyHex  16-hex-char key (8 bytes)
 * @param msgText UTF-8 message
 * @returns 16-char hex tag
 */
export function naiveMacTag(keyHex: string, msgText: string): string {
  const kBytes = new Uint8Array(BLOCK_BYTES);
  const kBig = hexToBigInt(keyHex) & BLOCK_MASK;
  for (let i = 0; i < BLOCK_BYTES; i++) {
    kBytes[BLOCK_BYTES - 1 - i] = Number((kBig >> BigInt(i * 8)) & 0xffn);
  }
  const mBytes = textToBytes(msgText);
  const combined = new Uint8Array(kBytes.length + mBytes.length);
  combined.set(kBytes);
  combined.set(mBytes, kBytes.length);
  return toyMdHash(combined);
}

// ---------------------------------------------------------------------------
// Length-extension attack
// ---------------------------------------------------------------------------

export interface LengthExtResult {
  /** Original message text */
  originalMsgText: string;
  /** Glue padding bytes (hex) */
  gluePadHex: string;
  /** Attacker-chosen suffix text */
  suffixText: string;
  /**
   * Extended message = original_m ‖ glue_pad ‖ suffix
   * (the key prefix is hidden; attacker only presents this part)
   */
  extendedMsgText: string;
  /** Forged tag, computed WITHOUT knowing k */
  extendedTagHex: string;
  /** Whether the forged tag verifies against naive H(k ‖ extended_m) */
  verified: boolean;
  explanation: string;
}

/**
 * Performs a length-extension attack on naiveMacTag.
 *
 * Given (originalMsgText, originalTagHex) from the MAC oracle, and
 * an attacker-chosen suffix, computes a valid tag for the extended
 * message WITHOUT knowing the key.
 *
 * @param keyHex          Real key (used only by challenger to verify — attacker code does NOT use this)
 * @param originalMsgText Original message text
 * @param originalTagHex  naiveMacTag(key, originalMsgText) — 16 hex chars
 * @param suffix          Attacker suffix text
 */
export function lengthExtend(
  keyHex: string,
  originalMsgText: string,
  originalTagHex: string,
  suffix: string,
): LengthExtResult {
  const KEY_LEN = BLOCK_BYTES; // Attacker knows |k| (common assumption)
  const mBytes = textToBytes(originalMsgText);
  const sBytes = textToBytes(suffix);

  // --- Attacker's work (no key knowledge used below this line) ---

  // Reconstruct glue padding: padding that was appended to (k ‖ m)
  // Attacker substitutes zeros for k (same length), producing the same padding.
  const fakeKm = new Uint8Array(KEY_LEN + mBytes.length);
  fakeKm.set(mBytes, KEY_LEN); // k is zero here (attacker doesn't know it)
  const paddedFakeKm = toyMdPad(fakeKm);
  const glueStart = fakeKm.length;
  const gluePad = paddedFakeKm.slice(glueStart);

  // Extended message presented to the challenger (without the k prefix)
  const extMsgBytes = new Uint8Array(mBytes.length + gluePad.length + sBytes.length);
  extMsgBytes.set(mBytes);
  extMsgBytes.set(gluePad, mBytes.length);
  extMsgBytes.set(sBytes, mBytes.length + gluePad.length);

  // Resume hashing from t = H(k ‖ m ‖ glue_pad).
  // The new padding must account for all bytes already hashed: |k| + |m| + |glue_pad|.
  const prefixLen = KEY_LEN + mBytes.length + gluePad.length;
  const suffixPadded = toyMdPad(sBytes, prefixLen);
  const resumeState = hexToBigInt(originalTagHex);
  const extTag = toyMdDigest(suffixPadded, resumeState);
  const extTagHex = bigIntToHex16(extTag);

  // --- Challenger verification (uses real key) ---
  const kBytes = new Uint8Array(BLOCK_BYTES);
  const kBig = hexToBigInt(keyHex) & BLOCK_MASK;
  for (let i = 0; i < BLOCK_BYTES; i++) {
    kBytes[BLOCK_BYTES - 1 - i] = Number((kBig >> BigInt(i * 8)) & 0xffn);
  }
  const fullExtended = new Uint8Array(kBytes.length + extMsgBytes.length);
  fullExtended.set(kBytes);
  fullExtended.set(extMsgBytes, kBytes.length);
  const expectedTag = toyMdHash(fullExtended);
  const verified = extTagHex === expectedTag;

  return {
    originalMsgText,
    gluePadHex: bytesToHex(gluePad),
    suffixText: suffix,
    extendedMsgText: new TextDecoder().decode(extMsgBytes),
    extendedTagHex: extTagHex,
    verified,
    explanation:
      "The attacker resumed hashing from state t = H(k ‖ m ‖ pad) and " +
      "computed a valid tag for (m ‖ pad ‖ suffix) WITHOUT knowing k. " +
      "HMAC prevents this by nesting H((k⊕opad) ‖ H((k⊕ipad) ‖ m)), " +
      "eliminating any reachable intermediate chaining state.",
  };
}

// ---------------------------------------------------------------------------
// 4. EUF-CMA game (browser-side)
// ---------------------------------------------------------------------------

export interface SignedPair {
  msg: string;
  tag: string;
}

const WORD_BANK = [
  "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
  "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
  "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
  "victor", "whiskey", "xray", "yankee", "zulu", "aegis", "beacon",
  "cipher", "delta2", "epsilon", "falcon", "gamma", "hydra", "iris",
  "janus", "kappa", "lambda", "morpheus", "nexus", "oracle", "prism",
  "quantum", "raven", "sigma", "theta", "umbra", "vortex", "warden",
  "xenon", "yield", "zenith",
];

/** Generate n random signed pairs under keyHex using the given MAC scheme. */
export function generateSignedPairs(
  keyHex: string,
  n: number,
  scheme: "PRF-MAC" | "CBC-MAC" = "CBC-MAC",
): SignedPair[] {
  const pairs: SignedPair[] = [];
  for (let i = 0; i < n; i++) {
    const msg = i < WORD_BANK.length ? WORD_BANK[i] : `msg-${String(i).padStart(4, "0")}`;
    const tag =
      scheme === "PRF-MAC" ? prfMacTag(keyHex, msg) : cbcMacTag(keyHex, msg);
    pairs.push({ msg, tag });
  }
  return pairs;
}

/** Verify a forgery attempt. */
export function verifyForgery(
  keyHex: string,
  msgText: string,
  tagHex: string,
  scheme: "PRF-MAC" | "CBC-MAC" = "CBC-MAC",
): boolean {
  return scheme === "PRF-MAC"
    ? prfMacVerify(keyHex, msgText, tagHex)
    : cbcMacVerify(keyHex, msgText, tagHex);
}

/** Generate a secure random 16-hex-char key for the browser demo. */
export function generateMacKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(BLOCK_BYTES));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
