/**
 * PA#7 — Merkle-Damgård Transform (TypeScript, browser demo)
 *
 * Toy parameters match pa07.py:
 *   block_size = 8 bytes
 *   digest_size = 4 bytes
 *   IV = 00000000 (4 zero bytes)
 *
 * MD-strengthening pad:
 *   msg || 0x80 || 0x00* || <64-bit big-endian bit-length>
 *   padded length is a multiple of block_size
 *
 * Toy compression:
 *   h(state[4], block[8]) = state XOR block[0..3] XOR block[4..7]
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MDBlock {
  /** 0-based block index */
  index: number;
  /** Raw block hex (8 bytes = 16 hex chars) */
  hex: string;
  /** True if this is the padding+length block */
  isPaddingBlock: boolean;
  /** Chaining value INPUT to this step (state before) */
  stateInHex: string;
  /** Chaining value OUTPUT from this step (state after) */
  stateOutHex: string;
  /** Whether this block was edited by the user */
  isEdited?: boolean;
}

export interface MDTrace {
  /** Original message text */
  messageText: string;
  /** Original message hex */
  messageHex: string;
  /** Full padded hex */
  paddedHex: string;
  /** All blocks as MDBlock entries */
  blocks: MDBlock[];
  /** Final digest (4-byte hex = 8 chars) */
  digestHex: string;
  /** IV hex */
  ivHex: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const BLOCK_SIZE = 8;   // bytes
export const DIGEST_SIZE = 4;  // bytes
export const IV_HEX = "00000000"; // 4-byte IV

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const h = hex.length % 2 ? "0" + hex : hex;
  return new Uint8Array((h.match(/../g) ?? []).map((b) => parseInt(b, 16)));
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (v) => v.toString(16).padStart(2, "0")).join("");
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ---------------------------------------------------------------------------
// MD-strengthening padding
// ---------------------------------------------------------------------------

/**
 * Pad message bytes using MD-strengthening:
 *   msg || 0x80 || (zeros) || [64-bit big-endian bit-length]
 * Result length is a multiple of BLOCK_SIZE.
 */
export function mdPad(msgBytes: Uint8Array): Uint8Array {
  const bitLen = BigInt(msgBytes.length) * 8n;
  let padded = new Uint8Array(msgBytes.length + 1);
  padded.set(msgBytes);
  padded[msgBytes.length] = 0x80;

  // Extend with zeros until (len + 8) % BLOCK_SIZE === 0
  while ((padded.length + 8) % BLOCK_SIZE !== 0) {
    const tmp = new Uint8Array(padded.length + 1);
    tmp.set(padded);
    padded = tmp;
  }

  // Append 8-byte big-endian bit-length
  const lenBytes = new Uint8Array(8);
  let rem = bitLen;
  for (let i = 7; i >= 0; i--) {
    lenBytes[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  const result = new Uint8Array(padded.length + 8);
  result.set(padded);
  result.set(lenBytes, padded.length);
  return result;
}

// ---------------------------------------------------------------------------
// Toy XOR compression function
// ---------------------------------------------------------------------------

/**
 * Toy compression: h(state[4], block[8]) = state XOR block[0..3] XOR block[4..7]
 * Matches pa07.py toy_xor_compression.
 */
export function toyCompress(stateHex: string, blockHex: string): string {
  const state = hexToBytes(stateHex.padStart(8, "0").slice(0, 8));
  const block = hexToBytes(blockHex.padStart(16, "0").slice(0, 16));
  const left = block.slice(0, 4);
  const right = block.slice(4, 8);
  const out = xorBytes(xorBytes(state, left), right);
  return bytesToHex(out);
}

// ---------------------------------------------------------------------------
// Full MD hash + trace
// ---------------------------------------------------------------------------

/**
 * Compute the full Merkle-Damgård trace for a message.
 *
 * @param messageText  UTF-8 plaintext (or hex if prefixed with "0x")
 * @param editedBlocks Optional map of blockIndex → overridden hex (for demo editing)
 */
export function computeMDTrace(
  messageText: string,
  editedBlocks?: Map<number, string>,
): MDTrace {
  const msgBytes = new TextEncoder().encode(messageText);
  const paddedBytes = mdPad(msgBytes);
  const numBlocks = Math.floor(paddedBytes.length / BLOCK_SIZE);

  const blocks: MDBlock[] = [];
  let state = IV_HEX;

  for (let i = 0; i < numBlocks; i++) {
    const rawBlockBytes = paddedBytes.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    const rawBlockHex = bytesToHex(rawBlockBytes);
    const isEdited = editedBlocks?.has(i) ?? false;
    const blockHex = isEdited ? (editedBlocks!.get(i) ?? rawBlockHex) : rawBlockHex;

    const isPaddingBlock = i === numBlocks - 1; // last block always has length field

    const stateIn = state;
    const stateOut = toyCompress(state, blockHex.padEnd(16, "0"));
    state = stateOut;

    blocks.push({
      index: i,
      hex: blockHex,
      isPaddingBlock,
      stateInHex: stateIn,
      stateOutHex: stateOut,
      isEdited,
    });
  }

  return {
    messageText,
    messageHex: bytesToHex(msgBytes),
    paddedHex: bytesToHex(paddedBytes),
    blocks,
    digestHex: state,
    ivHex: IV_HEX,
  };
}

// ---------------------------------------------------------------------------
// Collision propagation demo
// ---------------------------------------------------------------------------

export interface CollisionDemo {
  m1Hex: string;
  m2Hex: string;
  collisionStateHex: string;
  m1DigestHex: string;
  m2DigestHex: string;
  propagated: boolean;
  explanation: string;
}

/**
 * Demonstrate that a collision in the toy compression function propagates
 * through the entire MD hash.
 *
 * m1 and m2 are constructed so h(IV, m1) == h(IV, m2) but m1 != m2.
 * Because the single-block padding is the same (same length), the full
 * MD hashes also collide.
 */
export function collisionDemo(): CollisionDemo {
  const IV = IV_HEX;
  // delta XOR cancels: (left XOR delta) XOR (right XOR delta) = left XOR right
  const m1Hex = "00112233" + "44556677";
  const deltaHex = "deadbeef";

  const m1Left = hexToBytes("00112233");
  const m1Right = hexToBytes("44556677");
  const delta = hexToBytes(deltaHex);

  const m2Left = xorBytes(m1Left, delta);
  const m2Right = xorBytes(m1Right, delta);
  const m2Hex = bytesToHex(m2Left) + bytesToHex(m2Right);

  const col = toyCompress(IV, m1Hex);

  // Direct hash via manual padding (more reliable for non-UTF8 bytes)
  const h1 = hashBytes(hexToBytes(m1Hex));
  const h2 = hashBytes(hexToBytes(m2Hex));

  return {
    m1Hex,
    m2Hex,
    collisionStateHex: col,
    m1DigestHex: h1,
    m2DigestHex: h2,
    propagated: h1 === h2,
    explanation:
      "m₁ and m₂ differ in every byte, but h_toy(IV, m₁) = h_toy(IV, m₂) " +
      "because XOR-ing the same delta into both halves cancels out. Since padding " +
      "is identical (same message length), the full MD hashes also collide — " +
      "concretely witnessing: collision in h ⇒ collision in H_MD.",
  };
}

/**
 * Hash raw bytes (bypasses TextEncoder, handles non-UTF8 byte sequences).
 */
function hashBytes(msgBytes: Uint8Array): string {
  const padded = mdPad(msgBytes);
  const numBlocks = Math.floor(padded.length / BLOCK_SIZE);
  let state = IV_HEX;
  for (let i = 0; i < numBlocks; i++) {
    const block = padded.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    state = toyCompress(state, bytesToHex(block));
  }
  return state;
}
