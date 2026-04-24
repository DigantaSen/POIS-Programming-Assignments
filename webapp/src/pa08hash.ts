/**
 * PA08 helpers: DLP-style compression hash over Merkle-Damgard.
 * Toy parameters intentionally match backend shape (block=8, digest=4 bytes).
 */

export const PA08_BLOCK_BYTES = 8;
export const PA08_DIGEST_BYTES = 4;

const P = 2147483647n;
const G = 5n;
const H_HAT = 7n;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let b = base % mod;
  let e = exp;
  let acc = 1n;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      acc = (acc * b) % mod;
    }
    b = (b * b) % mod;
    e >>= 1n;
  }
  return acc;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = (hex || "").replace(/[^0-9a-f]/gi, "");
  const h = clean.length % 2 ? `0${clean}` : clean;
  return new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));
}

export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function mdPad(data: Uint8Array, prefixLen = 0): Uint8Array {
  const bitLen = BigInt(data.length + prefixLen) * 8n;
  let padded = new Uint8Array(data.length + 1);
  padded.set(data);
  padded[data.length] = 0x80;

  while ((padded.length + 8) % PA08_BLOCK_BYTES !== 0) {
    const next = new Uint8Array(padded.length + 1);
    next.set(padded);
    padded = next;
  }

  const lenBytes = new Uint8Array(8);
  let rem = bitLen;
  for (let i = 7; i >= 0; i--) {
    lenBytes[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }

  return concatBytes(padded, lenBytes);
}

function u8ToBig(v: Uint8Array): bigint {
  let out = 0n;
  for (const b of v) {
    out = (out << 8n) | BigInt(b);
  }
  return out;
}

function stateHexToBig(stateHex: string): bigint {
  const b = hexToBytes(stateHex.padStart(8, "0").slice(0, 8));
  return u8ToBig(b);
}

function compress(stateHex: string, block: Uint8Array): string {
  const state = stateHexToBig(stateHex);
  const y = u8ToBig(block);
  const v = (modPow(G, state, P) * modPow(H_HAT, y, P)) % P;
  const bytes = new Uint8Array(8);
  let rem = v;
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(rem & 0xffn);
    rem >>= 8n;
  }
  return bytesToHex(bytes.slice(8 - PA08_DIGEST_BYTES));
}

export function pa08DigestPadded(padded: Uint8Array, initialStateHex = "00000000"): string {
  if (padded.length % PA08_BLOCK_BYTES !== 0) {
    throw new Error("Padded input length must be a multiple of block size");
  }
  let state = initialStateHex.padStart(8, "0").slice(0, 8);
  for (let i = 0; i < padded.length; i += PA08_BLOCK_BYTES) {
    state = compress(state, padded.slice(i, i + PA08_BLOCK_BYTES));
  }
  return state;
}

export function pa08HashBytes(msg: Uint8Array): string {
  return pa08DigestPadded(mdPad(msg));
}

export function pa08HashText(message: string): string {
  return pa08HashBytes(textToBytes(message));
}

export function pa08HashNBits(msg: Uint8Array | string, nBits: number): number {
  if (nBits < 1 || nBits > 32) {
    throw new Error("nBits must be in [1,32]");
  }
  const digestHex = typeof msg === "string" ? pa08HashText(msg) : pa08HashBytes(msg);
  const full = parseInt(digestHex, 16) >>> 0;
  if (nBits === 32) return full;
  return full & ((1 << nBits) - 1);
}

export function u64ToBytes(v: number): Uint8Array {
  const out = new Uint8Array(8);
  let x = BigInt(v >>> 0);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
