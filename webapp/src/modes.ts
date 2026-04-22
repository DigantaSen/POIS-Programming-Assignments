import { ggmEvaluate } from "./ggm";

export type ModeId = "CBC" | "OFB" | "CTR";

export interface CBCTraceBlock {
  index: number;
  prevHex: string;
  ptHex: string;
  xorHex: string;
  ctHex: string;
}

export interface OFBTraceBlock {
  index: number;
  stateInHex: string;
  ksHex: string;
  ptHex: string;
  ctHex: string;
}

export interface CTRTraceBlock {
  index: number;
  counterHex: string;
  ksHex: string;
  ptHex: string;
  ctHex: string;
}

export interface CBCEncResult {
  iv: Uint8Array;
  ct: Uint8Array;
  trace: CBCTraceBlock[];
}

export interface OFBEncResult {
  iv: Uint8Array;
  ct: Uint8Array;
  trace: OFBTraceBlock[];
}

export interface CTREncResult {
  nonce: Uint8Array;
  ct: Uint8Array;
  trace: CTRTraceBlock[];
}

const BLOCK_BYTES = 4;
const HALF_BITS = 16;
const FEISTEL_ROUNDS = 6;
const MASK16 = 0xffff;
const MASK32 = 0xffff_ffff;

function toCleanKey(keyHex: string): bigint {
  const cleaned = keyHex.replace(/[^0-9a-fA-F]/g, "") || "0";
  return BigInt("0x" + cleaned);
}

function fRound(key: bigint, roundIdx: number, rightHalf: number): number {
  const query = ((roundIdx & 0xff) << HALF_BITS) | (rightHalf & MASK16);
  const out = ggmEvaluate(key.toString(16), query.toString(2).padStart(64, "0"));
  return Number(out & 0xffffn);
}

function encryptBlock(keyHex: string, block: Uint8Array): Uint8Array {
  if (block.length !== BLOCK_BYTES) throw new Error("encryptBlock expects 4-byte block");
  const key = toCleanKey(keyHex);

  let x = bytesToUint32(block);
  let left = (x >>> HALF_BITS) & MASK16;
  let right = x & MASK16;

  for (let r = 0; r < FEISTEL_ROUNDS; r += 1) {
    const nextLeft = right;
    const nextRight = left ^ fRound(key, r, right);
    left = nextLeft;
    right = nextRight & MASK16;
  }

  x = ((left & MASK16) << HALF_BITS) | (right & MASK16);
  return uint32ToBytes(x >>> 0);
}

function decryptBlock(keyHex: string, block: Uint8Array): Uint8Array {
  if (block.length !== BLOCK_BYTES) throw new Error("decryptBlock expects 4-byte block");
  const key = toCleanKey(keyHex);

  let y = bytesToUint32(block);
  let left = (y >>> HALF_BITS) & MASK16;
  let right = y & MASK16;

  for (let r = FEISTEL_ROUNDS - 1; r >= 0; r -= 1) {
    const prevLeft = right ^ fRound(key, r, left);
    const prevRight = left;
    left = prevLeft & MASK16;
    right = prevRight & MASK16;
  }

  const x = ((left & MASK16) << HALF_BITS) | (right & MASK16);
  return uint32ToBytes(x >>> 0);
}

function pkcs7Pad(bytes: Uint8Array): Uint8Array {
  const pad = BLOCK_BYTES - (bytes.length % BLOCK_BYTES);
  const out = new Uint8Array(bytes.length + pad);
  out.set(bytes);
  out.fill(pad, bytes.length);
  return out;
}

function pkcs7Unpad(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) return bytes;
  const pad = bytes[bytes.length - 1];
  if (pad < 1 || pad > BLOCK_BYTES) throw new Error("Invalid PKCS7 padding");
  for (let i = bytes.length - pad; i < bytes.length; i += 1) {
    if (bytes[i] !== pad) throw new Error("Invalid PKCS7 padding");
  }
  return bytes.slice(0, bytes.length - pad);
}

function chunkBlocks(bytes: Uint8Array, blockBytes = BLOCK_BYTES): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += blockBytes) {
    out.push(bytes.slice(i, i + blockBytes));
  }
  return out;
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) out[i] = a[i] ^ b[i];
  return out;
}

function bytesToUint32(block: Uint8Array): number {
  return (
    ((block[0] ?? 0) << 24) |
    ((block[1] ?? 0) << 16) |
    ((block[2] ?? 0) << 8) |
    (block[3] ?? 0)
  ) >>> 0;
}

function uint32ToBytes(v: number): Uint8Array {
  return new Uint8Array([
    (v >>> 24) & 0xff,
    (v >>> 16) & 0xff,
    (v >>> 8) & 0xff,
    v & 0xff,
  ]);
}

export function randomBlock(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(BLOCK_BYTES));
}

export function cbcEncrypt(keyHex: string, msg: Uint8Array, iv?: Uint8Array): CBCEncResult {
  const ivBytes = iv ?? randomBlock();
  const padded = pkcs7Pad(msg);
  const blocks = chunkBlocks(padded);

  let prev = ivBytes;
  const ctBlocks: Uint8Array[] = [];
  const trace: CBCTraceBlock[] = [];

  for (let i = 0; i < blocks.length; i += 1) {
    const x = xorBytes(blocks[i], prev);
    const c = encryptBlock(keyHex, x);
    ctBlocks.push(c);
    trace.push({
      index: i,
      prevHex: bytesToHex(prev),
      ptHex: bytesToHex(blocks[i]),
      xorHex: bytesToHex(x),
      ctHex: bytesToHex(c),
    });
    prev = c;
  }

  return { iv: ivBytes, ct: concatBlocks(ctBlocks), trace };
}

export function cbcDecrypt(keyHex: string, iv: Uint8Array, ct: Uint8Array): Uint8Array {
  const raw = cbcDecryptRaw(keyHex, iv, ct);
  return pkcs7Unpad(raw);
}

export function cbcDecryptRaw(keyHex: string, iv: Uint8Array, ct: Uint8Array): Uint8Array {
  const blocks = chunkBlocks(ct);
  let prev = iv;
  const out: Uint8Array[] = [];

  for (const c of blocks) {
    const x = decryptBlock(keyHex, c);
    out.push(xorBytes(x, prev));
    prev = c;
  }

  return concatBlocks(out);
}

export function ofbEncrypt(keyHex: string, msg: Uint8Array, iv?: Uint8Array): OFBEncResult {
  const ivBytes = iv ?? randomBlock();
  const blocks = chunkBlocks(msg);

  let state = ivBytes;
  const out: Uint8Array[] = [];
  const trace: OFBTraceBlock[] = [];

  for (let i = 0; i < blocks.length; i += 1) {
    const stateIn = state;
    const ks = encryptBlock(keyHex, stateIn);
    state = ks;
    const c = xorBytes(blocks[i], ks.slice(0, blocks[i].length));
    out.push(c);
    trace.push({
      index: i,
      stateInHex: bytesToHex(stateIn),
      ksHex: bytesToHex(ks),
      ptHex: bytesToHex(blocks[i]),
      ctHex: bytesToHex(c),
    });
  }

  return { iv: ivBytes, ct: concatBlocks(out), trace };
}

export function ofbDecrypt(keyHex: string, iv: Uint8Array, ct: Uint8Array): Uint8Array {
  return ofbEncrypt(keyHex, ct, iv).ct;
}

export function ctrEncrypt(keyHex: string, msg: Uint8Array, nonce?: Uint8Array): CTREncResult {
  const nonceBytes = nonce ?? randomBlock();
  const blocks = chunkBlocks(msg);
  const n0 = bytesToUint32(nonceBytes);

  const out: Uint8Array[] = [];
  const trace: CTRTraceBlock[] = [];

  for (let i = 0; i < blocks.length; i += 1) {
    const ctr = (n0 + i) & MASK32;
    const counterBytes = uint32ToBytes(ctr);
    const ks = encryptBlock(keyHex, counterBytes);
    const c = xorBytes(blocks[i], ks.slice(0, blocks[i].length));
    out.push(c);
    trace.push({
      index: i,
      counterHex: bytesToHex(counterBytes),
      ksHex: bytesToHex(ks),
      ptHex: bytesToHex(blocks[i]),
      ctHex: bytesToHex(c),
    });
  }

  return { nonce: nonceBytes, ct: concatBlocks(out), trace };
}

export function ctrDecrypt(keyHex: string, nonce: Uint8Array, ct: Uint8Array): Uint8Array {
  return ctrEncrypt(keyHex, ct, nonce).ct;
}

export function mutateCipherBlockBit(ct: Uint8Array, blockIdx: number): Uint8Array {
  const out = ct.slice();
  const pos = blockIdx * BLOCK_BYTES;
  if (pos >= 0 && pos < out.length) {
    out[pos] ^= 0x01;
  }
  return out;
}

export function splitToDisplayBlocks(bytes: Uint8Array, nBlocks = 3): string[] {
  const blocks = chunkBlocks(bytes);
  const out: string[] = [];
  for (let i = 0; i < nBlocks; i += 1) {
    out.push(bytesToHex(blocks[i] ?? new Uint8Array(BLOCK_BYTES)));
  }
  return out;
}

export function normalizeToThreeBlocks(text: string): Uint8Array {
  const raw = utf8ToBytes(text);
  const out = new Uint8Array(BLOCK_BYTES * 3);
  out.set(raw.slice(0, out.length));
  return out;
}

function concatBlocks(blocks: Uint8Array[]): Uint8Array {
  const size = blocks.reduce((acc, b) => acc + b.length, 0);
  const out = new Uint8Array(size);
  let off = 0;
  for (const b of blocks) {
    out.set(b, off);
    off += b.length;
  }
  return out;
}
