import {
  concatBytes,
  hexToBytes,
  bytesToHex,
  mdPad,
  pa08DigestPadded,
  pa08HashBytes,
  textToBytes,
} from "./pa08hash";

export const HMAC_BLOCK_BYTES = 8;

function xorWithPad(key: Uint8Array, padByte: number): Uint8Array {
  const out = new Uint8Array(HMAC_BLOCK_BYTES);
  for (let i = 0; i < HMAC_BLOCK_BYTES; i++) {
    out[i] = key[i] ^ padByte;
  }
  return out;
}

function normalizeKey(key: Uint8Array): Uint8Array {
  let k = key;
  if (k.length > HMAC_BLOCK_BYTES) {
    k = hexToBytes(pa08HashBytes(k));
  }
  if (k.length < HMAC_BLOCK_BYTES) {
    const out = new Uint8Array(HMAC_BLOCK_BYTES);
    out.set(k);
    k = out;
  }
  return k;
}

export function hmacPa08TagHex(key: Uint8Array, message: Uint8Array): string {
  const k0 = normalizeKey(key);
  const inner = hexToBytes(pa08HashBytes(concatBytes(xorWithPad(k0, 0x36), message)));
  return pa08HashBytes(concatBytes(xorWithPad(k0, 0x5c), inner));
}

export function naiveMacTagHex(key: Uint8Array, message: Uint8Array): string {
  return pa08HashBytes(concatBytes(key, message));
}

export function fixedTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export interface LengthExtensionResult {
  forgedMsgBytes: Uint8Array;
  forgedTagHex: string;
  gluePadHex: string;
}

export function forgeNaiveLengthExtension(
  originalMsg: Uint8Array,
  originalTagHex: string,
  appendData: Uint8Array,
  keyLenBytes: number,
): LengthExtensionResult {
  const glue = mdPad(concatBytes(new Uint8Array(keyLenBytes), originalMsg)).slice(keyLenBytes + originalMsg.length);
  const prefixLen = keyLenBytes + originalMsg.length + glue.length;
  const suffixPadded = mdPad(appendData, prefixLen);
  const forgedTagHex = pa08DigestPadded(suffixPadded, originalTagHex);

  return {
    forgedMsgBytes: concatBytes(originalMsg, glue, appendData),
    forgedTagHex,
    gluePadHex: bytesToHex(glue),
  };
}

export function verifyNaive(key: Uint8Array, msg: Uint8Array, tagHex: string): boolean {
  return fixedTimeHexEqual(naiveMacTagHex(key, msg), tagHex);
}

export function verifyHmac(key: Uint8Array, msg: Uint8Array, tagHex: string): boolean {
  return fixedTimeHexEqual(hmacPa08TagHex(key, msg), tagHex);
}

export function randomKeyHex(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(HMAC_BLOCK_BYTES));
  return bytesToHex(bytes);
}

export function strBytes(s: string): Uint8Array {
  return textToBytes(s);
}
