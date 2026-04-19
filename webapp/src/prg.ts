/**
 * PA#1 – OWF & PRG (TypeScript port, toy parameters for the live web demo)
 *
 * DLP-based OWF:  f(x) = g^x mod p
 *   safe prime p ≈ 2^31, prime-order subgroup of order q ≈ 2^30
 *
 * PRG construction (Håstad–Impagliazzo–Levin–Luby):
 *   G(x0) = b(x0) ‖ b(x1) ‖ … ‖ b(xℓ)   where  x_{i+1} = f(x_i)
 *   b(x)  = hard-core bit (inner-product / last bit of lightweight hash of x)
 */

// ---------------------------------------------------------------------------
// Toy DLP parameters (64-bit seed, group order ≈ 2^30)
// These are pre-computed safe-prime parameters that match the Python backend.
// ---------------------------------------------------------------------------
export const P = 2147483867n; // safe prime  (2*Q + 1), fits in 32-bit
export const Q = 1073741933n; // prime-order subgroup
export const G = 4n;          // generator of prime-order subgroup

// ---------------------------------------------------------------------------
// Modular exponentiation via BigInt (square-and-multiply)
// ---------------------------------------------------------------------------
function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// ---------------------------------------------------------------------------
// OWF: f(x) = g^x mod p
// ---------------------------------------------------------------------------
export function owfEvaluate(x: bigint): bigint {
  const exponent = x % Q;
  return modpow(G, exponent, P);
}

// ---------------------------------------------------------------------------
// Hard-core bit: lightweight FNV-1a over the BigInt bytes, take LSB
// (mirrors the Python blake2s-based hard-core bit in spirit)
// ---------------------------------------------------------------------------
function hardcoreBit(state: bigint): number {
  // Convert to byte array (big-endian, 4 bytes for 32-bit range)
  const bytes: number[] = [];
  let tmp = state;
  for (let i = 0; i < 4; i++) {
    bytes.unshift(Number(tmp & 0xffn));
    tmp >>= 8n;
  }

  // FNV-1a 32-bit
  let h = 2166136261;
  for (const b of bytes) {
    h ^= b;
    h = Math.imul(h, 16777619);
    h >>>= 0;
  }
  return h & 1;
}

// ---------------------------------------------------------------------------
// PRG: iterative hard-core bit expansion
//   seed    – seed integer (treated mod Q)
//   extraBits – number of extra bits ℓ to append after the seed prefix
// Returns the full bit-string (seed bits + ℓ extra bits) as a "0"/"1" string.
// ---------------------------------------------------------------------------
export function prgExpand(seedHex: string, extraBits: number): string {
  if (extraBits < 0) extraBits = 0;

  // Parse hex seed → BigInt
  const cleaned = seedHex.toLowerCase().replace(/[^0-9a-f]/g, "") || "0";
  let state: bigint = BigInt("0x" + cleaned) % Q;

  // Build the bit string
  let bits = "";
  for (let i = 0; i < extraBits; i++) {
    state = owfEvaluate(state);
    bits += hardcoreBit(state).toString();
  }
  return bits;
}

// ---------------------------------------------------------------------------
// Statistical tests (NIST SP 800-22 style)
// ---------------------------------------------------------------------------

export interface TestResult {
  name: string;
  pValue: number;
  pass: boolean;
  extra?: Record<string, number | string>;
}

function erfc(x: number): number {
  // Abramowitz & Stegun approximation
  const t = 1 / (1 + 0.3275911 * Math.abs(x));
  const poly =
    t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  const result = poly * Math.exp(-x * x);
  return x >= 0 ? result : 2 - result;
}

export function frequencyTest(bits: string): TestResult {
  const n = bits.length;
  if (n === 0) return { name: "Frequency (monobit)", pValue: 0, pass: false };
  const ones = [...bits].filter((b) => b === "1").length;
  const sObs = Math.abs(ones - (n - ones));
  const pValue = erfc(sObs / Math.sqrt(2 * n));
  return {
    name: "Frequency (monobit)",
    pValue,
    pass: pValue >= 0.01,
    extra: { ones_ratio: ones / n },
  };
}

export function runsTest(bits: string): TestResult {
  const n = bits.length;
  if (n < 2) return { name: "Runs", pValue: 0, pass: false };
  const pi = [...bits].filter((b) => b === "1").length / n;
  const tau = 2 / Math.sqrt(n);
  if (Math.abs(pi - 0.5) >= tau) return { name: "Runs", pValue: 0, pass: false };
  let transitions = 0;
  for (let i = 1; i < n; i++) if (bits[i] !== bits[i - 1]) transitions++;
  const vObs = transitions + 1;
  const numerator = Math.abs(vObs - 2 * n * pi * (1 - pi));
  const denominator = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
  const pValue = denominator ? erfc(numerator / denominator) : 0;
  return { name: "Runs", pValue, pass: pValue >= 0.01 };
}

export function serialTest(bits: string): TestResult {
  const n = bits.length;
  if (n < 4) return { name: "Serial (2-bit)", pValue: 0, pass: false };
  const wrapped = bits + bits[0];
  const counts: Record<string, number> = { "00": 0, "01": 0, "10": 0, "11": 0 };
  for (let i = 0; i < n; i++) counts[wrapped[i] + wrapped[i + 1]]++;
  const expected = n / 4;
  let chi2 = 0;
  for (const c of Object.values(counts)) chi2 += ((c - expected) ** 2) / expected;
  // Approximation: chi-sq to p-value (dof=3)
  const dof = 3;
  const z = ((chi2 / dof) ** (1 / 3) - (1 - 2 / (9 * dof))) / Math.sqrt(2 / (9 * dof));
  const pValue = Math.max(0, Math.min(1, 0.5 * erfc(z / Math.sqrt(2))));
  return { name: "Serial (2-bit)", pValue, pass: pValue >= 0.01 };
}

export function runAllTests(bits: string): TestResult[] {
  return [frequencyTest(bits), runsTest(bits), serialTest(bits)];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a binary string to hex (padded to full nibbles) */
export function bitsToHex(bits: string): string {
  if (!bits) return "";
  const pad = (4 - (bits.length % 4)) % 4;
  const padded = bits + "0".repeat(pad);
  let hex = "";
  for (let i = 0; i < padded.length; i += 4) {
    hex += parseInt(padded.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

/** Generate a random 16-byte hex seed */
export function randomSeedHex(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
