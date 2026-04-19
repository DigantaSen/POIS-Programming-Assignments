export type FoundationId = "AES" | "DLP";

export type PrimitiveId =
  | "OWF"
  | "OWP"
  | "PRG"
  | "PRF"
  | "PRP"
  | "MAC"
  | "ENC"
  | "CRHF";

export type DirectionMode = "forward" | "backward";

export interface BuildInputs {
  keyHex: string;
  messageHex: string;
}

export interface PrimitiveExecution {
  primitive: PrimitiveId;
  functionApplied: string;
  inputHex: string;
  outputHex: string;
  theorem: string;
  security: string;
  pa: string;
  implemented: boolean;
  duePa?: string;
  note?: string;
}

export interface PrimitiveOracle {
  primitive: PrimitiveId;
  evaluate: (inputHex: string) => string;
}

export interface ReductionStep {
  from: PrimitiveId;
  to: PrimitiveId;
  functionApplied: string;
  theorem: string;
  security: string;
  pa: string;
  implemented: boolean;
  duePa?: string;
  note?: string;
}

export interface ReductionTraceItem extends ReductionStep {
  inputHex: string;
  oracleResponseHex: string;
  outputHex: string;
}

export interface BuildResult {
  target: PrimitiveId;
  steps: PrimitiveExecution[];
  oracle: PrimitiveOracle | null;
  foundationCapability: PrimitiveId | null;
  message?: string;
}

export interface ProofSummary {
  headline: string;
  detail: string;
  steps: Array<{
    theorem: string;
    security: string;
    pa: string;
    implemented: boolean;
    duePa?: string;
  }>;
}

export const primitiveOrder: PrimitiveId[] = [
  "OWF",
  "OWP",
  "PRG",
  "PRF",
  "PRP",
  "MAC",
  "ENC",
  "CRHF",
];

export const primitiveLabel: Record<PrimitiveId, string> = {
  OWF: "One-Way Function (OWF)",
  OWP: "One-Way Permutation (OWP)",
  PRG: "Pseudorandom Generator (PRG)",
  PRF: "Pseudorandom Function (PRF)",
  PRP: "Pseudorandom Permutation (PRP)",
  MAC: "Message Authentication Code (MAC)",
  ENC: "Symmetric Encryption (ENC)",
  CRHF: "Collision-Resistant Hash (CRHF)",
};

export const primitiveDuePa: Record<PrimitiveId, string> = {
  OWF: "PA01",
  OWP: "PA01",
  PRG: "PA01",
  PRF: "PA02",
  PRP: "PA02",
  ENC: "PA03",
  MAC: "PA05",
  CRHF: "PA08",
};

const HEX_CHARS = "0123456789abcdef";

export function normalizeHex(value: string, fallback = "00"): string {
  const cleaned = value.toLowerCase().replace(/[^0-9a-f]/g, "");
  if (cleaned.length === 0) {
    return fallback;
  }
  if (cleaned.length % 2 === 0) {
    return cleaned;
  }
  return `0${cleaned}`;
}

export function stubHex(seed: string, bytes = 16): string {
  let state = 0x13579bdf;
  for (let i = 0; i < seed.length; i += 1) {
    state ^= seed.charCodeAt(i);
    state = (state * 1103515245 + 12345) & 0x7fffffff;
  }

  let output = "";
  for (let i = 0; i < bytes * 2; i += 1) {
    state = (state * 1664525 + 1013904223) >>> 0;
    output += HEX_CHARS[(state >>> 28) & 0x0f];
  }
  return output;
}
