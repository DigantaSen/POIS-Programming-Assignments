/**
 * PA#2 — GGM PRF (TypeScript, browser demo)
 *
 * Length-doubling PRG split using the DLP OWF from PA#1:
 *   G_0(s) = owfEvaluate(s mod Q)              [left  child]
 *   G_1(s) = owfEvaluate((s + Q/2) mod Q)      [right child]
 *
 * PRF:  F_k(b_1 … b_n) = G_{b_n}(…G_{b_1}(k)…)
 *
 * Cost: n OWF evaluations (one modpow each) per query — fast even for n=8.
 */

import { owfEvaluate, Q } from "./prg";

const Q_HALF: bigint = Q >> 1n;

// ---------------------------------------------------------------------------
// Core GGM primitives
// ---------------------------------------------------------------------------

/**
 * G(s) → (G_0(s), G_1(s)):  two pseudorandom children via OWF.
 *   G_0(s) = g^{s}        mod p
 *   G_1(s) = g^{s+Q/2}    mod p   (shifted — independent of G_0)
 */
export function ggmExpand(s: bigint): [bigint, bigint] {
  const g0 = owfEvaluate(s % Q);
  const g1 = owfEvaluate(((s % Q) + Q_HALF) % Q);
  return [g0, g1];
}

/**
 * F_k(b_1…b_n): follow the bit path through the GGM tree.
 *
 * @param keyHex  hex string for the root seed k
 * @param queryBits  binary string "0101…" of length n
 * @returns  the PRF output (leaf node value as bigint)
 */
export function ggmEvaluate(keyHex: string, queryBits: string): bigint {
  const cleaned = keyHex.replace(/[^0-9a-fA-F]/g, "") || "0";
  let state = BigInt("0x" + cleaned) % Q;
  for (const bit of queryBits) {
    const [g0, g1] = ggmExpand(state);
    state = bit === "1" ? g1 : g0;
  }
  return state;
}

// ---------------------------------------------------------------------------
// Tree structure for visualisation
// ---------------------------------------------------------------------------

export interface GGMTreeNode {
  /** Binary path from root, e.g. "" = root, "01" = right child of left child */
  path: string;
  /** Node value (DLP OWF output) */
  value: bigint;
  /** Depth (0 = root) */
  level: number;
  /** Left-to-right index at this level (0-based) */
  index: number;
  /** True iff this node lies on the query path */
  onPath: boolean;
  /** True iff level === tree depth */
  isLeaf: boolean;
}

/**
 * Build all nodes in a GGM tree of given depth (BFS order).
 * For depth n: 2^(n+1) - 1 total nodes, 2^n leaves.
 */
export function buildGGMTree(
  keyHex: string,
  depth: number,
  queryBits: string,
): GGMTreeNode[] {
  const cleaned = keyHex.replace(/[^0-9a-fA-F]/g, "") || "0";
  const rootValue = BigInt("0x" + cleaned) % Q;

  const nodes: GGMTreeNode[] = [];
  const queue: Array<{ path: string; value: bigint }> = [
    { path: "", value: rootValue },
  ];

  for (const { path, value } of queue) {
    const level = path.length;
    const index = level === 0 ? 0 : parseInt(path, 2);
    const onPath = queryBits.slice(0, level) === path;

    nodes.push({ path, value, level, index, onPath, isLeaf: level === depth });

    if (level < depth) {
      const [g0, g1] = ggmExpand(value);
      queue.push({ path: path + "0", value: g0 });
      queue.push({ path: path + "1", value: g1 });
    }
  }

  return nodes;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Zero-padded hex string from a BigInt. */
export function bigintToHex(value: bigint, minLen = 8): string {
  return value.toString(16).padStart(minLen, "0");
}
