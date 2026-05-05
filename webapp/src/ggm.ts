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

import { Q, SEED_BITS, prgExpand } from "./prg";

// ---------------------------------------------------------------------------
// Core GGM primitives
// ---------------------------------------------------------------------------

/**
 * G(s) → (G_0(s), G_1(s)):  two SEED_BITS-wide pseudorandom children.
 *
 * Uses the PA#1 PRG (iterative hardcore-bit construction) to produce
 * 2*SEED_BITS bits, then splits them — matching the Python _expand().
 *   stream = PRG(s, 2*SEED_BITS)
 *   G_0(s) = stream[0 .. SEED_BITS)
 *   G_1(s) = stream[SEED_BITS .. 2*SEED_BITS)
 */
export function ggmExpand(s: bigint): [bigint, bigint] {
  const seedHex = (s % Q).toString(16);
  // prgExpand returns SEED_BITS prefix + extraBits stream
  const allBits = prgExpand(seedHex, 2 * SEED_BITS);
  const stream = allBits.slice(SEED_BITS);          // skip seed-prefix
  const g0 = BigInt("0b" + stream.slice(0, SEED_BITS));
  const g1 = BigInt("0b" + stream.slice(SEED_BITS, 2 * SEED_BITS));
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
/**
 * Build nodes of a GGM tree (BFS order).
 *
 * @param pathOnly  When true, only expand on-path nodes (for n>4 path view).
 *                  Keeps performance acceptable for deep trees.
 */
export function buildGGMTree(
  keyHex: string,
  depth: number,
  queryBits: string,
  pathOnly = false,
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
      // In pathOnly mode skip off-path branches — cuts cost from O(2^n) to O(n)
      if (pathOnly && !onPath) continue;
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
