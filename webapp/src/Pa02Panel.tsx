import { useMemo, useState } from "react";
import {
  GGMTreeNode,
  bigintToHex,
  buildGGMTree,
  ggmEvaluate,
  ggmExpand,
} from "./ggm";

// ---------------------------------------------------------------------------
// Layout constants for the SVG full-tree view (used when depth ≤ 4)
// ---------------------------------------------------------------------------
const SVG_W = 900;
const LEVEL_H = 76;
const TOP_PAD = 40;
const MAX_FULL_DEPTH = 4; // full tree for n ≤ 4 (16 leaves)

function nodeX(level: number, index: number): number {
  const slots = Math.pow(2, level);
  return ((index + 0.5) * SVG_W) / slots;
}
function nodeY(level: number): number {
  return TOP_PAD + level * LEVEL_H;
}
function nodeR(isLeaf: boolean, isActive: boolean): number {
  if (isActive) return 26;
  if (isLeaf) return 20;
  return 22;
}

// ---------------------------------------------------------------------------
// SVG tree (full, up to depth 4)
// ---------------------------------------------------------------------------
function GGMTreeSVG({
  nodes,
  depth,
}: {
  nodes: GGMTreeNode[];
  depth: number;
}) {
  const svgH = TOP_PAD + depth * LEVEL_H + 30 + 36;
  const nodeMap = new Map(nodes.map((n) => [n.path, n]));

  return (
    <svg
      viewBox={`0 0 ${SVG_W} ${svgH}`}
      width="100%"
      style={{ maxWidth: SVG_W, display: "block", margin: "0 auto" }}
      aria-label="GGM binary tree"
    >
      {/* ── Edges ── */}
      {nodes
        .filter((n) => n.path.length > 0)
        .map((node) => {
          const parent = nodeMap.get(node.path.slice(0, -1))!;
          const px = nodeX(parent.level, parent.index);
          const py = nodeY(parent.level);
          const cx = nodeX(node.level, node.index);
          const cy = nodeY(node.level);
          const bit = node.path[node.path.length - 1];
          const active = node.onPath && parent.onPath;
          const mx = (px + cx) / 2 + (bit === "0" ? -10 : 10);
          const my = (py + cy) / 2;

          return (
            <g key={`e-${node.path}`}>
              <line
                x1={px}
                y1={py + nodeR(false, false)}
                x2={cx}
                y2={cy - nodeR(node.isLeaf, node.onPath && node.isLeaf)}
                stroke={active ? "#1a5c9e" : "#d1d5db"}
                strokeWidth={active ? 2.5 : 1}
                strokeOpacity={active ? 1 : 0.55}
              />
              <text
                x={mx}
                y={my}
                fontSize={10}
                fontFamily="IBM Plex Mono, Consolas, monospace"
                fill={active ? "#1a5c9e" : "#9ca3af"}
                textAnchor="middle"
                dominantBaseline="middle"
                fontWeight={active ? "800" : "400"}
              >
                {bit}
              </text>
            </g>
          );
        })}

      {/* ── Nodes ── */}
      {nodes.map((node) => {
        const cx = nodeX(node.level, node.index);
        const cy = nodeY(node.level);
        const isActive = node.isLeaf && node.onPath;
        const r = nodeR(node.isLeaf, isActive);

        let fill: string, stroke: string, textFill: string;
        if (!node.onPath) {
          fill = "#e5e7eb";
          stroke = "#d1d5db";
          textFill = "#9ca3af";
        } else if (isActive) {
          fill = "#0d7f77";
          stroke = "#07564f";
          textFill = "#ffffff";
        } else {
          fill = "#1a5c9e";
          stroke = "#0f4080";
          textFill = "#ffffff";
        }

        const hexVal = bigintToHex(node.value, 8);
        const fontSize = depth <= 4 ? 9 : 8;

        return (
          <g key={`n-${node.path}`}>
            {isActive && (
              <circle
                cx={cx}
                cy={cy}
                r={r + 5}
                fill={fill}
                fillOpacity={0.2}
              />
            )}
            <circle
              cx={cx}
              cy={cy}
              r={r}
              fill={fill}
              stroke={stroke}
              strokeWidth={isActive ? 2 : 1}
            />
            <text
              x={cx}
              y={cy}
              fontSize={fontSize}
              fontFamily="IBM Plex Mono, Consolas, monospace"
              fill={textFill}
              textAnchor="middle"
              dominantBaseline="middle"
            >
              {hexVal.slice(0, 7)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Path-only view (when depth > 4: just the traversal steps in a column)
// ---------------------------------------------------------------------------
function PathView({
  nodes,
  queryBits,
}: {
  nodes: GGMTreeNode[];
  queryBits: string;
}) {
  const pathNodes = nodes.filter((n) => n.onPath);

  return (
    <div className="pa02-path-view">
      {pathNodes.map((node, i) => (
        <div key={node.path} className="pa02-path-step">
          <div className={`pa02-path-node${node.isLeaf ? " leaf" : ""}`}>
            <div className="pa02-path-node-label">
              {node.isLeaf ? "Leaf (F_k(x))" : node.level === 0 ? "Root (k)" : `Level ${node.level}`}
            </div>
            <div className="pa02-path-hex mono">
              0x{bigintToHex(node.value, 8)}
            </div>
          </div>
          {!node.isLeaf && (
            <div className="pa02-path-arrow">
              <span className="pa02-path-bit">
                b<sub>{i + 1}</sub> = {queryBits[i]}
              </span>
              <span className="pa02-path-down">↓</span>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main PA#2 Panel
// ---------------------------------------------------------------------------
export default function Pa02Panel() {
  const [keyHex, setKeyHex] = useState("a1b2c3d4e5f60718");
  const [depth, setDepth] = useState(4);
  const [rawQuery, setRawQuery] = useState("1010");

  /* Normalise queryBits to exactly `depth` binary chars */
  const queryBits = useMemo(() => {
    const q = rawQuery.replace(/[^01]/g, "");
    if (q.length >= depth) return q.slice(0, depth);
    return q.padEnd(depth, "0");
  }, [rawQuery, depth]);

  const isKeyHexValid = /^[0-9a-fA-F]+$/.test(keyHex) && keyHex.length > 0;

  /* GGM tree + leaf */
  const { nodes, leaf } = useMemo(() => {
    if (!isKeyHexValid) return { nodes: [] as GGMTreeNode[], leaf: 0n };
    return {
      nodes: buildGGMTree(keyHex, depth, queryBits),
      leaf: ggmEvaluate(keyHex, queryBits),
    };
  }, [keyHex, depth, queryBits, isKeyHexValid]);

  const leafHex = bigintToHex(leaf, 8);

  /* Avalanche demo: flip each bit and show new leaf */
  const avalanche = useMemo(() => {
    if (!isKeyHexValid) return [];
    return Array.from({ length: depth }, (_, i) => {
      const flipped = queryBits.split("");
      flipped[i] = flipped[i] === "0" ? "1" : "0";
      const altLeaf = ggmEvaluate(keyHex, flipped.join(""));
      return {
        i,
        orig: queryBits[i],
        flip: flipped[i],
        altHex: bigintToHex(altLeaf, 8),
        same: altLeaf === leaf,
      };
    });
  }, [keyHex, depth, queryBits, leaf, isKeyHexValid]);

  /* Handlers */
  const randomKey = () => {
    const b = new Uint8Array(8);
    crypto.getRandomValues(b);
    setKeyHex(Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""));
  };

  const handleDepth = (n: number) => {
    setDepth(n);
    setRawQuery(queryBits.slice(0, n).padEnd(n, "0"));
  };

  const flipBit = (i: number) => {
    const bits = queryBits.split("");
    bits[i] = bits[i] === "0" ? "1" : "0";
    setRawQuery(bits.join(""));
  };

  // Quick "PRG from PRF" preview: G_0(k) and G_1(k) using ggmExpand
  const prgPreview = useMemo(() => {
    if (!isKeyHexValid) return null;
    const cleaned = keyHex.replace(/[^0-9a-fA-F]/g, "") || "0";
    const rootVal = BigInt("0x" + cleaned);
    const [g0, g1] = ggmExpand(rootVal);
    return { g0: bigintToHex(g0, 8), g1: bigintToHex(g1, 8) };
  }, [keyHex, isKeyHexValid]);

  const showFull = depth <= MAX_FULL_DEPTH;

  return (
    <div className="pa02-shell">
      {/* ── Hero ── */}
      <section className="pa02-hero">
        <div className="pa01-hero-badge" style={{ background: "rgba(108,56,14,0.25)", borderColor: "rgba(230,155,80,0.4)", color: "#f0c070" }}>
          PA #2
        </div>
        <h2 className="pa02-hero-title">Pseudorandom Functions via GGM Tree</h2>
        <p className="pa02-hero-sub">
          F<sub>k</sub>(b₁…b<sub>n</sub>) = G<sub>b<sub>n</sub></sub>(…G<sub>b₁</sub>(k)…){" "}
          &nbsp;·&nbsp; Goldreich–Goldwasser–Micali &nbsp;·&nbsp; PRG ⇒ PRF
        </p>
        <div className="pa01-params">
          {[
            { label: "Construction", val: "GGM binary tree" },
            { label: "Leaves (2^n)", val: String(Math.pow(2, depth)) },
            { label: "Base PRG", val: "DLP OWF (PA#1)" },
            { label: "Interface", val: "F(k, x)" },
          ].map((p) => (
            <div key={p.label} className="pa01-param" style={{ borderColor: "rgba(230,155,80,0.25)", background: "rgba(180,100,20,0.14)" }}>
              <span className="pa01-param-label" style={{ color: "#d4a060" }}>{p.label}</span>
              <span className="pa01-param-val">{p.val}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── Controls ── */}
      <section className="pa02-controls">
        <div className="pa02-control-card">
          <div className="pa01-control-label">
            <label htmlFor="pa02-key">Key k (hex)</label>
            <button type="button" className="pa01-random-btn" onClick={randomKey}>
              ↻ Random
            </button>
          </div>
          <input
            id="pa02-key"
            className={`pa01-hex-input${isKeyHexValid ? "" : " error"}`}
            value={keyHex}
            onChange={(e) => setKeyHex(e.target.value)}
            spellCheck={false}
            placeholder="e.g. a1b2c3d4e5f60718"
          />
        </div>

        <div className="pa02-control-card">
          <div className="pa01-control-label">
            <label htmlFor="pa02-depth">Tree depth n</label>
            <span className="pa01-slider-readout">
              {depth} bits → {Math.pow(2, depth)} leaves
            </span>
          </div>
          <input
            id="pa02-depth"
            type="range"
            min={4}
            max={8}
            value={depth}
            className="pa01-slider"
            onChange={(e) => handleDepth(Number(e.target.value))}
          />
          <div className="pa01-slider-ticks">
            {[4, 5, 6, 7, 8].map((v) => (
              <span key={v}>{v}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Query bit-toggle input ── */}
      <section className="pa02-query-section">
        <div className="pa02-query-label">
          Query x &nbsp;(click bits to flip — watch the path re-highlight)
        </div>
        <div className="pa02-bit-row">
          {queryBits.split("").map((bit, i) => (
            <button
              key={i}
              type="button"
              id={`pa02-bit-${i}`}
              className={`pa02-bit-btn ${bit === "1" ? "one" : "zero"}`}
              onClick={() => flipBit(i)}
              title={`b${i + 1} = ${bit} (click to flip)`}
            >
              {bit}
            </button>
          ))}
        </div>
        <div className="pa02-query-raw">
          x = <span className="mono pa02-query-bits">{queryBits}</span>
          <sub>2</sub>
        </div>
      </section>

      {/* ── Tree visualisation ── */}
      <section className="pa02-tree-section">
        <div className="pa02-section-header">
          <span className="pa01-output-title">
            GGM Tree (depth {depth}
            {!showFull && " · path view"})
          </span>
          <span className="pa01-output-meta">
            {showFull
              ? `${Math.pow(2, depth + 1) - 1} nodes · blue = active path`
              : "Full tree hidden for n > 4 — showing path only"}
          </span>
        </div>

        {isKeyHexValid ? (
          <>
            {showFull ? (
              <div className="pa02-svg-wrapper">
                <GGMTreeSVG nodes={nodes} depth={depth} />
              </div>
            ) : (
              <PathView nodes={nodes} queryBits={queryBits} />
            )}

            <div className="pa02-result-box">
              <span className="pa02-result-label">
                F<sub>k</sub>(x) =
              </span>
              <span className="pa02-result-hex mono">0x{leafHex}</span>
            </div>
          </>
        ) : (
          <div className="pa01-warn">Enter a valid hex key to see the GGM tree.</div>
        )}
      </section>

      {/* ── Avalanche (1-bit flip demo) ── */}
      <section className="pa02-avalanche-section">
        <div className="pa02-section-header">
          <span className="pa01-output-title">1-Bit Flip → Uncorrelated Output</span>
          <span className="pa01-output-meta">
            Flip each query bit; compare resulting leaf — PRF avalanche effect
          </span>
        </div>
        <div className="pa02-avalanche-grid">
          {avalanche.map((r) => (
            <div key={r.i} className={`pa02-avl-card${r.same ? " warn" : ""}`}>
              <div className="pa02-avl-head">
                Flip b<sub>{r.i + 1}</sub>: {r.orig} → {r.flip}
              </div>
              <div className="pa02-avl-row">
                <span className="pa02-avl-key">Original</span>
                <span className="mono pa02-avl-val">0x{leafHex}</span>
              </div>
              <div className="pa02-avl-row">
                <span className="pa02-avl-key">New</span>
                <span className="mono pa02-avl-val">0x{r.altHex}</span>
              </div>
              <div className={`pa02-avl-verdict ${r.same ? "same" : "changed"}`}>
                {r.same ? "✗ Unchanged (check params)" : "✓ Output changed"}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── PRG from PRF preview ── */}
      {prgPreview && (
        <section className="pa02-prg-section">
          <div className="pa02-section-header">
            <span className="pa01-output-title">PRG from PRF (PA#2b)</span>
            <span className="pa01-output-meta">
              G(k) = F_k(0ⁿ) ‖ F_k(1ⁿ)
            </span>
          </div>
          <div className="pa02-prg-row">
            <div className="pa02-prg-item">
              <span className="pa02-prg-label">G₀(k) = F_k(0ⁿ)</span>
              <span className="mono pa02-prg-val">0x{prgPreview.g0}</span>
            </div>
            <div className="pa02-prg-sep">‖</div>
            <div className="pa02-prg-item">
              <span className="pa02-prg-label">G₁(k) = F_k(1ⁿ)</span>
              <span className="mono pa02-prg-val">0x{prgPreview.g1}</span>
            </div>
          </div>
          <div className="pa02-prg-concat mono">
            G(k) = 0x{prgPreview.g0}{prgPreview.g1}
          </div>
        </section>
      )}

      {/* ── Theory grid ── */}
      <section className="pa01-theory-grid">
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">GGM Construction</div>
          <div className="pa01-formula">
            F_k(b₁…bₙ) = G_bₙ(…G_b₁(k)…)
          </div>
          <p className="pa01-theory-body">
            Split G(s) = G₀(s) ‖ G₁(s). Follow the left (0) or right (1)
            child at each level. Only one root-to-leaf path is computed per
            query — cost = n OWF calls.
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">Security (PRG ⇒ PRF)</div>
          <p className="pa01-theory-body">
            Any PPT adversary A making q queries: Adv<sub>PRF</sub>(A) ≤ q ·
            Adv<sub>PRG</sub>(B).
          </p>
          <p className="pa01-theory-body">
            Reduction: if A distinguishes F_k from a random oracle, then B
            simulates the GGM tree to break the PA#1 PRG.
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">PRG from PRF (PA#2b)</div>
          <div className="pa01-formula">G(s) = F_s(0ⁿ) ‖ F_s(1ⁿ)</div>
          <p className="pa01-theory-body">
            Backward direction: The PRF produces a length-doubling PRG.
            Statistical tests on the Python backend confirm pseudorandomness.
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">AES Plug-in (Python)</div>
          <p className="pa01-theory-body">
            The Python backend also provides F_k(x) = AES_k(x) as a drop-in — 
            a Cipher.evaluate() call bypassing the GGM construction. Both
            interfaces expose F(k, x) identically for PA#3–PA#5.
          </p>
        </div>
      </section>
    </div>
  );
}
