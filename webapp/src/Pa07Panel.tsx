/**
 * PA#7 — Merkle-Damgård Transform Interactive Panel
 *
 * Two tabs:
 *   1. Chain Viewer — animated MD chain; click any block to edit it
 *   2. Collision Demo — shows compression collision propagating to MD collision
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  BLOCK_SIZE,
  DIGEST_SIZE,
  IV_HEX,
  MDBlock,
  MDTrace,
  collisionDemo,
  computeMDTrace,
} from "./merkle";

// ---------------------------------------------------------------------------
// ChainBlock — single animated block in the chain
// ---------------------------------------------------------------------------

interface ChainBlockProps {
  block: MDBlock;
  isSelected: boolean;
  editHex: string;
  onSelect: () => void;
  onEditChange: (v: string) => void;
  onEditCommit: () => void;
  animDelay: number;
  highlighted?: boolean;
}

function ChainBlock({
  block,
  isSelected,
  editHex,
  onSelect,
  onEditChange,
  onEditCommit,
  animDelay,
  highlighted,
}: ChainBlockProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isSelected && inputRef.current) inputRef.current.focus();
  }, [isSelected]);

  return (
    <div
      className="pa07-chain-step"
      style={{ animationDelay: `${animDelay}ms` }}
    >
      {/* State-in bubble */}
      <div className="pa07-state-bubble">
        <span className="pa07-state-label">z{block.index}</span>
        <code className="pa07-state-val">{block.stateInHex}</code>
      </div>

      {/* Arrow down */}
      <div className="pa07-chain-arrow">↓</div>

      {/* Compression box */}
      <div
        className={`pa07-compress-box${highlighted ? " highlighted" : ""}${block.isPaddingBlock ? " padding-block" : ""}${block.isEdited ? " edited" : ""}`}
        onClick={onSelect}
        title="Click to edit this block"
      >
        <div className="pa07-compress-label">
          h(z{block.index}, M{block.index + 1})
          {block.isPaddingBlock && <span className="pa07-pad-badge">pad+len</span>}
        </div>

        {isSelected ? (
          <input
            ref={inputRef}
            className="pa07-block-input"
            value={editHex}
            onChange={(e) => onEditChange(e.target.value.toLowerCase())}
            onBlur={onEditCommit}
            onKeyDown={(e) => e.key === "Enter" && onEditCommit()}
            maxLength={16}
            spellCheck={false}
            placeholder="8-byte hex…"
            onClick={(e) => e.stopPropagation()}
          />
        ) : (
          <code className="pa07-block-hex">
            {block.hex.slice(0, 8)}
            <span className="pa07-block-hex-sep">|</span>
            {block.hex.slice(8)}
          </code>
        )}
        {block.isEdited && (
          <div className="pa07-edited-badge">✏ edited</div>
        )}
      </div>

      {/* Arrow down */}
      <div className="pa07-chain-arrow">↓</div>

      {/* State-out bubble */}
      <div className={`pa07-state-bubble out${highlighted ? " highlighted" : ""}`}>
        <span className="pa07-state-label">z{block.index + 1}</span>
        <code className="pa07-state-val">{block.stateOutHex}</code>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ChainViewer tab
// ---------------------------------------------------------------------------

function ChainViewer() {
  const [message, setMessage] = useState("Hello POIS!");
  const [selectedBlock, setSelectedBlock] = useState<number | null>(null);
  const [editHex, setEditHex] = useState("");
  const [editedBlocks, setEditedBlocks] = useState<Map<number, string>>(new Map());
  const [animKey, setAnimKey] = useState(0);

  const trace = useMemo(
    () => computeMDTrace(message, editedBlocks),
    [message, editedBlocks],
  );

  // Which blocks changed after an edit (for avalanche highlight)
  const baseTrace = useMemo(() => computeMDTrace(message), [message]);

  const avalancheFrom = useMemo(() => {
    if (editedBlocks.size === 0) return -1;
    return Math.min(...editedBlocks.keys());
  }, [editedBlocks]);

  const handleMessageChange = useCallback((msg: string) => {
    setMessage(msg);
    setEditedBlocks(new Map());
    setSelectedBlock(null);
    setAnimKey((k) => k + 1);
  }, []);

  const handleSelect = useCallback(
    (idx: number, currentHex: string) => {
      setSelectedBlock(idx);
      setEditHex(currentHex);
    },
    [],
  );

  const handleEditCommit = useCallback(() => {
    if (selectedBlock === null) return;
    const hex = editHex.replace(/[^0-9a-f]/g, "").padEnd(16, "0").slice(0, 16);
    setEditedBlocks((prev) => {
      const next = new Map(prev);
      next.set(selectedBlock, hex);
      return next;
    });
    setSelectedBlock(null);
  }, [selectedBlock, editHex]);

  const resetEdits = useCallback(() => {
    setEditedBlocks(new Map());
    setSelectedBlock(null);
    setAnimKey((k) => k + 1);
  }, []);

  return (
    <div className="pa07-viewer-shell">
      {/* Controls */}
      <div className="pa07-controls">
        <div className="pa07-control-card wide" style={{ flex: 2 }}>
          <label htmlFor="pa07-msg" className="pa07-ctrl-label">Message</label>
          <div className="pa07-ctrl-row">
            <input
              id="pa07-msg"
              className="pa07-text-input"
              value={message}
              onChange={(e) => handleMessageChange(e.target.value)}
              placeholder="Type any message…"
              spellCheck={false}
            />
            {editedBlocks.size > 0 && (
              <button type="button" className="pa07-ghost-btn" onClick={resetEdits}>
                × Reset edits
              </button>
            )}
          </div>
        </div>

        <div className="pa07-control-card" style={{ minWidth: 200 }}>
          <div className="pa07-ctrl-label">Parameters</div>
          <div className="pa07-param-grid">
            <span className="pa07-param-item">block_size = {BLOCK_SIZE} B</span>
            <span className="pa07-param-item">digest_size = {DIGEST_SIZE} B</span>
            <span className="pa07-param-item">IV = <code>{IV_HEX}</code></span>
            <span className="pa07-param-item">{trace.blocks.length} blocks after pad</span>
          </div>
        </div>
      </div>

      {/* Padding display */}
      <div className="pa07-pad-strip">
        <span className="pa07-pad-label">Padded message (hex)</span>
        <div className="pa07-pad-bytes">
          {/* Colour-coded: message / 0x80 / zeros / length-field */}
          {(() => {
            const msgLen = new TextEncoder().encode(message).length;
            const padded = trace.paddedHex;
            const msgHex = padded.slice(0, msgLen * 2);
            const rest = padded.slice(msgLen * 2);
            const sepIdx = rest.indexOf("80") === 0 ? 2 : 0;
            const zeroAndLen = rest.slice(sepIdx + 2);
            const lenPart = zeroAndLen.slice(-16); // last 8 bytes = 16 hex
            const zeroPart = zeroAndLen.slice(0, -16);
            return (
              <>
                <code className="pa07-padchunk msg" title="Message">{msgHex}</code>
                <code className="pa07-padchunk sep" title="0x80 separator">80</code>
                {zeroPart && <code className="pa07-padchunk zeros" title="Zero padding">{zeroPart}</code>}
                <code className="pa07-padchunk lenfield" title="64-bit bit-length">{lenPart}</code>
              </>
            );
          })()}
        </div>
        <div className="pa07-pad-legend">
          <span className="pa07-leg msg">message</span>
          <span className="pa07-leg sep">0x80</span>
          <span className="pa07-leg zeros">zero pad</span>
          <span className="pa07-leg lenfield">bit-length</span>
        </div>
      </div>

      {/* Chain */}
      <div className="pa07-chain-scroll">
        <div className="pa07-chain-row" key={animKey}>
          {trace.blocks.map((block, i) => (
            <ChainBlock
              key={i}
              block={block}
              isSelected={selectedBlock === i}
              editHex={selectedBlock === i ? editHex : block.hex}
              onSelect={() => handleSelect(i, block.hex)}
              onEditChange={setEditHex}
              onEditCommit={handleEditCommit}
              animDelay={i * 80}
              highlighted={i >= avalancheFrom && avalancheFrom >= 0 &&
                trace.blocks[i].stateOutHex !== baseTrace.blocks[i]?.stateOutHex}
            />
          ))}
        </div>
      </div>

      {/* Final digest */}
      <div className="pa07-digest-row">
        <span className="pa07-digest-label">H(M) =</span>
        <code className={`pa07-digest-val${editedBlocks.size > 0 && trace.digestHex !== baseTrace.digestHex ? " changed" : ""}`}>
          {trace.digestHex}
        </code>
        {editedBlocks.size > 0 && trace.digestHex !== baseTrace.digestHex && (
          <span className="pa07-digest-badge">⚡ Avalanche — digest changed</span>
        )}
      </div>

      {editedBlocks.size > 0 && (
        <div className="pa07-theory-note">
          <strong>Avalanche effect:</strong> Editing block M{Math.min(...editedBlocks.keys()) + 1} re-computes
          the chain from z{Math.min(...editedBlocks.keys()) + 1} onwards — all subsequent chaining values and the final
          digest change. Highlighted blocks show where the chain diverges.
        </div>
      )}

      <div className="pa07-theory-note">
        <strong>MD-strengthening padding:</strong> M ‖ 0x80 ‖ 0* ‖ ⟨|M|⟩₆₄.
        The length field ensures distinct message lengths produce structurally different paddings,
        preventing trivial length-extension issues at the padding level.
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Collision Demo tab
// ---------------------------------------------------------------------------

function CollisionDemoPanel() {
  const demo = useMemo(() => collisionDemo(), []);

  const [showTrace1, setShowTrace1] = useState(false);
  const [showTrace2, setShowTrace2] = useState(false);

  const trace1 = useMemo(
    () => computeMDTrace(String.fromCharCode(...hexToUint8(demo.m1Hex))),
    [demo.m1Hex],
  );
  const trace2 = useMemo(
    () => computeMDTrace(String.fromCharCode(...hexToUint8(demo.m2Hex))),
    [demo.m2Hex],
  );

  return (
    <div className="pa07-collision-shell">
      <div className="pa07-collision-desc">
        <p>
          We construct two 8-byte messages m₁ ≠ m₂ such that
          h<sub>toy</sub>(IV, m₁) = h<sub>toy</sub>(IV, m₂). The <strong>same
          padding block</strong> is appended to both (equal lengths). Therefore
          the full MD hashes also collide — witnessing the reduction:
          <em> collision in h ⇒ collision in H_MD</em>.
        </p>
      </div>

      {/* Two messages */}
      <div className="pa07-col-pair">
        <div className="pa07-col-card m1">
          <div className="pa07-col-card-badge">m₁</div>
          <div className="pa07-col-card-rows">
            <div><span className="pa07-field-label">bytes (hex)</span>
              <code className="pa07-col-hex">{demo.m1Hex}</code>
            </div>
            <div><span className="pa07-field-label">left half</span>
              <code className="pa07-col-hex">{demo.m1Hex.slice(0, 8)}</code>
            </div>
            <div><span className="pa07-field-label">right half</span>
              <code className="pa07-col-hex">{demo.m1Hex.slice(8)}</code>
            </div>
            <div><span className="pa07-field-label">h_toy(IV, m₁)</span>
              <code className="pa07-col-hex">{demo.collisionStateHex}</code>
            </div>
          </div>
          <button type="button" className="pa07-ghost-btn"
            onClick={() => setShowTrace1((v) => !v)}>
            {showTrace1 ? "Hide" : "Show"} MD trace
          </button>
          {showTrace1 && (
            <MiniTrace trace={trace1} />
          )}
        </div>

        <div className="pa07-col-eq">
          <div className="pa07-eq-symbol">⊕Δ</div>
          <div className="pa07-eq-label">Δ = {demo.m2Hex.slice(0, 8).padStart(8)}</div>
        </div>

        <div className="pa07-col-card m2">
          <div className="pa07-col-card-badge">m₂</div>
          <div className="pa07-col-card-rows">
            <div><span className="pa07-field-label">bytes (hex)</span>
              <code className="pa07-col-hex">{demo.m2Hex}</code>
            </div>
            <div><span className="pa07-field-label">left half</span>
              <code className="pa07-col-hex">{demo.m2Hex.slice(0, 8)}</code>
            </div>
            <div><span className="pa07-field-label">right half</span>
              <code className="pa07-col-hex">{demo.m2Hex.slice(8)}</code>
            </div>
            <div><span className="pa07-field-label">h_toy(IV, m₂)</span>
              <code className="pa07-col-hex">{demo.collisionStateHex}</code>
            </div>
          </div>
          <button type="button" className="pa07-ghost-btn"
            onClick={() => setShowTrace2((v) => !v)}>
            {showTrace2 ? "Hide" : "Show"} MD trace
          </button>
          {showTrace2 && (
            <MiniTrace trace={trace2} />
          )}
        </div>
      </div>

      {/* Verdict */}
      <div className={`pa07-col-verdict${demo.propagated ? " propagated" : " failed"}`}>
        <div className="pa07-col-verdict-title">
          {demo.propagated ? "✓ COLLISION PROPAGATED" : "✗ No collision"}
        </div>
        <div className="pa07-col-verdict-rows">
          <div>
            <span className="pa07-field-label">H_MD(m₁)</span>
            <code className="pa07-col-hex">{demo.m1DigestHex}</code>
          </div>
          <div>
            <span className="pa07-field-label">H_MD(m₂)</span>
            <code className="pa07-col-hex">{demo.m2DigestHex}</code>
          </div>
          <div>
            <span className="pa07-field-label">m₁ ≠ m₂?</span>
            <code className="pa07-col-hex">{demo.m1Hex !== demo.m2Hex ? "Yes ✓" : "No —"}</code>
          </div>
          <div>
            <span className="pa07-field-label">H(m₁) = H(m₂)?</span>
            <code className="pa07-col-hex">{demo.propagated ? "Yes ✓" : "No"}</code>
          </div>
        </div>
      </div>

      <div className="pa07-theory-note">
        {demo.explanation}
      </div>

      <div className="pa07-theory-note">
        <strong>Theorem (MD collision resistance):</strong> If h is collision-resistant,
        then H_MD is collision-resistant. Proof: any collision M ≠ M′ with H(M) = H(M′)
        implies a collision in h — trace back through the chain until two inputs to h
        differ but produce the same output. Our toy XOR compression intentionally has
        collisions; this demo concretely witnesses the reduction.
      </div>
    </div>
  );
}

// Mini trace for collision demo
function MiniTrace({ trace }: { trace: MDTrace }) {
  return (
    <div className="pa07-mini-trace">
      <div className="pa07-mini-trace-row">
        <span className="pa07-mini-label">IV</span>
        <code className="pa07-mini-val">{trace.ivHex}</code>
      </div>
      {trace.blocks.map((b, i) => (
        <div key={i} className="pa07-mini-trace-row">
          <span className="pa07-mini-label">M{i + 1}</span>
          <code className="pa07-mini-val">{b.hex.slice(0, 8)}|{b.hex.slice(8)}</code>
          <span className="pa07-mini-arrow">→</span>
          <code className={`pa07-mini-val out`}>{b.stateOutHex}</code>
        </div>
      ))}
      <div className="pa07-mini-trace-row digest">
        <span className="pa07-mini-label">digest</span>
        <code className="pa07-mini-val">{trace.digestHex}</code>
      </div>
    </div>
  );
}

function hexToUint8(hex: string): number[] {
  const h = hex.length % 2 ? "0" + hex : hex;
  return (h.match(/../g) ?? []).map((b) => parseInt(b, 16));
}

// ---------------------------------------------------------------------------
// Main PA07 Panel
// ---------------------------------------------------------------------------

type PA07Tab = "chain" | "collision";

export default function Pa07Panel() {
  const [tab, setTab] = useState<PA07Tab>("chain");

  return (
    <div className="pa07-shell">
      {/* Hero */}
      <section className="pa07-hero">
        <div className="pa07-hero-badge">PA #7</div>
        <h2 className="pa07-hero-title">Merkle-Damgård Transform</h2>
        <p className="pa07-hero-sub">
          Domain extension · MD-strengthening padding · Animated chain viewer · Collision propagation
        </p>
        <div className="pa07-hero-pills">
          <span>h : {'{0,1}'}<sup>n+b</sup> → {'{0,1}'}<sup>n</sup></span>
          <span>block_size = 8 B</span>
          <span>digest = 4 B</span>
          <span>IV = 00000000</span>
          <span>Edit any block → avalanche</span>
        </div>
      </section>

      {/* Tabs */}
      <div className="pa07-subtabs">
        <button
          id="pa07-tab-chain"
          type="button"
          className={`pa07-subtab-btn${tab === "chain" ? " active" : ""}`}
          onClick={() => setTab("chain")}
        >
          ⛓ Chain Viewer
        </button>
        <button
          id="pa07-tab-collision"
          type="button"
          className={`pa07-subtab-btn${tab === "collision" ? " active" : ""}`}
          onClick={() => setTab("collision")}
        >
          💥 Collision Demo
        </button>
      </div>

      {tab === "chain" ? <ChainViewer /> : <CollisionDemoPanel />}
    </div>
  );
}
