/**
 * PA#6 — CCA-Secure Encryption: Encrypt-then-MAC
 *
 * Interactive demo with two sub-tabs:
 *   1. Malleability Attack Panel — live bit-flip on CPA vs. CCA side-by-side
 *   2. IND-CCA2 Game — adversary advantage explorer
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CCAResult,
  CCA2GameState,
  ccaEncrypt,
  ccaDecrypt,
  decOracle,
  encOracle,
  flipBit,
  generateKeyPair,
  issueChallenge,
  newCCA2Game,
  submitGuess,
} from "./cca";
import { encryptText, decryptText, hexToBytes } from "./enc";
import { generateMacKey } from "./mac";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Pa06Tab = "malleability" | "cca2-game";

interface BitFlipState {
  /** Set of flipped bit indices (0 = MSB of byte 0) */
  flippedBits: Set<number>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexBinary(hex: string): string {
  return hexToBytes(hex)
    .reduce((s, b) => s + b.toString(2).padStart(8, "0"), "");
}

function randomKey(): string {
  return generateMacKey(); // 16-hex-char from mac.ts
}

// ---------------------------------------------------------------------------
// BitFlipGrid — interactive grid of bits
// ---------------------------------------------------------------------------

interface BitFlipGridProps {
  /** hex string representing the ciphertext body */
  ctHex: string;
  flippedBits: Set<number>;
  onToggleBit: (bitIndex: number) => void;
  /** If true, this is a read-only display (no clicking) */
  readOnly?: boolean;
}

function BitFlipGrid({ ctHex, flippedBits, onToggleBit, readOnly }: BitFlipGridProps) {
  const bits = useMemo(() => hexBinary(ctHex), [ctHex]);
  const totalBytes = Math.floor(bits.length / 8);

  // Show at most 8 bytes in the grid for clarity
  const displayBytes = Math.min(totalBytes, 8);

  return (
    <div className="pa06-bitgrid">
      <div className="pa06-bitgrid-legend">
        {Array.from({ length: 8 }, (_, i) => (
          <span key={i} className="pa06-bit-col-label">b{7 - i}</span>
        ))}
      </div>
      {Array.from({ length: displayBytes }, (_, byteIdx) => (
        <div key={byteIdx} className="pa06-byte-row">
          <span className="pa06-byte-label">B{byteIdx}</span>
          {Array.from({ length: 8 }, (_, bitInByte) => {
            const globalBitIdx = byteIdx * 8 + bitInByte;
            const bitVal = bits[globalBitIdx] ?? "0";
            const isFlipped = flippedBits.has(globalBitIdx);
            return (
              <button
                key={bitInByte}
                type="button"
                className={`pa06-bit${bitVal === "1" ? " one" : " zero"}${isFlipped ? " flipped" : ""}${readOnly ? " readonly" : ""}`}
                onMouseDown={readOnly ? undefined : () => onToggleBit(globalBitIdx)}
                title={readOnly ? `Bit ${globalBitIdx}: ${bitVal}` : `Click to flip bit ${globalBitIdx}`}
              >
                {bitVal}
              </button>
            );
          })}
        </div>
      ))}
      {totalBytes > 8 && (
        <div className="pa06-bitgrid-overflow">
          +{(totalBytes - 8) * 8} more bits in {totalBytes - 8} bytes (not shown)
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// MalleabilityPanel — the main deliverable
// ---------------------------------------------------------------------------

function MalleabilityPanel() {
  const [plaintext, setPlaintext] = useState("Hello, POIS!");
  const [cpaCTHex, setCpaCTHex] = useState("");
  const [cpaNonce, setCpaNonce] = useState(0);
  const [cpaKey, setCpaKey] = useState(() => randomKey());

  const [ccaResult, setCcaResult] = useState<CCAResult | null>(null);
  const [kEHex, setKEHex] = useState("");
  const [kMHex, setKMHex] = useState("");

  const [flipState, setFlipState] = useState<BitFlipState>({ flippedBits: new Set() });

  // Encrypt both sides when plaintext or keys change
  const encryptBothSides = useCallback(() => {
    if (!plaintext.trim()) return;

    // CPA side
    try {
      const { nonce, ctHex } = encryptText(cpaKey, plaintext);
      setCpaNonce(nonce);
      setCpaCTHex(ctHex);
    } catch {}

    // CCA side
    try {
      const result = ccaEncrypt(kEHex, kMHex, plaintext);
      setCcaResult(result);
    } catch {}

    setFlipState({ flippedBits: new Set() });
  }, [plaintext, cpaKey, kEHex, kMHex]);

  // Generate fresh keys on mount
  useEffect(() => {
    const { kEHex: kE, kMHex: kM } = generateKeyPair();
    const kCPA = randomKey();
    setKEHex(kE);
    setKMHex(kM);
    setCpaKey(kCPA);
  }, []);

  // Re-encrypt when keys are ready
  useEffect(() => {
    if (kEHex && kMHex && cpaKey) {
      encryptBothSides();
    }
  }, [kEHex, kMHex, cpaKey, encryptBothSides]);

  const regenerateKeys = useCallback(() => {
    const { kEHex: kE, kMHex: kM } = generateKeyPair();
    setKEHex(kE);
    setKMHex(kM);
    setCpaKey(randomKey());
  }, []);

  const toggleBit = useCallback((bitIndex: number) => {
    setFlipState((prev) => {
      const next = new Set(prev.flippedBits);
      if (next.has(bitIndex)) {
        next.delete(bitIndex);
      } else {
        next.add(bitIndex);
      }
      return { flippedBits: next };
    });
  }, []);

  const resetBits = useCallback(() => {
    setFlipState({ flippedBits: new Set() });
  }, []);

  // --- Compute CPA modified ciphertext and decrypted result ---
  const cpaModifiedCtHex = useMemo(() => {
    if (!cpaCTHex) return "";
    let result = cpaCTHex;
    for (const bit of flipState.flippedBits) {
      result = flipBit(result, bit);
    }
    return result;
  }, [cpaCTHex, flipState.flippedBits]);

  const cpaDecryptedOriginal = useMemo(() => {
    if (!cpaCTHex || !cpaKey) return "";
    try {
      return decryptText(cpaKey, cpaNonce, cpaCTHex);
    } catch {
      return "[decrypt error]";
    }
  }, [cpaCTHex, cpaKey, cpaNonce]);

  const cpaDecryptedModified = useMemo(() => {
    if (!cpaModifiedCtHex || !cpaKey) return "";
    try {
      return decryptText(cpaKey, cpaNonce, cpaModifiedCtHex);
    } catch {
      return "[decrypt error]";
    }
  }, [cpaModifiedCtHex, cpaKey, cpaNonce]);

  const cpaIsMalleable = flipState.flippedBits.size > 0 && cpaDecryptedModified !== cpaDecryptedOriginal;

  // --- Compute CCA modified ciphertext and decrypted result ---
  const ccaModifiedCtHex = useMemo(() => {
    if (!ccaResult) return "";
    let result = ccaResult.ctHex;
    for (const bit of flipState.flippedBits) {
      result = flipBit(result, bit);
    }
    return result;
  }, [ccaResult, flipState.flippedBits]);

  const ccaDecryptResult = useMemo((): string | null => {
    if (!ccaResult || !kEHex || !kMHex) return "";
    if (flipState.flippedBits.size === 0) {
      // No modification — should decrypt fine
      return ccaDecrypt(kEHex, kMHex, ccaResult.nonce, ccaResult.ctHex, ccaResult.tagHex);
    }
    // Modified — MAC should reject
    return ccaDecrypt(kEHex, kMHex, ccaResult.nonce, ccaModifiedCtHex, ccaResult.tagHex);
  }, [ccaResult, ccaModifiedCtHex, kEHex, kMHex, flipState.flippedBits]);

  const ccaMacRejected = flipState.flippedBits.size > 0 && ccaDecryptResult === null;

  const flippedCount = flipState.flippedBits.size;

  return (
    <div className="pa06-mal-shell">
      {/* Controls row */}
      <div className="pa06-mal-controls">
        <div className="pa06-control-card">
          <label htmlFor="pa06-plaintext" className="pa06-ctrl-label">Plaintext message</label>
          <div className="pa06-ctrl-row">
            <input
              id="pa06-plaintext"
              className="pa06-text-input"
              value={plaintext}
              onChange={(e) => setPlaintext(e.target.value)}
              placeholder="Type a message…"
              spellCheck={false}
            />
            <button
              type="button"
              id="pa06-encrypt-btn"
              className="pa06-primary-btn"
              onClick={encryptBothSides}
              disabled={!plaintext.trim()}
            >
              🔒 Encrypt
            </button>
          </div>
        </div>

        <div className="pa06-control-card">
          <div className="pa06-ctrl-label">Keys</div>
          <div className="pa06-key-row">
            <span className="pa06-key-chip">kE <code>{kEHex.slice(0, 8)}…</code></span>
            <span className="pa06-key-chip">kM <code>{kMHex.slice(0, 8)}…</code></span>
            <button type="button" className="pa06-ghost-btn" onClick={regenerateKeys} title="Regenerate keys">
              ↻ New Keys
            </button>
          </div>
          {kEHex === kMHex && (
            <div className="pa06-warn-badge">⚠ kE = kM — insecure! Regenerating…</div>
          )}
        </div>

        <div className="pa06-control-card pa06-flip-summary-card">
          <div className="pa06-ctrl-label">Bit flips active</div>
          <div className="pa06-flip-count-display">
            <span className="pa06-flip-count">{flippedCount}</span>
            <span className="pa06-flip-count-label">bit{flippedCount !== 1 ? "s" : ""} flipped</span>
          </div>
          {flippedCount > 0 && (
            <button type="button" className="pa06-ghost-btn" onClick={resetBits}>
              × Reset all flips
            </button>
          )}
        </div>
      </div>

      {/* Two-column layout */}
      {cpaCTHex && ccaResult && (
        <div className="pa06-mal-columns">
          {/* === LEFT: CPA-only === */}
          <section className="pa06-column pa06-col-cpa">
            <div className="pa06-col-header">
              <div className="pa06-col-scheme-badge cpa">CPA-only</div>
              <div className="pa06-col-title">PA #3 Stream Cipher</div>
              <div className="pa06-col-subtitle">No integrity protection</div>
            </div>

            <div className="pa06-ct-section">
              <div className="pa06-section-label">Ciphertext C = ⟨r, F_k(r) ⊕ m⟩</div>
              <div className="pa06-nonce-row">
                <span className="pa06-field-label">Nonce r</span>
                <span className="pa06-field-val">{cpaNonce} (0x{cpaNonce.toString(16).padStart(2,"0")})</span>
              </div>
              <div className="pa06-field-label">Ciphertext body (click bits to flip)</div>
              <BitFlipGrid
                ctHex={cpaCTHex}
                flippedBits={flipState.flippedBits}
                onToggleBit={toggleBit}
              />
              {flippedCount > 0 && (
                <div className="pa06-modified-ct">
                  <span className="pa06-field-label">Modified ct (hex)</span>
                  <code className="pa06-hex-code warn">{cpaModifiedCtHex}</code>
                </div>
              )}
            </div>

            <div className="pa06-decrypt-section">
              <div className="pa06-section-label">Decryption result</div>
              <div className="pa06-decrypt-row">
                <div className="pa06-decrypt-col">
                  <span className="pa06-field-label">Original plaintext</span>
                  <div className="pa06-plaintext-chip">{cpaDecryptedOriginal}</div>
                </div>
                {flippedCount > 0 && (
                  <div className="pa06-decrypt-col">
                    <span className="pa06-field-label">After bit-flip</span>
                    <div className={`pa06-plaintext-chip${cpaIsMalleable ? " corrupted" : ""}`}>
                      {cpaDecryptedModified}
                    </div>
                  </div>
                )}
              </div>
              {flippedCount > 0 && (
                <div className={`pa06-verdict-banner${cpaIsMalleable ? " malleable" : ""}`}>
                  {cpaIsMalleable
                    ? "⚠ MALLEABLE — plaintext corrupted without knowing k!"
                    : "✓ Plaintext unchanged (flipped bits are in padding)"}
                </div>
              )}
            </div>

            <div className="pa06-theory-note">
              <strong>Why it's malleable:</strong> C = ⟨r, F_k(r)⊕m⟩. Flipping bit i
              of ct flips bit i of m⊕F_k(r), so Dec yields m with bit i flipped.
              No authentication ⇒ any tampering goes undetected.
            </div>
          </section>

          {/* === RIGHT: CCA / Encrypt-then-MAC === */}
          <section className="pa06-column pa06-col-cca">
            <div className="pa06-col-header">
              <div className="pa06-col-scheme-badge cca">CCA / Enc-then-MAC</div>
              <div className="pa06-col-title">PA #6 Encrypt-then-MAC</div>
              <div className="pa06-col-subtitle">MAC verification before decryption</div>
            </div>

            <div className="pa06-ct-section">
              <div className="pa06-section-label">Ciphertext C = ⟨r, ct⟩  +  tag t</div>
              <div className="pa06-nonce-row">
                <span className="pa06-field-label">Nonce r</span>
                <span className="pa06-field-val">{ccaResult.nonce} (0x{ccaResult.nonce.toString(16).padStart(2,"0")})</span>
              </div>
              <div className="pa06-tag-row">
                <span className="pa06-field-label">MAC tag t</span>
                <code className="pa06-tag-chip">{ccaResult.tagHex}</code>
              </div>
              <div className="pa06-field-label">Ciphertext body (click bits to flip — same grid as left)</div>
              <BitFlipGrid
                ctHex={ccaResult.ctHex}
                flippedBits={flipState.flippedBits}
                onToggleBit={toggleBit}
              />
              {flippedCount > 0 && (
                <div className="pa06-modified-ct">
                  <span className="pa06-field-label">Modified ct (hex)</span>
                  <code className="pa06-hex-code warn">{ccaModifiedCtHex}</code>
                </div>
              )}
            </div>

            <div className="pa06-decrypt-section">
              <div className="pa06-section-label">CCA Decryption result</div>

              {flippedCount === 0 ? (
                <div className="pa06-decrypt-row">
                  <div className="pa06-decrypt-col">
                    <span className="pa06-field-label">Plaintext (no modification)</span>
                    <div className="pa06-plaintext-chip">{ccaDecryptResult ?? "[null]"}</div>
                  </div>
                </div>
              ) : (
                <>
                  <div className="pa06-vrfy-steps">
                    <div className="pa06-step-row">
                      <span className="pa06-step-num">1</span>
                      <span className="pa06-step-desc">Compute MAC input: 0x00 ‖ nonce_byte ‖ modified_ct</span>
                    </div>
                    <div className="pa06-step-row">
                      <span className="pa06-step-num">2</span>
                      <span className="pa06-step-desc">Vrfy_kM(mac_input, t) → <strong className={ccaMacRejected ? "pa06-reject-text" : "pa06-accept-text"}>{ccaMacRejected ? "FALSE" : "TRUE"}</strong></span>
                    </div>
                    {ccaMacRejected && (
                      <div className="pa06-step-row rejected">
                        <span className="pa06-step-num">⊥</span>
                        <span className="pa06-step-desc">MAC verification FAILED — decryption aborted, plaintext never exposed</span>
                      </div>
                    )}
                    {!ccaMacRejected && (
                      <div className="pa06-step-row">
                        <span className="pa06-step-num">3</span>
                        <span className="pa06-step-desc">Dec_kE(r, ct) → plaintext</span>
                      </div>
                    )}
                  </div>

                  <div className={`pa06-verdict-banner${ccaMacRejected ? " rejected" : " accepted"}`}>
                    {ccaMacRejected
                      ? "🛡 CCA SECURE — MAC rejected ⊥, attack detected!"
                      : "✓ MAC verified (unmodified path)"}
                  </div>

                  {ccaMacRejected && (
                    <div className="pa06-perp-display">
                      <span className="pa06-perp-symbol">⊥</span>
                      <span className="pa06-perp-label">Returns ⊥ (rejection symbol)</span>
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="pa06-theory-note cca">
              <strong>Why it's secure:</strong> The tag t = MAC_kM(0x00‖r‖ct) binds both
              the nonce and the ciphertext body. Any modification invalidates the MAC.
              Vrfy is called BEFORE Dec — the plaintext is never decrypted on tampered ciphertexts.
            </div>
          </section>
        </div>
      )}

      {!cpaCTHex && (
        <div className="pa06-empty-state">
          <div className="pa06-empty-icon">🔐</div>
          <div className="pa06-empty-text">Enter a message and click Encrypt to begin the demo</div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// IND-CCA2 Game Panel
// ---------------------------------------------------------------------------

interface CCA2Stat {
  round: number;
  bPrime: number;
  b: number;
  correct: boolean;
  advantage: number;
}

function CCA2GamePanel() {
  const [game, setGame] = useState<CCA2GameState>(() => newCCA2Game());
  const [m0, setM0] = useState("hello-world!");
  const [m1, setM1] = useState("goodbye-wrld");
  const [challengeResult, setChallengeResult] = useState<CCAResult | null>(null);
  const [stats, setStats] = useState<CCA2Stat[]>([]);
  const [encQuery, setEncQuery] = useState("");
  const [encQueryResult, setEncQueryResult] = useState<CCAResult | null>(null);
  const [decQuery, setDecQuery] = useState<{ nonce: string; ctHex: string; tagHex: string }>({ nonce: "", ctHex: "", tagHex: "" });
  const [decQueryResult, setDecQueryResult] = useState<string | null | undefined>(undefined);
  const [isRunning, setIsRunning] = useState(false);

  const currentAdvantage = stats.length > 0 ? stats[stats.length - 1].advantage : 0;
  const wins = stats.filter((s) => s.correct).length;

  const resetGame = useCallback(() => {
    setGame(newCCA2Game());
    setChallengeResult(null);
    setStats([]);
    setEncQueryResult(null);
    setDecQueryResult(undefined);
  }, []);

  const getChallenge = useCallback(() => {
    if (!m0 || !m1 || m0.length !== m1.length) return;
    const result = issueChallenge(game, m0, m1);
    setChallengeResult(result);
  }, [game, m0, m1]);

  const makeGuess = useCallback((bPrime: number) => {
    const result = submitGuess(game, bPrime);
    setGame({ ...game }); // trigger re-render with updated state
    setStats((prev) => [
      ...prev,
      {
        round: result.rounds,
        bPrime,
        b: result.b,
        correct: result.correct,
        advantage: result.advantage,
      },
    ]);
    setChallengeResult(null);
  }, [game]);

  const runAutoSim = useCallback(async (rounds: number) => {
    setIsRunning(true);
    const freshGame = newCCA2Game();
    setGame(freshGame);
    const newStats: CCA2Stat[] = [];

    for (let i = 0; i < rounds; i++) {
      issueChallenge(freshGame, m0, m1);
      const bPrime = Math.random() < 0.5 ? 0 : 1;
      const result = submitGuess(freshGame, bPrime);
      newStats.push({
        round: result.rounds,
        bPrime,
        b: result.b,
        correct: result.correct,
        advantage: result.advantage,
      });
      // Tiny yield to keep UI breathing
      if (i % 10 === 9) {
        setStats([...newStats]);
        await new Promise((r) => setTimeout(r, 0));
      }
    }
    setStats([...newStats]);
    setChallengeResult(null);
    setIsRunning(false);
  }, [m0, m1]);

  const queryEnc = useCallback(() => {
    if (!encQuery.trim()) return;
    const result = encOracle(game, encQuery.trim());
    setEncQueryResult(result);
  }, [game, encQuery]);

  const queryDec = useCallback(() => {
    const nonce = parseInt(decQuery.nonce, 10);
    if (isNaN(nonce) || !decQuery.ctHex || !decQuery.tagHex) return;
    const result = decOracle(game, nonce, decQuery.ctHex.trim(), decQuery.tagHex.trim());
    setDecQueryResult(result);
  }, [game, decQuery]);

  const lastFewStats = stats.slice(-8);

  return (
    <div className="pa06-cca2-shell">
      <div className="pa06-cca2-desc">
        <p>
          The IND-CCA2 game gives the adversary both an{" "}
          <strong>encryption oracle</strong> and a{" "}
          <strong>decryption oracle</strong> (which rejects the challenge
          ciphertext). A random adversary should achieve advantage ≈ 0.
        </p>
      </div>

      {/* Game setup */}
      <div className="pa06-cca2-setup">
        <div className="pa06-control-card">
          <label className="pa06-ctrl-label">Message pair (must be same length)</label>
          <div className="pa06-msg-row">
            <div className="pa06-msg-field">
              <label htmlFor="pa06-m0">m₀</label>
              <input
                id="pa06-m0"
                className="pa06-text-input"
                value={m0}
                onChange={(e) => setM0(e.target.value)}
              />
            </div>
            <div className="pa06-msg-field">
              <label htmlFor="pa06-m1">m₁</label>
              <input
                id="pa06-m1"
                className="pa06-text-input"
                value={m1}
                onChange={(e) => setM1(e.target.value)}
              />
            </div>
          </div>
          {m0.length !== m1.length && (
            <div className="pa06-warn-badge">⚠ Messages must have equal length ({m0.length} vs {m1.length})</div>
          )}
        </div>

        <div className="pa06-cca2-score-card">
          <div className="pa06-cca2-score-row">
            <div className="pa06-cca2-score-item">
              <span className="pa06-cca2-score-val">{stats.length}</span>
              <span className="pa06-cca2-score-lbl">Rounds</span>
            </div>
            <div className="pa06-cca2-score-item">
              <span className="pa06-cca2-score-val">{wins}</span>
              <span className="pa06-cca2-score-lbl">Wins</span>
            </div>
            <div className="pa06-cca2-score-item">
              <span className={`pa06-cca2-score-val${currentAdvantage < 0.15 ? " green" : " amber"}`}>
                {currentAdvantage.toFixed(4)}
              </span>
              <span className="pa06-cca2-score-lbl">Advantage</span>
            </div>
          </div>
          {stats.length >= 20 && (
            <div className={`pa06-verdict-banner${currentAdvantage < 0.15 ? " accepted" : " malleable"}`}>
              {currentAdvantage < 0.15
                ? "✓ Advantage ≈ 0 — IND-CCA2 SECURE"
                : "⚠ High advantage — check scheme"}
            </div>
          )}
        </div>
      </div>

      {/* Oracle playgrounds */}
      <div className="pa06-oracle-row">
        <section className="pa06-oracle-card">
          <div className="pa06-oracle-title">🔐 Encryption Oracle</div>
          <div className="pa06-oracle-inputs">
            <input
              className="pa06-text-input"
              value={encQuery}
              onChange={(e) => setEncQuery(e.target.value)}
              placeholder="Message to encrypt…"
              spellCheck={false}
            />
            <button type="button" className="pa06-primary-btn" onClick={queryEnc} disabled={!encQuery.trim()}>
              Query
            </button>
          </div>
          {encQueryResult && (
            <div className="pa06-oracle-result">
              <div><span className="pa06-field-label">nonce</span> {encQueryResult.nonce}</div>
              <div><span className="pa06-field-label">ct</span> <code className="pa06-mono-sm">{encQueryResult.ctHex.slice(0, 24)}…</code></div>
              <div><span className="pa06-field-label">tag</span> <code className="pa06-mono-sm">{encQueryResult.tagHex}</code></div>
            </div>
          )}
        </section>

        <section className="pa06-oracle-card">
          <div className="pa06-oracle-title">🔓 Decryption Oracle <span className="pa06-oracle-note">(rejects challenge ct)</span></div>
          <div className="pa06-oracle-inputs dec">
            <input className="pa06-text-input" value={decQuery.nonce} onChange={(e) => setDecQuery((d) => ({ ...d, nonce: e.target.value }))} placeholder="nonce (int)…" spellCheck={false} style={{ width: "5rem" }} />
            <input className="pa06-text-input" value={decQuery.ctHex} onChange={(e) => setDecQuery((d) => ({ ...d, ctHex: e.target.value }))} placeholder="ctHex…" spellCheck={false} />
            <input className="pa06-text-input" value={decQuery.tagHex} onChange={(e) => setDecQuery((d) => ({ ...d, tagHex: e.target.value }))} placeholder="tagHex (16 hex)…" spellCheck={false} style={{ width: "9rem" }} />
            <button type="button" className="pa06-primary-btn" onClick={queryDec}>
              Query
            </button>
          </div>
          {decQueryResult !== undefined && (
            <div className={`pa06-oracle-result${decQueryResult === null ? " rejected" : ""}`}>
              {decQueryResult === null
                ? "⊥  (MAC rejected or challenge ciphertext)"
                : `Plaintext: "${decQueryResult}"`}
            </div>
          )}
        </section>
      </div>

      {/* Manual game */}
      <div className="pa06-manual-game">
        <div className="pa06-game-actions">
          <button
            type="button"
            id="pa06-get-challenge"
            className="pa06-primary-btn"
            onClick={getChallenge}
            disabled={m0.length !== m1.length || !!challengeResult || isRunning}
          >
            🎲 Get Challenge
          </button>
          <button
            type="button"
            id="pa06-guess-0"
            className="pa06-ghost-btn"
            onClick={() => makeGuess(0)}
            disabled={!challengeResult || isRunning}
          >
            Guess b′=0 (m₀)
          </button>
          <button
            type="button"
            id="pa06-guess-1"
            className="pa06-ghost-btn"
            onClick={() => makeGuess(1)}
            disabled={!challengeResult || isRunning}
          >
            Guess b′=1 (m₁)
          </button>
          <button type="button" className="pa06-ghost-btn" onClick={resetGame} disabled={isRunning}>
            ↻ New Game
          </button>
        </div>

        {challengeResult && (
          <div className="pa06-challenge-display">
            <div className="pa06-section-label">Challenge ciphertext (c*, t*)</div>
            <div><span className="pa06-field-label">nonce</span> {challengeResult.nonce}</div>
            <div><span className="pa06-field-label">ct</span> <code className="pa06-mono-sm">{challengeResult.ctHex.slice(0, 32)}…</code></div>
            <div><span className="pa06-field-label">tag</span> <code className="pa06-mono-sm">{challengeResult.tagHex}</code></div>
            <div className="pa06-challenge-note">Which plaintext (m₀ or m₁) did the challenger encrypt?</div>
          </div>
        )}

        {/* Last few rounds */}
        {stats.length > 0 && (
          <div className="pa06-rounds-list">
            {lastFewStats.map((s) => (
              <div key={s.round} className={`pa06-round-row${s.correct ? " correct" : " wrong"}`}>
                <span>Round {s.round}</span>
                <span>b={s.b}</span>
                <span>b′={s.bPrime}</span>
                <span>{s.correct ? "✓" : "✗"}</span>
                <span>Adv={s.advantage.toFixed(3)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Auto-simulate */}
      <div className="pa06-sim-row">
        <button
          type="button"
          id="pa06-sim-50"
          className="pa06-primary-btn"
          onClick={() => runAutoSim(50)}
          disabled={isRunning || m0.length !== m1.length}
        >
          ⚡ Simulate 50 rounds
        </button>
        <button
          type="button"
          id="pa06-sim-200"
          className="pa06-ghost-btn"
          onClick={() => runAutoSim(200)}
          disabled={isRunning || m0.length !== m1.length}
        >
          Simulate 200 rounds
        </button>
        {isRunning && <span className="pa06-running">Running…</span>}
      </div>

      <div className="pa06-theory-note">
        <strong>Theorem (Enc-then-MAC → IND-CCA2):</strong> If the CPA scheme is
        IND-CPA secure and the MAC is EUF-CMA secure under independently sampled keys,
        then the Encrypt-then-MAC scheme is IND-CCA2 secure.
        Adv<sub>CCA2</sub>(A) ≤ Adv<sub>CPA</sub>(B) + Adv<sub>MAC</sub>(F).
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main PA06 Panel
// ---------------------------------------------------------------------------

export default function Pa06Panel() {
  const [tab, setTab] = useState<Pa06Tab>("malleability");

  return (
    <div className="pa06-shell">
      {/* Hero */}
      <section className="pa06-hero">
        <div className="pa06-hero-badge">PA #6</div>
        <h2 className="pa06-hero-title">CCA-Secure Encryption</h2>
        <p className="pa06-hero-sub">
          Encrypt-then-MAC · Key Separation · IND-CCA2 Game · Malleability Attack Demo
        </p>
        <div className="pa06-hero-pills">
          <span>CCA_Enc(kE, kM, m) → (c, t)</span>
          <span>CCA_Dec verifies MAC first</span>
          <span>Bit-flip → ⊥ on CCA side</span>
          <span>Bit-flip → corrupted pt on CPA side</span>
        </div>
      </section>

      {/* Sub-tabs */}
      <div className="pa06-subtabs">
        <button
          id="pa06-tab-malleability"
          type="button"
          className={`pa06-subtab-btn${tab === "malleability" ? " active" : ""}`}
          onClick={() => setTab("malleability")}
        >
          ⚡ Malleability Attack
        </button>
        <button
          id="pa06-tab-cca2"
          type="button"
          className={`pa06-subtab-btn${tab === "cca2-game" ? " active" : ""}`}
          onClick={() => setTab("cca2-game")}
        >
          🎲 IND-CCA2 Game
        </button>
      </div>

      {tab === "malleability" ? <MalleabilityPanel /> : <CCA2GamePanel />}
    </div>
  );
}
