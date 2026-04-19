import { useMemo, useState, useCallback } from "react";
import { encryptText, decryptText, xorHex, textToHex } from "./enc";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Phase = "setup" | "challenge" | "guessing" | "revealed";

interface RoundResult {
  roundNum: number;
  b: 0 | 1;
  bGuess: 0 | 1;
  correct: boolean;
  nonce: number;
  ctHex: string;
  reuseNonce: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function randomKeyHex(): string {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function advantage(results: RoundResult[]): number {
  if (!results.length) return 0;
  const wins = results.filter((r) => r.correct).length;
  return 2.0 * Math.abs(wins / results.length - 0.5);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------
function AdvantageBar({ results }: { results: RoundResult[] }) {
  const adv = advantage(results);
  const maxAdv = 1.0;
  const pct = Math.min(100, (adv / maxAdv) * 100);
  const isBreak = adv >= 0.9;

  return (
    <div className="pa03-adv-wrap">
      <div className="pa03-adv-header">
        <span className="pa01-output-title">Running Advantage</span>
        <span
          className={`pa03-adv-val ${isBreak ? "broken" : adv < 0.1 ? "secure" : ""}`}
        >
          {adv.toFixed(4)}
        </span>
      </div>
      <div className="pa03-adv-track">
        <div
          className={`pa03-adv-fill ${isBreak ? "broken" : "secure"}`}
          style={{ width: `${pct}%` }}
        />
        <div className="pa03-adv-midline" />
      </div>
      <div className="pa03-adv-labels">
        <span>0 (secure)</span>
        <span>0.5</span>
        <span>1.0 (broken)</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Panel
// ---------------------------------------------------------------------------
export default function Pa03Panel() {
  const [keyHex, setKeyHex] = useState(randomKeyHex);
  const [m0, setM0] = useState("hello world!");
  const [m1, setM1] = useState("goodbye world");
  const [reuseNonce, setReuseNonce] = useState(false);
  const [fixedNonce] = useState<number>(() => Math.floor(Math.random() * 256));

  const [phase, setPhase] = useState<Phase>("setup");
  const [hiddenB, setHiddenB] = useState<0 | 1>(0);
  const [challenge, setChallenge] = useState<{ nonce: number; ctHex: string } | null>(null);
  const [lastResult, setLastResult] = useState<RoundResult | null>(null);
  const [history, setHistory] = useState<RoundResult[]>([]);
  const [roundNum, setRoundNum] = useState(0);

  const isKeyValid = /^[0-9a-fA-F]{1,16}$/.test(keyHex);
  const lengthsMatch = m0.length === m1.length;

  // --- Derived values for nonce-reuse demo ---
  const xorDemo = useMemo(() => {
    if (!isKeyValid || !m0 || !m1) return null;
    const ct0 = encryptText(keyHex, m0, fixedNonce);
    const ct1 = encryptText(keyHex, m1, fixedNonce);
    const ctXor = xorHex(ct0.ctHex, ct1.ctHex);
    const mXor = xorHex(textToHex(m0), textToHex(m1));
    return { ct0, ct1, ctXor, mXor, match: ctXor === mXor };
  }, [keyHex, m0, m1, fixedNonce, isKeyValid]);

  // ─── Handlers ─────────────────────────────────────────────────────────────

  const newRound = useCallback(() => {
    if (!isKeyValid || !lengthsMatch) return;
    const b = (Math.random() < 0.5 ? 0 : 1) as 0 | 1;
    const chosen = b === 0 ? m0 : m1;
    const enc = encryptText(keyHex, chosen, reuseNonce ? fixedNonce : undefined);
    setHiddenB(b);
    setChallenge(enc);
    setPhase("guessing");
    setLastResult(null);
    setRoundNum((n) => n + 1);
  }, [isKeyValid, lengthsMatch, keyHex, m0, m1, reuseNonce, fixedNonce]);

  const submitGuess = useCallback(
    (guess: 0 | 1) => {
      if (!challenge) return;
      const correct = guess === hiddenB;
      const result: RoundResult = {
        roundNum,
        b: hiddenB,
        bGuess: guess,
        correct,
        nonce: challenge.nonce,
        ctHex: challenge.ctHex,
        reuseNonce,
      };
      setLastResult(result);
      setHistory((h) => [result, ...h].slice(0, 30));
      setPhase("revealed");
    },
    [challenge, hiddenB, roundNum, reuseNonce],
  );

  const resetGame = () => {
    setHistory([]);
    setPhase("setup");
    setChallenge(null);
    setLastResult(null);
    setRoundNum(0);
  };

  // Verify decryption of challenge
  const decrypted = useMemo(() => {
    if (!challenge || !isKeyValid) return null;
    try {
      return decryptText(keyHex, challenge.nonce, challenge.ctHex);
    } catch {
      return null;
    }
  }, [challenge, keyHex, isKeyValid]);

  // ─── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="pa03-shell">
      {/* ── Hero ── */}
      <section className="pa03-hero">
        <div
          className="pa01-hero-badge"
          style={{
            background: "rgba(80, 30, 120, 0.3)",
            borderColor: "rgba(180, 120, 240, 0.45)",
            color: "#d8b0ff",
          }}
        >
          PA #3
        </div>
        <h2 className="pa03-hero-title">CPA-Secure Symmetric Encryption</h2>
        <p className="pa03-hero-sub">
          Enc(k, m) = (r, F<sub>k</sub>(r) ⊕ m) &nbsp;·&nbsp; fresh nonce per
          encryption &nbsp;·&nbsp; IND-CPA game &nbsp;·&nbsp; nonce-reuse break
        </p>
        <div className="pa01-params">
          {[
            { label: "Scheme", val: "Enc-then-PRF" },
            { label: "PRF", val: "GGM (PA#2)" },
            { label: "Block", val: "4 bytes" },
            { label: "Nonce", val: "8-bit (fresh)" },
          ].map((p) => (
            <div
              key={p.label}
              className="pa01-param"
              style={{
                borderColor: "rgba(180,120,240,0.25)",
                background: "rgba(100,50,160,0.15)",
              }}
            >
              <span className="pa01-param-label" style={{ color: "#c090f0" }}>
                {p.label}
              </span>
              <span className="pa01-param-val">{p.val}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── Configuration ── */}
      <section className="pa03-config">
        <div className="pa03-config-card">
          <div className="pa01-control-label">
            <label htmlFor="pa03-key">Key k (hex)</label>
            <button
              type="button"
              className="pa01-random-btn"
              onClick={() => { setKeyHex(randomKeyHex()); resetGame(); }}
            >
              ↻ New Key
            </button>
          </div>
          <input
            id="pa03-key"
            className={`pa01-hex-input${isKeyValid ? "" : " error"}`}
            value={keyHex}
            onChange={(e) => { setKeyHex(e.target.value); resetGame(); }}
            spellCheck={false}
          />
        </div>

        <div className="pa03-config-card">
          <div className="pa01-control-label">
            <label>Messages m₀ and m₁</label>
            <span
              className="pa01-slider-readout"
              style={{ color: lengthsMatch ? undefined : "#e05050" }}
            >
              {lengthsMatch ? `${m0.length} chars each ✓` : "⚠ lengths must match"}
            </span>
          </div>
          <div className="pa03-msg-row">
            <div className="pa03-msg-field">
              <label htmlFor="pa03-m0" className="pa03-msg-label">m₀</label>
              <input
                id="pa03-m0"
                className="pa01-hex-input"
                value={m0}
                onChange={(e) => { setM0(e.target.value); resetGame(); }}
                placeholder="message zero"
              />
            </div>
            <div className="pa03-msg-field">
              <label htmlFor="pa03-m1" className="pa03-msg-label">m₁</label>
              <input
                id="pa03-m1"
                className="pa01-hex-input"
                value={m1}
                onChange={(e) => { setM1(e.target.value); resetGame(); }}
                placeholder="message one"
              />
            </div>
          </div>
        </div>

        <div className="pa03-config-card pa03-toggle-card">
          <div className="pa03-toggle-row">
            <button
              id="pa03-reuse-toggle"
              type="button"
              className={`pa03-toggle-btn${reuseNonce ? " active-broken" : ""}`}
              onClick={() => { setReuseNonce((v) => !v); resetGame(); }}
            >
              {reuseNonce ? "🔴 Reuse Nonce (BROKEN)" : "🟢 Fresh Nonce (SECURE)"}
            </button>
          </div>
          <p className="pa03-toggle-desc">
            {reuseNonce
              ? "Nonce is fixed! Repeating r in Enc(k,·) leaks m₀ ⊕ m₁ from the ciphertexts and gives the adversary advantage ≈ 1.0."
              : "Each encryption samples a fresh random r. The adversary cannot distinguish Enc(m₀) from Enc(m₁)."}
          </p>
        </div>
      </section>

      {/* ── IND-CPA Game ── */}
      <section className="pa03-game-section">
        <div className="pa02-section-header">
          <span className="pa01-output-title">IND-CPA Game — Round {roundNum}</span>
          <span className="pa01-output-meta">Play as the adversary</span>
        </div>

        {/* Step 1: ready */}
        {(phase === "setup" || phase === "revealed") && (
          <div className="pa03-step">
            <div className="pa03-step-label">
              {phase === "revealed" ? "Round complete — play another?" : "Ready to start"}
            </div>

            {lastResult && (
              <div className={`pa03-result-card ${lastResult.correct ? "correct" : "wrong"}`}>
                <span className="pa03-result-icon">{lastResult.correct ? "✓" : "✗"}</span>
                <span>
                  Challenger chose <strong>b = {lastResult.b}</strong>. You guessed{" "}
                  <strong>b′ = {lastResult.bGuess}</strong>.{" "}
                  {lastResult.correct ? "Correct!" : "Wrong."}
                </span>
              </div>
            )}

            <button
              id="pa03-start-round"
              type="button"
              className="pa03-primary-btn"
              disabled={!isKeyValid || !lengthsMatch}
              onClick={newRound}
            >
              {phase === "setup" ? "Start Round →" : "Next Round →"}
            </button>
          </div>
        )}

        {/* Step 2: guessing */}
        {phase === "guessing" && challenge && (
          <div className="pa03-step">
            <div className="pa03-step-label">
              Challenger encrypted <strong>one</strong> of your messages. Guess which!
            </div>

            <div className="pa03-ct-display">
              <div className="pa03-ct-row">
                <span className="pa03-ct-key">Nonce r =</span>
                <span className="mono pa03-ct-val">{challenge.nonce}</span>
              </div>
              <div className="pa03-ct-row">
                <span className="pa03-ct-key">C* =</span>
                <span className="mono pa03-ct-val pa03-ct-long">{challenge.ctHex}</span>
              </div>
              {decrypted && (
                <div className="pa03-ct-row">
                  <span className="pa03-ct-key">Dec(k, r, C*) =</span>
                  <span className="mono pa03-ct-val">{decrypted}</span>
                </div>
              )}
            </div>

            <div className="pa03-guess-row">
              <button
                id="pa03-guess-0"
                type="button"
                className="pa03-guess-btn m0"
                onClick={() => submitGuess(0)}
              >
                This is Enc(m₀)
                <span className="pa03-guess-sub">{m0}</span>
              </button>
              <button
                id="pa03-guess-1"
                type="button"
                className="pa03-guess-btn m1"
                onClick={() => submitGuess(1)}
              >
                This is Enc(m₁)
                <span className="pa03-guess-sub">{m1}</span>
              </button>
            </div>
          </div>
        )}

        <AdvantageBar results={history} />

        {/* History table */}
        {history.length > 0 && (
          <details className="pa03-history">
            <summary>Round history ({history.length} rounds)</summary>
            <table className="pa03-hist-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>b</th>
                  <th>b′</th>
                  <th>Result</th>
                  <th>Nonce</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 10).map((r) => (
                  <tr key={r.roundNum} className={r.correct ? "win" : "lose"}>
                    <td>{r.roundNum}</td>
                    <td>{r.b}</td>
                    <td>{r.bGuess}</td>
                    <td>{r.correct ? "✓" : "✗"}</td>
                    <td className="mono">{r.nonce}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        )}
      </section>

      {/* ── Nonce-reuse XOR Attack ── */}
      {xorDemo && (
        <section className="pa03-attack-section">
          <div className="pa02-section-header">
            <span className="pa01-output-title">Nonce-Reuse XOR Attack</span>
            <span className="pa01-output-meta">
              ct₀ ⊕ ct₁ = m₀ ⊕ m₁ when nonce is fixed
            </span>
          </div>
          <div className="pa03-xor-grid">
            <div className="pa03-xor-row">
              <span className="pa03-xor-label">Enc(k, m₀, r={fixedNonce})</span>
              <span className="mono pa03-xor-val">{xorDemo.ct0.ctHex}</span>
            </div>
            <div className="pa03-xor-row">
              <span className="pa03-xor-label">Enc(k, m₁, r={fixedNonce})</span>
              <span className="mono pa03-xor-val">{xorDemo.ct1.ctHex}</span>
            </div>
            <div className="pa03-xor-divider" />
            <div className="pa03-xor-row highlight">
              <span className="pa03-xor-label">ct₀ ⊕ ct₁</span>
              <span className="mono pa03-xor-val">{xorDemo.ctXor}</span>
            </div>
            <div className="pa03-xor-row highlight">
              <span className="pa03-xor-label">m₀ ⊕ m₁</span>
              <span className="mono pa03-xor-val">{xorDemo.mXor}</span>
            </div>
            <div className={`pa03-xor-verdict ${xorDemo.match ? "match" : "no-match"}`}>
              {xorDemo.match
                ? "✓ ct₀ ⊕ ct₁ = m₀ ⊕ m₁ — keystream leaked!"
                : "Lengths differ — partial leak still visible"}
            </div>
          </div>
        </section>
      )}

      {/* ── Theory cards ── */}
      <section className="pa01-theory-grid">
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">IND-CPA Definition</div>
          <p className="pa01-theory-body">
            Scheme is IND-CPA secure if for all PPT adversaries A:
          </p>
          <div className="pa01-formula">Adv_CPA(A) = |Pr[b′=b] − ½| ≤ negl(n)</div>
          <p className="pa01-theory-body">
            A can encrypt arbitrary messages (CPA oracle) but cannot distinguish
            which of two equal-length messages was encrypted in the challenge.
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">Enc-then-PRF Security</div>
          <div className="pa01-formula">Adv_IND-CPA(A) ≤ Adv_PRF(D)</div>
          <p className="pa01-theory-body">
            Reduction: any A winning the CPA game yields D distinguishing F_k
            from a random oracle. Since PA#2's GGM PRF is secure (PRG ⇒ PRF),
            advantage is negligible.
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">Why Fresh Nonce Matters</div>
          <p className="pa01-theory-body">
            If r is fixed: ct₀ ⊕ ct₁ = F_k(r) ⊕ m₀ ⊕ F_k(r) ⊕ m₁ = m₀ ⊕ m₁.
            The keystream cancels and the XOR of plaintexts is exposed —
            catastrophic break with advantage = ½ (full reveal).
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">Multi-Block Extension</div>
          <div className="pa01-formula">c_i = m_i ⊕ F_k((r+i) mod 256)</div>
          <p className="pa01-theory-body">
            Counter mode: each block uses an incremented nonce. PKCS7 padding
            handles non-block-aligned messages. Exposed as Enc/Dec interface for
            PA#6 (authenticated encryption).
          </p>
        </div>
      </section>
    </div>
  );
}
