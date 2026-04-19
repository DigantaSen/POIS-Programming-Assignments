import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  TestResult,
  bitsToHex,
  prgExpand,
  randomSeedHex,
  runAllTests,
} from "./prg";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function formatHex(hex: string, charsPerLine = 64): string {
  const rows: string[] = [];
  for (let i = 0; i < hex.length; i += charsPerLine) {
    rows.push(hex.slice(i, i + charsPerLine));
  }
  return rows.join("\n");
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function TestBadge({ result }: { result: TestResult }) {
  const pct = Math.round(result.pValue * 100);
  return (
    <div className={`test-badge ${result.pass ? "pass" : "fail"}`}>
      <div className="test-badge-head">
        <span className="test-name">{result.name}</span>
        <span className={`test-pill ${result.pass ? "pass" : "fail"}`}>
          {result.pass ? "PASS" : "FAIL"}
        </span>
      </div>
      <div className="test-pbar-track">
        <div
          className={`test-pbar-fill ${result.pass ? "pass" : "fail"}`}
          style={{ width: `${clamp(pct, 0, 100)}%` }}
        />
      </div>
      <div className="test-pvalue">p-value = {result.pValue.toFixed(5)}</div>
      {result.extra?.ones_ratio !== undefined && (
        <div className="test-extra">
          Bit ratio: {((result.extra.ones_ratio as number) * 100).toFixed(2)}% ones
          <span className="test-ideal"> (ideal ≈ 50%)</span>
        </div>
      )}
    </div>
  );
}

function BitRatioBar({ bits }: { bits: string }) {
  if (!bits) return null;
  const ones = [...bits].filter((b) => b === "1").length;
  const ratio = bits.length ? ones / bits.length : 0.5;
  const pct = ratio * 100;
  const deviation = Math.abs(ratio - 0.5) * 100;

  return (
    <div className="ratio-bar-wrapper">
      <div className="ratio-bar-label">
        <span>Bit ratio</span>
        <span className="ratio-val">
          {pct.toFixed(2)}% ones &nbsp;·&nbsp;{deviation.toFixed(2)}% deviation from 50%
        </span>
      </div>
      <div className="ratio-bar-track">
        <div
          className="ratio-bar-fill"
          style={{ width: `${pct}%`, background: deviation < 5 ? "var(--accent)" : "var(--accent-warm)" }}
        />
        <div className="ratio-bar-midline" />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main PA#1 Panel
// ---------------------------------------------------------------------------

export default function Pa01Panel() {
  const [seedHex, setSeedHex] = useState<string>(randomSeedHex);
  const [outputBytes, setOutputBytes] = useState<number>(64);
  const [testResults, setTestResults] = useState<TestResult[] | null>(null);
  const [testRunning, setTestRunning] = useState(false);
  const [seedError, setSeedError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Validate hex seed
  const isValidHex = useMemo(() => /^[0-9a-fA-F]*$/.test(seedHex) && seedHex.length > 0, [seedHex]);

  // Compute PRG output (live, on every change)
  const prgBits = useMemo(() => {
    if (!isValidHex) return "";
    return prgExpand(seedHex, outputBytes * 8);
  }, [seedHex, outputBytes, isValidHex]);

  const prgHex = useMemo(() => bitsToHex(prgBits), [prgBits]);

  // Clear test results when inputs change
  useEffect(() => {
    setTestResults(null);
  }, [seedHex, outputBytes]);

  // Validate on input
  const handleSeedChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setSeedHex(val);
    if (val && !/^[0-9a-fA-F]*$/.test(val)) {
      setSeedError("Only hexadecimal characters (0-9, a-f) are allowed.");
    } else {
      setSeedError(null);
    }
  }, []);

  const handleRandomSeed = useCallback(() => {
    const s = randomSeedHex();
    setSeedHex(s);
    setSeedError(null);
    inputRef.current?.focus();
  }, []);

  const handleRunTests = useCallback(() => {
    if (!isValidHex || !prgBits) return;
    setTestRunning(true);
    // Use a small timeout so the button state can render before computation
    setTimeout(() => {
      // Run tests on a longer stream for statistical significance
      const longBits = prgExpand(seedHex, 2048);
      setTestResults(runAllTests(longBits));
      setTestRunning(false);
    }, 30);
  }, [isValidHex, prgBits, seedHex]);

  return (
    <div className="pa01-shell">
      {/* ------------------------------------------------------------------ */}
      {/* Header                                                               */}
      {/* ------------------------------------------------------------------ */}
      <section className="pa01-hero">
        <div className="pa01-hero-badge">PA #1</div>
        <h2 className="pa01-hero-title">One-Way Functions &amp; Pseudorandom Generators</h2>
        <p className="pa01-hero-sub">
          DLP-based OWF f(x)&nbsp;=&nbsp;g<sup>x</sup> mod p &nbsp;·&nbsp; Håstad–Impagliazzo–Levin–Luby
          construction &nbsp;·&nbsp; NIST SP 800-22 statistical tests
        </p>
        <div className="pa01-params">
          <div className="pa01-param">
            <span className="pa01-param-label">Group modulus p</span>
            <span className="pa01-param-val mono">2147483867</span>
          </div>
          <div className="pa01-param">
            <span className="pa01-param-label">Subgroup order q</span>
            <span className="pa01-param-val mono">1073741933</span>
          </div>
          <div className="pa01-param">
            <span className="pa01-param-label">Generator g</span>
            <span className="pa01-param-val mono">4</span>
          </div>
          <div className="pa01-param">
            <span className="pa01-param-label">Seed size</span>
            <span className="pa01-param-val mono">64 bits</span>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Controls                                                             */}
      {/* ------------------------------------------------------------------ */}
      <section className="pa01-controls">
        {/* Seed input */}
        <div className="pa01-control-card">
          <div className="pa01-control-label">
            <label htmlFor="pa01-seed">Seed s (hex, 8 bytes / 64 bits recommended)</label>
            <button
              type="button"
              className="pa01-random-btn"
              onClick={handleRandomSeed}
              title="Generate a random seed"
            >
              ↻ Random
            </button>
          </div>
          <input
            ref={inputRef}
            id="pa01-seed"
            className={`pa01-hex-input${seedError ? " error" : ""}`}
            value={seedHex}
            onChange={handleSeedChange}
            spellCheck={false}
            placeholder="e.g. deadbeefcafe1234"
            autoComplete="off"
          />
          {seedError && <div className="pa01-field-error">{seedError}</div>}
        </div>

        {/* Output length slider */}
        <div className="pa01-control-card">
          <div className="pa01-control-label">
            <label htmlFor="pa01-length">Output length ℓ</label>
            <span className="pa01-slider-readout">{outputBytes} bytes ({outputBytes * 8} bits)</span>
          </div>
          <input
            id="pa01-length"
            type="range"
            className="pa01-slider"
            min={8}
            max={256}
            step={8}
            value={outputBytes}
            onChange={(e) => setOutputBytes(Number(e.target.value))}
          />
          <div className="pa01-slider-ticks">
            <span>8 B</span>
            <span>64 B</span>
            <span>128 B</span>
            <span>192 B</span>
            <span>256 B</span>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* PRG Output                                                           */}
      {/* ------------------------------------------------------------------ */}
      <section className="pa01-output-section">
        <div className="pa01-output-header">
          <span className="pa01-output-title">G(s) — PRG Output</span>
          <span className="pa01-output-meta">
            {prgBits.length} bits · {prgBits.length / 8} bytes
          </span>
        </div>

        {isValidHex ? (
          <>
            <BitRatioBar bits={prgBits} />
            <div className="pa01-hex-display" aria-label="PRG hex output">
              <pre className="pa01-hex-pre">{formatHex(prgHex)}</pre>
            </div>
            <div className="pa01-bits-display" aria-label="PRG bit string">
              <div className="pa01-bits-label">Bit string</div>
              <pre className="pa01-bits-pre">{prgBits}</pre>
            </div>
          </>
        ) : (
          <div className="pa01-warn">Enter a valid hexadecimal seed to see live PRG output.</div>
        )}
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Randomness Tests                                                     */}
      {/* ------------------------------------------------------------------ */}
      <section className="pa01-test-section">
        <div className="pa01-test-header">
          <div>
            <div className="pa01-output-title">Randomness Tests</div>
            <div className="pa01-test-note">
              NIST SP 800-22: Frequency, Runs, Serial — tested on 2048 bits of PRG output
            </div>
          </div>
          <button
            id="pa01-run-tests"
            type="button"
            className="pa01-test-btn"
            onClick={handleRunTests}
            disabled={!isValidHex || testRunning}
          >
            {testRunning ? "Running…" : "Run Tests"}
          </button>
        </div>

        {testResults && (
          <div className="pa01-test-grid">
            {testResults.map((r) => (
              <TestBadge key={r.name} result={r} />
            ))}
          </div>
        )}

        {!testResults && !testRunning && (
          <div className="pa01-test-placeholder">
            Click <strong>Run Tests</strong> to run the NIST-like statistical test suite on the PRG output stream.
          </div>
        )}
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Theory boxes                                                         */}
      {/* ------------------------------------------------------------------ */}
      <section className="pa01-theory-grid">
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">OWF → PRG (PA#1a)</div>
          <p className="pa01-theory-body">
            Given OWF f with hard-core predicate b, the PRG is defined as:
          </p>
          <div className="pa01-formula">
            G(x₀) = b(x₀) ‖ b(x₁) ‖ … ‖ b(xₗ) &nbsp; where &nbsp; xᵢ₊₁ = f(xᵢ)
          </div>
          <p className="pa01-theory-body">
            Security reduces to inverting f: any distinguisher D for G yields an inverter A for f
            with advantage Adv<sub>OWF</sub>(A) ≥ Adv<sub>PRG</sub>(D) / ℓ.
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">PRG → OWF (PA#1b)</div>
          <p className="pa01-theory-body">
            The PRG output <em>is itself</em> a one-way function: define F(s) = G(s).
          </p>
          <p className="pa01-theory-body">
            <strong>Argument:</strong> If an adversary A could recover s from G(s) efficiently,
            it would contradict the PRG distinguishing game — the adversary could simply re-compute
            G(s') for each guess s' and check equality, inverting G in polynomial time. But PRG
            security (pseudo-randomness of G(s)) prevents efficient search over the seed space.
          </p>
          <p className="pa01-theory-body">
            The bounded inversion demo (Python backend) confirms this empirically: with a
            20-bit seed space (≈ 10⁶ seeds), a budget-4096 exhaustive search succeeds with
            probability ≈ 4096 / 2²⁰ ≈ 0.004 — negligible.
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">Hard-core bit b(x)</div>
          <p className="pa01-theory-body">
            The Goldreich-Levin theorem guarantees the existence of a hard-core bit for any OWF.
            In this implementation b(x) = LSB(FNV-hash(x)), which is computationally unpredictable
            from f(x) = gˣ mod p as long as the DLP is hard.
          </p>
          <p className="pa01-theory-body">
            Formally b is a hard-core predicate: Pr[ A(f(x)) = b(x) ] ≤ ½ + negl(n).
          </p>
        </div>
        <div className="pa01-theory-card">
          <div className="pa01-theory-title">OWF Hardness Demo</div>
          <p className="pa01-theory-body">
            A random adversary A that guesses x ← {"{0,1}"}ⁿ uniformly succeeds in inverting
            f(x) = gˣ mod p with probability 1/q ≈ 2⁻³⁰ ≈ 10⁻⁹.
          </p>
          <p className="pa01-theory-body">
            The Python backend's <code>verify_hardness()</code> runs 64 random guess trials and
            consistently observes 0 successes, confirming negligible empirical inversion rate.
          </p>
        </div>
      </section>
    </div>
  );
}
