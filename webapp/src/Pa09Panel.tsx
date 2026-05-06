import { useEffect, useMemo, useRef, useState } from "react";
import { bytesToHex, pa08HashNBits } from "./pa08hash";

const N_VALUES = [8, 10, 12, 14, 16] as const;

type Point = {
  evaluations: number;
  probability: number;
};

type CollisionWitness = {
  x1: string;
  x2: string;
  digest: string;
  evaluations: number;
};

function theoreticalBirthdayProbability(k: number, nBits: number): number {
  if (k <= 0) return 0;
  return 1 - Math.exp(-((k * k) / 2 ** nBits));
}

function expectedCollisionPoint(nBits: number): number {
  return 2 ** (nBits / 2);
}

function padHex(value: number, nBits: number): string {
  return value.toString(16).padStart(Math.max(2, Math.ceil(nBits / 4)), "0");
}

function randomMessageBytes(): Uint8Array {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return bytes;
}

function nextFrame(): Promise<void> {
  return new Promise((resolve) => {
    window.requestAnimationFrame(() => resolve());
  });
}

function scalePoint(
  evaluations: number,
  probability: number,
  maxEvaluations: number,
  width: number,
  height: number,
) {
  const left = 50;
  const right = 18;
  const top = 16;
  const bottom = 30;
  const x = left + (Math.min(evaluations, maxEvaluations) / maxEvaluations) * (width - left - right);
  const y = top + (1 - Math.max(0, Math.min(1, probability))) * (height - top - bottom);
  return { x, y, left, right, top, bottom };
}

function buildCurvePath(nBits: number, maxEvaluations: number, width: number, height: number): string {
  const segments = 160;
  const points: string[] = [];
  for (let i = 0; i <= segments; i += 1) {
    const evaluations = (i / segments) * maxEvaluations;
    const probability = theoreticalBirthdayProbability(evaluations, nBits);
    const scaled = scalePoint(evaluations, probability, maxEvaluations, width, height);
    points.push(`${scaled.x.toFixed(2)},${scaled.y.toFixed(2)}`);
  }
  return points.join(" ");
}

export default function Pa09Panel() {
  const [nBits, setNBits] = useState<(typeof N_VALUES)[number]>(12);
  const [running, setRunning] = useState(false);
  const [evaluations, setEvaluations] = useState(0);
  const [currentInputHex, setCurrentInputHex] = useState("");
  const [currentDigest, setCurrentDigest] = useState<number | null>(null);
  const [currentProbability, setCurrentProbability] = useState(0);
  const [history, setHistory] = useState<Point[]>([]);
  const [witness, setWitness] = useState<CollisionWitness | null>(null);
  const runTokenRef = useRef(0);

  const expectedK = useMemo(() => expectedCollisionPoint(nBits), [nBits]);
  const maxEvaluations = useMemo(() => Math.max(64, Math.ceil(expectedK * 2.25)), [expectedK]);
  const width = 760;
  const height = 270;
  const curvePath = useMemo(() => buildCurvePath(nBits, maxEvaluations, width, height), [nBits, maxEvaluations]);
  const latestPoint = history[history.length - 1];
  const latestScaled = latestPoint
    ? scalePoint(latestPoint.evaluations, latestPoint.probability, maxEvaluations, width, height)
    : null;
  const expectedScaled = scalePoint(expectedK, 0, maxEvaluations, width, height);
  const liveDigestHex = currentDigest === null ? "—" : padHex(currentDigest, nBits);
  const progressPct = Math.min(100, (evaluations / maxEvaluations) * 100);

  useEffect(
    () => () => {
      runTokenRef.current += 1;
    },
    [],
  );

  const resetRun = () => {
    runTokenRef.current += 1;
    setRunning(false);
    setEvaluations(0);
    setCurrentInputHex("");
    setCurrentDigest(null);
    setCurrentProbability(0);
    setHistory([]);
    setWitness(null);
  };

  const runAttack = async () => {
    if (running) return;

    const token = runTokenRef.current + 1;
    runTokenRef.current = token;

    setRunning(true);
    setEvaluations(0);
    setCurrentInputHex("");
    setCurrentDigest(null);
    setCurrentProbability(0);
    setHistory([]);
    setWitness(null);

    const seen = new Map<number, string>();
    const maxTrials = Math.min(200_000, Math.max(512, Math.ceil(expectedK * 16)));

    for (let step = 1; step <= maxTrials; step += 1) {
      if (runTokenRef.current !== token) return;

      const message = randomMessageBytes();
      const messageHex = bytesToHex(message);
      const digest = pa08HashNBits(message, nBits);
      const probability = theoreticalBirthdayProbability(step, nBits);
      const prior = seen.get(digest);

      setEvaluations(step);
      setCurrentInputHex(messageHex);
      setCurrentDigest(digest);
      setCurrentProbability(probability);
      setHistory((previous) => [...previous, { evaluations: step, probability }]);

      if (prior !== undefined && prior !== messageHex) {
        setWitness({
          x1: prior,
          x2: messageHex,
          digest: padHex(digest, nBits),
          evaluations: step,
        });
        setRunning(false);
        return;
      }

      seen.set(digest, messageHex);

      if (step % 2 === 0) {
        await nextFrame();
      }
    }

    if (runTokenRef.current === token) {
      setRunning(false);
    }
  };

  return (
    <section className="panel" aria-label="PA09 panel">
      <h3>PA #9: Birthday Attack Live Demo</h3>
      <p className="panel-note">
        Pick a single output length, run the attack, and watch the hash count, collision witness,
        and birthday curve update live.
      </p>

      <div className="control-grid">
        <div className="control-card pa09-slab">
          <div className="control-field">
            <label htmlFor="pa09-nbits">Output bit-length n = {nBits}</label>
            <input
              id="pa09-nbits"
              type="range"
              min={N_VALUES[0]}
              max={N_VALUES[N_VALUES.length - 1]}
              step={2}
              value={nBits}
              onChange={(e) => setNBits(Number(e.target.value) as (typeof N_VALUES)[number])}
              disabled={running}
            />
          </div>
          <div className="pa09-ticks" aria-hidden="true">
            {N_VALUES.map((value) => (
              <span key={value}>{value}</span>
            ))}
          </div>
          <p className="kv">Expected collision point: {expectedK.toFixed(1)} evaluations</p>
        </div>

        <div className="control-card">
          <div className="pa09-status-row">
            <button type="button" className="segment-row button" onClick={runAttack} disabled={running}>
              {running ? "Running..." : "Run attack"}
            </button>
            <button type="button" className="segment-row button" onClick={resetRun}>
              Reset
            </button>
            <span className={`status-pill${running ? " ready" : ""}`}>{running ? "live" : "idle"}</span>
          </div>
          <p className="kv">The demo uses PA08 truncated hashes and stops at the first collision witness.</p>
          <div className="pa09-progress" aria-label="Attack progress">
            <div className="pa09-progress-bar" style={{ width: `${progressPct}%` }} />
          </div>
        </div>
      </div>

      <div className="pa09-stat-grid">
        <article className="pa09-stat">
          <strong>Hashes computed</strong>
          <span>{evaluations}</span>
        </article>
        <article className="pa09-stat">
          <strong>Current collision probability</strong>
          <span>{(currentProbability * 100).toFixed(2)}%</span>
        </article>
        <article className="pa09-stat">
          <strong>Latest digest</strong>
          <span>{liveDigestHex}</span>
        </article>
        <article className="pa09-stat">
          <strong>Status</strong>
          <span>{witness ? "collision found" : running ? "searching" : "ready"}</span>
        </article>
      </div>

      <div className="pa09-chart">
        <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Birthday attack probability chart">
          <defs>
            <linearGradient id="pa09-curve-fill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="rgba(13, 127, 119, 0.26)" />
              <stop offset="100%" stopColor="rgba(13, 127, 119, 0.02)" />
            </linearGradient>
          </defs>

          <line x1="50" y1="16" x2="50" y2={height - 30} stroke="rgba(52, 78, 90, 0.35)" />
          <line x1="50" y1={height - 30} x2={width - 18} y2={height - 30} stroke="rgba(52, 78, 90, 0.35)" />
          <line x1="50" y1="16" x2={width - 18} y2="16" stroke="rgba(52, 78, 90, 0.08)" strokeDasharray="4 4" />
          <line x1="50" y1={(height - 30) / 2 + 16} x2={width - 18} y2={(height - 30) / 2 + 16} stroke="rgba(52, 78, 90, 0.08)" strokeDasharray="4 4" />
          <line x1="50" y1={height - 30} x2={width - 18} y2={height - 30} stroke="rgba(52, 78, 90, 0.08)" strokeDasharray="4 4" />

          <polyline points={curvePath} fill="none" stroke="url(#pa09-curve-fill)" strokeWidth="10" opacity="0.4" />
          <polyline points={curvePath} fill="none" stroke="var(--accent)" strokeWidth="2.6" />

          {latestScaled ? (
            <polyline points={history.map((point) => {
              const scaled = scalePoint(point.evaluations, point.probability, maxEvaluations, width, height);
              return `${scaled.x.toFixed(2)},${scaled.y.toFixed(2)}`;
            }).join(" ")} fill="none" stroke="var(--accent-warm)" strokeWidth="3" />
          ) : null}

          <line
            x1={expectedScaled.x}
            y1="16"
            x2={expectedScaled.x}
            y2={height - 30}
            stroke="rgba(215, 108, 47, 0.7)"
            strokeDasharray="6 5"
          />
          <text x={Math.min(width - 74, Math.max(54, expectedScaled.x - 22))} y="26" fill="var(--ink-700)" fontSize="11" fontWeight="700">
            2^(n/2)
          </text>

          {latestScaled ? (
            <circle cx={latestScaled.x} cy={latestScaled.y} r="4.5" fill="var(--accent-warm)" stroke="#fff" strokeWidth="1.5" />
          ) : null}

          <text x="14" y="25" fill="var(--ink-500)" fontSize="11" fontWeight="700">
            collision probability
          </text>
          <text x={width - 135} y={height - 8} fill="var(--ink-500)" fontSize="11" fontWeight="700">
            hashes computed
          </text>
        </svg>

        <div className="pa09-legend">
          <span><strong style={{ color: "var(--accent)" }}>Theoretical curve</strong></span>
          <span><strong style={{ color: "var(--accent-warm)" }}>Live attack progress</strong></span>
          <span><strong style={{ color: "rgba(215, 108, 47, 0.9)" }}>Expected collision point</strong></span>
        </div>
      </div>

      <div className="pa09-witnesses">
        <article className="step-card">
          <div className="step-head">
            <strong>Live input</strong>
            <span className="status-pill ready">{running ? "updating" : "last sample"}</span>
          </div>
          <p className="kv">Message being hashed</p>
          <div className="hex">{currentInputHex || "waiting for attack..."}</div>
        </article>

        <article className={`step-card${witness ? "" : " pending"}`}>
          <div className="step-head">
            <strong>Collision witness</strong>
            <span className={`status-pill${witness ? " ready" : ""}`}>{witness ? "found" : "not yet"}</span>
          </div>
          {witness ? (
            <>
              <p className="kv">x1</p>
              <div className="hex">{witness.x1}</div>
              <p className="kv">x2</p>
              <div className="hex">{witness.x2}</div>
              <p className="kv">Shared truncated digest: {witness.digest}</p>
              <p className="kv">Found after {witness.evaluations} evaluations.</p>
            </>
          ) : (
            <p className="kv">Run the attack to reveal the two colliding inputs and their shared hash value.</p>
          )}
        </article>
      </div>

      <div className="warn" style={{ marginTop: "0.8rem" }}>
        This demo is intentionally live and toy-sized: it uses the PA08 hash truncated to n bits,
        so the birthday attack becomes visible at the expected 2^(n/2) scale.
      </div>
    </section>
  );
}
