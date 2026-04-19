import { useMemo, useState } from "react";

import {
  DirectionMode,
  FoundationId,
  PrimitiveExecution,
  PrimitiveId,
  ReductionTraceItem,
  normalizeHex,
  primitiveDuePa,
  primitiveLabel,
  primitiveOrder,
} from "./domain";
import { buildFromFoundation, getFoundationModule } from "./foundations";
import { buildProofSummary, findReverseHint, reduce, runReductionTrace } from "./routing";
import Pa01Panel from "./Pa01Panel";
import Pa02Panel from "./Pa02Panel";
import Pa03Panel from "./Pa03Panel";

function buildStatusLabel(step: { implemented: boolean; duePa?: string }): string {
  if (step.implemented) {
    return "implemented";
  }
  if (step.duePa) {
    return `Not implemented yet (due: ${step.duePa})`;
  }
  return "Not implemented yet";
}

function BuildSteps({ steps }: { steps: PrimitiveExecution[] }) {
  return (
    <div className="step-list">
      {steps.map((step, index) => (
        <article key={`${step.primitive}-${index}`} className={`step-card${step.implemented ? "" : " pending"}`}>
          <div className="step-head">
            <strong>
              {index + 1}. {step.functionApplied}
            </strong>
            <span className={`status-pill${step.implemented ? " ready" : ""}`}>
              {buildStatusLabel(step)}
            </span>
          </div>
          <p className="kv">Primitive: {step.primitive}</p>
          <p className="kv">Theorem: {step.theorem}</p>
          <p className="kv">Security reduction: {step.security}</p>
          <p className="kv">Implemented in: {step.pa}</p>
          <p className="kv">Input bytes (hex)</p>
          <div className="hex">{step.inputHex}</div>
          <p className="kv">Output bytes (hex)</p>
          <div className="hex">{step.outputHex}</div>
          {step.note ? <p className="kv">{step.note}</p> : null}
        </article>
      ))}
    </div>
  );
}

function ReductionSteps({ traces }: { traces: ReductionTraceItem[] }) {
  return (
    <div className="step-list">
      {traces.map((step, index) => (
        <article key={`${step.from}-${step.to}-${index}`} className={`step-card${step.implemented ? "" : " pending"}`}>
          <div className="step-head">
            <strong>
              {index + 1}. {step.from} to {step.to}
            </strong>
            <span className={`status-pill${step.implemented ? " ready" : ""}`}>
              {buildStatusLabel(step)}
            </span>
          </div>
          <p className="kv">Function applied: {step.functionApplied}</p>
          <p className="kv">Theorem: {step.theorem}</p>
          <p className="kv">Security reduction: {step.security}</p>
          <p className="kv">Implemented in: {step.pa}</p>
          <p className="kv">Input bytes (hex)</p>
          <div className="hex">{step.inputHex}</div>
          <p className="kv">A-oracle response (hex)</p>
          <div className="hex">{step.oracleResponseHex}</div>
          <p className="kv">Output bytes (hex)</p>
          <div className="hex">{step.outputHex}</div>
          {step.note ? <p className="kv">{step.note}</p> : null}
        </article>
      ))}
    </div>
  );
}

type AppTab = "pa00" | "pa01" | "pa02" | "pa03";

export default function App() {
  const [activeTab, setActiveTab] = useState<AppTab>("pa01");
  const [foundation, setFoundation] = useState<FoundationId>("AES");
  const [direction, setDirection] = useState<DirectionMode>("forward");
  const [primitiveA, setPrimitiveA] = useState<PrimitiveId>("PRF");
  const [primitiveB, setPrimitiveB] = useState<PrimitiveId>("MAC");
  const [keyHex, setKeyHex] = useState("00112233445566778899aabbccddeeff");
  const [messageHex, setMessageHex] = useState("68656c6c6f706f69732d70613030");
  const [proofOpen, setProofOpen] = useState(true);

  const foundationModule = useMemo(() => getFoundationModule(foundation), [foundation]);

  const buildTarget = direction === "forward" ? primitiveA : primitiveB;
  const reductionSource = direction === "forward" ? primitiveA : primitiveB;
  const reductionTarget = direction === "forward" ? primitiveB : primitiveA;

  const buildResult = useMemo(
    () =>
      buildFromFoundation(foundation, buildTarget, {
        keyHex: normalizeHex(keyHex, "00"),
        messageHex: normalizeHex(messageHex, "00"),
      }),
    [buildTarget, foundation, keyHex, messageHex],
  );

  const route = useMemo(
    () => reduce(reductionSource, reductionTarget, foundation),
    [reductionSource, reductionTarget, foundation],
  );

  const reverseHint = useMemo(
    () => findReverseHint(reductionSource, reductionTarget, foundation),
    [reductionSource, reductionTarget, foundation],
  );

  const reductionTraces = useMemo(() => {
    if (!buildResult.oracle || route === null) {
      return [];
    }
    if (route.length === 0) {
      return [];
    }
    return runReductionTrace(
      buildResult.oracle,
      route,
      normalizeHex(messageHex, "00"),
      normalizeHex(keyHex, "00"),
      foundation,
    );
  }, [buildResult.oracle, foundation, keyHex, messageHex, route]);

  const proofSummary = useMemo(
    () => buildProofSummary(reductionSource, reductionTarget, route),
    [reductionSource, reductionTarget, route],
  );

  const buildPanel = (
    <article className="panel" aria-label="Build panel">
      <h3>Column 1: Build ({foundation} to {buildTarget})</h3>
      <p className="panel-note">
        Chain from selected foundation to source primitive with full step trace.
      </p>
      {buildResult.message ? <div className="warn">{buildResult.message}</div> : null}
      {buildResult.steps.length > 0 ? (
        <BuildSteps steps={buildResult.steps} />
      ) : (
        <div className="warn">No build chain available for this selection.</div>
      )}
    </article>
  );

  const reductionPanel = (
    <article className="panel" aria-label="Reduce panel">
      <h3>Column 2: Reduce ({reductionSource} to {reductionTarget})</h3>
      <p className="panel-note">
        Reduction consumes the concrete {reductionSource} instance as a black-box oracle.
      </p>
      {route === null ? (
        <div className="warn">
          No direct path from {reductionSource} to {reductionTarget} in this direction.
          {reverseHint ? ` ${reverseHint}` : " Try the opposite mode toggle."}
        </div>
      ) : null}
      {route === null ? (
        <article className="step-card pending">
          <div className="step-head">
            <strong>{reductionSource} to {reductionTarget} (placeholder)</strong>
            <span className="status-pill">Not implemented yet (due: {primitiveDuePa[reductionTarget]})</span>
          </div>
          <p className="kv">
            No direct reduction path is modeled for this direction. Use backward mode or implement an additional reduction theorem.
          </p>
        </article>
      ) : null}
      {route && route.length === 0 ? (
        <div className="warn">Source and target are the same primitive. Reduction is identity.</div>
      ) : null}
      {route && route.length > 0 && buildResult.oracle ? (
        <ReductionSteps traces={reductionTraces} />
      ) : null}
      {route && route.length > 0 && !buildResult.oracle ? (
        <div className="warn">Build panel did not produce a usable source oracle.</div>
      ) : null}
    </article>
  );

  return (
    <main className="app-shell">
      {/* Tab navigation */}
      <nav className="tab-nav" aria-label="Assignment tabs">
        <button
          type="button"
          id="tab-pa03"
          className={`tab-btn${activeTab === "pa03" ? " active" : ""}`}
          onClick={() => setActiveTab("pa03")}
        >
          PA #3 &mdash; CPA Enc
        </button>
        <button
          type="button"
          id="tab-pa02"
          className={`tab-btn${activeTab === "pa02" ? " active" : ""}`}
          onClick={() => setActiveTab("pa02")}
        >
          PA #2 &mdash; GGM PRF
        </button>
        <button
          type="button"
          id="tab-pa01"
          className={`tab-btn${activeTab === "pa01" ? " active" : ""}`}
          onClick={() => setActiveTab("pa01")}
        >
          PA #1 &mdash; OWF &amp; PRG
        </button>
        <button
          type="button"
          id="tab-pa00"
          className={`tab-btn${activeTab === "pa00" ? " active" : ""}`}
          onClick={() => setActiveTab("pa00")}
        >
          PA #0 &mdash; Reduction Explorer
        </button>
      </nav>

      {/* PA03 CPA demo */}
      {activeTab === "pa03" && <Pa03Panel />}

      {/* PA02 GGM demo */}
      {activeTab === "pa02" && <Pa02Panel />}

      {/* PA01 demo */}
      {activeTab === "pa01" && <Pa01Panel />}

      {/* PA00 reduction explorer (hidden when pa01 active) */}
      {activeTab === "pa00" && <>
      <section className="hero">
        <h1>PA00 Minicrypt Reduction Explorer</h1>
        <p>
          Interactive scaffold with foundation toggle, two-column Build/Reduce pipeline, bidirectional mode,
          and formal proof summary stubs.
        </p>
        <div className="hero-meta">
          <span>{foundation} foundation</span>
          <span>{direction === "forward" ? "Forward reduction" : "Backward reduction"}</span>
          <span>
            {reductionSource} to {reductionTarget}
          </span>
        </div>

        <div className="control-grid">
          <div className="control-card">
            <h2>Foundation</h2>
            <div className="segment-row">
              {(["AES", "DLP"] as FoundationId[]).map((candidate) => (
                <button
                  key={candidate}
                  type="button"
                  className={foundation === candidate ? "active" : ""}
                  onClick={() => setFoundation(candidate)}
                >
                  {candidate}
                </button>
              ))}
            </div>
            <p className="panel-note">{foundationModule.name} capabilities: {foundationModule.capabilities.join(", ")}</p>
          </div>

          <div className="control-card">
            <h2>Mode</h2>
            <div className="segment-row">
              <button
                type="button"
                className={direction === "forward" ? "active" : ""}
                onClick={() => setDirection("forward")}
              >
                Forward (A to B)
              </button>
              <button
                type="button"
                className={direction === "backward" ? "active" : ""}
                onClick={() => setDirection("backward")}
              >
                Backward (B to A)
              </button>
            </div>
          </div>

          <div className="control-card">
            <h2>Primitive Pair</h2>
            <div className="control-field">
              <label htmlFor="primitive-a">Primitive A (source in forward mode)</label>
              <select
                id="primitive-a"
                value={primitiveA}
                onChange={(event) => setPrimitiveA(event.target.value as PrimitiveId)}
              >
                {primitiveOrder.map((primitive) => (
                  <option key={primitive} value={primitive}>
                    {primitiveLabel[primitive]}
                  </option>
                ))}
              </select>
            </div>
            <div className="control-field">
              <label htmlFor="primitive-b">Primitive B (target in forward mode)</label>
              <select
                id="primitive-b"
                value={primitiveB}
                onChange={(event) => setPrimitiveB(event.target.value as PrimitiveId)}
              >
                {primitiveOrder.map((primitive) => (
                  <option key={primitive} value={primitive}>
                    {primitiveLabel[primitive]}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="control-card">
            <h2>Input Bytes</h2>
            <div className="control-field">
              <label htmlFor="key-hex">Key (hex)</label>
              <input
                id="key-hex"
                value={keyHex}
                onChange={(event) => setKeyHex(event.target.value)}
                spellCheck={false}
              />
            </div>
            <div className="control-field">
              <label htmlFor="message-hex">Message (hex)</label>
              <input
                id="message-hex"
                value={messageHex}
                onChange={(event) => setMessageHex(event.target.value)}
                spellCheck={false}
              />
            </div>
          </div>
        </div>
      </section>

      <section className="columns" aria-label="Two-column layout">
        {direction === "forward" ? buildPanel : reductionPanel}
        {direction === "forward" ? reductionPanel : buildPanel}
      </section>

      <section className="proof-shell" aria-label="Proof summary panel">
        <button className="proof-toggle" type="button" onClick={() => setProofOpen((open) => !open)}>
          Proof Summary {proofOpen ? "(hide)" : "(show)"}
        </button>
        {proofOpen ? (
          <div className="proof-body">
            <h4>{proofSummary.headline}</h4>
            <p>{proofSummary.detail}</p>
            {proofSummary.steps.length > 0 ? (
              proofSummary.steps.map((step, index) => (
                <div key={`${step.theorem}-${index}`} className={`proof-item${step.implemented ? "" : " pending"}`}>
                  <p className="kv">Step {index + 1} theorem: {step.theorem}</p>
                  <p className="kv">Security chain: {step.security}</p>
                  <p className="kv">
                    Assignment source: {step.pa}
                    {step.implemented ? "" : ` - Not implemented yet (due: ${step.duePa ?? "TBD"})`}
                  </p>
                </div>
              ))
            ) : (
              <div className="warn">No reduction theorem chain is available for this direction yet.</div>
            )}
          </div>
        ) : null}
      </section>
      </>}
    </main>
  );
}
