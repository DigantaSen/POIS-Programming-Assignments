import { useMemo, useState } from "react";
import { birthdayFloyd, birthdayNaive, theoreticalK50 } from "./pa09birthday";

interface Row {
  n: number;
  k50: number;
  naive: ReturnType<typeof birthdayNaive>;
  floyd: ReturnType<typeof birthdayFloyd>;
}

const N_VALUES = [8, 10, 12, 14, 16];

export default function Pa09Panel() {
  const [tick, setTick] = useState(0);

  const rows = useMemo<Row[]>(() => {
    void tick;
    return N_VALUES.map((n) => ({
      n,
      k50: theoreticalK50(n),
      naive: birthdayNaive(n),
      floyd: birthdayFloyd(n),
    }));
  }, [tick]);

  return (
    <section className="panel" aria-label="PA09 panel">
      <h3>PA #9: Birthday Attack</h3>
      <p className="panel-note">
        Comparison of naive collision search and Floyd cycle detection over PA08 truncated outputs.
      </p>

      <div className="control-card" style={{ marginBottom: "0.8rem" }}>
        <button type="button" className="segment-row button" onClick={() => setTick((t) => t + 1)}>
          Rerun Experiments
        </button>
      </div>

      <div className="step-list">
        {rows.map((r) => (
          <article key={r.n} className="step-card">
            <div className="step-head">
              <strong>n = {r.n} bits</strong>
              <span className="status-pill ready">k@50% ≈ {r.k50.toFixed(1)}</span>
            </div>
            <p className="kv">
              Naive: steps={r.naive.steps}, found={String(r.naive.found)}, digest={r.naive.digest?.toString(16) ?? "-"}
            </p>
            <p className="kv">
              Floyd: steps={r.floyd.steps}, found={String(r.floyd.found)}, digest={r.floyd.digest?.toString(16) ?? "-"}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}
