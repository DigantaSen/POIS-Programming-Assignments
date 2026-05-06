import { useEffect, useMemo, useState } from "react";
import { clampSecret, genSafePrime, publicFromSecret, randomSecret, shared } from "./pa11dh";

type ExchangePhase = "idle" | "alice-sent" | "bob-sent" | "done";

function toHex(v: number): string {
  return `0x${v.toString(16)}`;
}

function parseSecretInput(raw: string, fallback: number): number {
  const s = raw.trim();
  if (!s) return fallback;
  if (/^0x[0-9a-f]+$/i.test(s)) {
    return Number.parseInt(s.slice(2), 16);
  }
  if (/^[0-9a-f]+$/i.test(s) && /[a-f]/i.test(s)) {
    return Number.parseInt(s, 16);
  }
  const asNumber = Number(s);
  return Number.isFinite(asNumber) ? Math.floor(asNumber) : fallback;
}

export default function Pa11Panel() {
  const params = useMemo(() => genSafePrime(32), []);

  const [aliceSecretInput, setAliceSecretInput] = useState(() => toHex(randomSecret(params)));
  const [bobSecretInput, setBobSecretInput] = useState(() => toHex(randomSecret(params)));
  const [eveEnabled, setEveEnabled] = useState(false);
  const [eveToBobInput, setEveToBobInput] = useState(() => toHex(randomSecret(params)));
  const [eveToAliceInput, setEveToAliceInput] = useState(() => toHex(randomSecret(params)));
  const [phase, setPhase] = useState<ExchangePhase>("idle");
  const [exchangeSeq, setExchangeSeq] = useState(0);

  useEffect(() => {
    if (exchangeSeq === 0) return;
    setPhase("alice-sent");
    const t1 = window.setTimeout(() => setPhase("bob-sent"), 720);
    const t2 = window.setTimeout(() => setPhase("done"), 1480);
    return () => {
      window.clearTimeout(t1);
      window.clearTimeout(t2);
    };
  }, [exchangeSeq]);

  const aliceSecret = useMemo(
    () => clampSecret(params, parseSecretInput(aliceSecretInput, 2)),
    [aliceSecretInput, params],
  );
  const bobSecret = useMemo(
    () => clampSecret(params, parseSecretInput(bobSecretInput, 2)),
    [bobSecretInput, params],
  );
  const eveToBobSecret = useMemo(
    () => clampSecret(params, parseSecretInput(eveToBobInput, 2)),
    [eveToBobInput, params],
  );
  const eveToAliceSecret = useMemo(
    () => clampSecret(params, parseSecretInput(eveToAliceInput, 2)),
    [eveToAliceInput, params],
  );

  const model = useMemo(() => {
    const alicePk = publicFromSecret(params, aliceSecret);
    const bobPk = publicFromSecret(params, bobSecret);
    const eveToBobPk = publicFromSecret(params, eveToBobSecret);
    const eveToAlicePk = publicFromSecret(params, eveToAliceSecret);

    const deliveredToBob = eveEnabled ? eveToBobPk : alicePk;
    const deliveredToAlice = eveEnabled ? eveToAlicePk : bobPk;

    const aliceShared = shared(params, aliceSecret, deliveredToAlice);
    const bobShared = shared(params, bobSecret, deliveredToBob);

    const eveWithAlice = eveEnabled ? shared(params, eveToAliceSecret, alicePk) : null;
    const eveWithBob = eveEnabled ? shared(params, eveToBobSecret, bobPk) : null;

    return {
      alicePk,
      bobPk,
      eveToBobPk,
      eveToAlicePk,
      deliveredToBob,
      deliveredToAlice,
      aliceShared,
      bobShared,
      eveWithAlice,
      eveWithBob,
      keysMatch: aliceShared === bobShared,
    };
  }, [params, aliceSecret, bobSecret, eveToBobSecret, eveToAliceSecret, eveEnabled]);

  const stepLabel =
    phase === "idle"
      ? "Ready"
      : phase === "alice-sent"
        ? "Step 1/2: Alice sends first"
        : phase === "bob-sent"
          ? "Step 2/2: Bob sends back"
          : "Exchange complete";

  function randomizeAll(): void {
    setAliceSecretInput(toHex(randomSecret(params)));
    setBobSecretInput(toHex(randomSecret(params)));
    setEveToBobInput(toHex(randomSecret(params)));
    setEveToAliceInput(toHex(randomSecret(params)));
    setPhase("idle");
  }

  function runExchange(): void {
    setExchangeSeq((n) => n + 1);
  }

  return (
    <section className="panel" aria-label="PA11 panel">
      <h3>PA #11: Diffie-Hellman and MITM</h3>
      <p className="panel-note">Unauthenticated DH allows an active man-in-the-middle to establish separate keys with each party.</p>

      <div className="control-card pa11-toolbar">
        <button type="button" onClick={runExchange}>Exchange</button>
        <button type="button" onClick={randomizeAll}>Randomize Session</button>
        <label className="pa11-eve-toggle">
          <input type="checkbox" checked={eveEnabled} onChange={(e) => setEveEnabled(e.target.checked)} />
          Enable Eve (MITM)
        </label>
        <span className="status-pill ready">{stepLabel}</span>
      </div>

      <div className="control-grid pa11-group-row">
        <div className="control-card pa11-group-card">
          <h2>Group</h2>
          <p className="kv">p = {toHex(params.p)}</p>
          <p className="kv">q = {toHex(params.q)}</p>
          <p className="kv">g = {toHex(params.g)}</p>
          <p className="kv">Toy safe-prime near 2^32 for instant browser math.</p>
        </div>
      </div>

      <div className="pa11-animation" aria-live="polite">
        <div className="pa11-node-row">
          <span>Alice</span>
          {eveEnabled && <span>Eve</span>}
          <span>Bob</span>
        </div>
        <div className="pa11-track">
          <div
            key={`a-${exchangeSeq}-${eveEnabled ? "eve" : "clean"}`}
            className={[
              "pa11-packet",
              eveEnabled ? "a2b-eve" : "a2b",
              phase === "alice-sent" || phase === "bob-sent" || phase === "done" ? "go" : "",
            ].join(" ")}
          >
            {eveEnabled ? "A intercepted" : "A sent"}
          </div>
          <div
            key={`b-${exchangeSeq}-${eveEnabled ? "eve" : "clean"}`}
            className={[
              "pa11-packet",
              eveEnabled ? "b2a-eve" : "b2a",
              phase === "bob-sent" || phase === "done" ? "go" : "",
            ].join(" ")}
          >
            {eveEnabled ? "B intercepted" : "B sent"}
          </div>
        </div>
      </div>

      <div className="pa11-panels">
        <div className="control-card pa11-party-card">
          <h2>Alice (left)</h2>
          <div className="control-field">
            <label>Private exponent a</label>
            <input
              value={aliceSecretInput}
              onChange={(e) => setAliceSecretInput(e.target.value)}
              spellCheck={false}
              aria-label="Alice private exponent"
            />
          </div>
          <button type="button" className="pa11-mini-btn" onClick={() => setAliceSecretInput(toHex(randomSecret(params)))}>
            Randomize a
          </button>
          <p className="kv">A = g^a mod p = {toHex(model.alicePk)}</p>
          <p className="kv">Received from Bob side = {toHex(model.deliveredToAlice)}</p>
          <p className={model.keysMatch ? "kv pa11-key-ok" : "kv pa11-key-bad"}>Shared K_A = {toHex(model.aliceShared)}</p>
        </div>

        {eveEnabled && (
          <div className="control-card pa11-party-card pa11-eve-card">
            <h2>Eve (MITM)</h2>
            <div className="control-field">
              <label>Eve secret to Bob</label>
              <input
                value={eveToBobInput}
                onChange={(e) => setEveToBobInput(e.target.value)}
                spellCheck={false}
                aria-label="Eve private exponent to Bob"
              />
            </div>
            <div className="control-field">
              <label>Eve secret to Alice</label>
              <input
                value={eveToAliceInput}
                onChange={(e) => setEveToAliceInput(e.target.value)}
                spellCheck={false}
                aria-label="Eve private exponent to Alice"
              />
            </div>
            <p className="kv">Substitute to Bob = {toHex(model.eveToBobPk)}</p>
            <p className="kv">Substitute to Alice = {toHex(model.eveToAlicePk)}</p>
            <p className="kv">Eve with Alice = {model.eveWithAlice === null ? "-" : toHex(model.eveWithAlice)}</p>
            <p className="kv">Eve with Bob = {model.eveWithBob === null ? "-" : toHex(model.eveWithBob)}</p>
          </div>
        )}

        <div className="control-card pa11-party-card">
          <h2>Bob (right)</h2>
          <div className="control-field">
            <label>Private exponent b</label>
            <input
              value={bobSecretInput}
              onChange={(e) => setBobSecretInput(e.target.value)}
              spellCheck={false}
              aria-label="Bob private exponent"
            />
          </div>
          <button type="button" className="pa11-mini-btn" onClick={() => setBobSecretInput(toHex(randomSecret(params)))}>
            Randomize b
          </button>
          <p className="kv">B = g^b mod p = {toHex(model.bobPk)}</p>
          <p className="kv">Received from Alice side = {toHex(model.deliveredToBob)}</p>
          <p className={model.keysMatch ? "kv pa11-key-ok" : "kv pa11-key-bad"}>Shared K_B = {toHex(model.bobShared)}</p>
        </div>
      </div>

      <div className="control-card pa11-summary">
        <h2>Outcome</h2>
        <p className="kv">Alice and Bob match = {String(model.keysMatch)}</p>
        {eveEnabled ? (
          <p className="kv">Eve now holds two separate secrets while Alice and Bob diverge.</p>
        ) : (
          <p className="kv">No attacker: both parties derive the same shared key.</p>
        )}
      </div>
    </section>
  );
}
