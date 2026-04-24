import { useMemo, useState } from "react";
import { genSafePrime, keygen, mitmDemo, shared } from "./pa11dh";

export default function Pa11Panel() {
  const [seed, setSeed] = useState(0);

  const model = useMemo(() => {
    void seed;
    const params = genSafePrime(30);
    const alice = keygen(params);
    const bob = keygen(params);
    const kAlice = shared(params, alice.sk, bob.pk);
    const kBob = shared(params, bob.sk, alice.pk);
    const mitm = mitmDemo(params);
    return { params, alice, bob, kAlice, kBob, mitm };
  }, [seed]);

  return (
    <section className="panel" aria-label="PA11 panel">
      <h3>PA #11: Diffie-Hellman and MITM</h3>
      <p className="panel-note">Unauthenticated DH allows an active man-in-the-middle to establish separate keys with each party.</p>

      <div className="control-card" style={{ marginBottom: "0.8rem" }}>
        <button type="button" onClick={() => setSeed((s) => s + 1)}>Generate New Session</button>
      </div>

      <div className="control-grid">
        <div className="control-card">
          <h2>Group</h2>
          <p className="kv">p = {model.params.p}</p>
          <p className="kv">q = {model.params.q}</p>
          <p className="kv">g = {model.params.g}</p>
        </div>

        <div className="control-card">
          <h2>Honest Exchange</h2>
          <p className="kv">A = g^a mod p = {model.alice.pk}</p>
          <p className="kv">B = g^b mod p = {model.bob.pk}</p>
          <p className="kv">Alice key = {model.kAlice}</p>
          <p className="kv">Bob key = {model.kBob}</p>
          <p className="kv">Keys match = {String(model.kAlice === model.kBob)}</p>
        </div>

        <div className="control-card">
          <h2>MITM Outcome</h2>
          <p className="kv">Alice compromised = {String(model.mitm.aliceCompromised)}</p>
          <p className="kv">Bob compromised = {String(model.mitm.bobCompromised)}</p>
          <p className="kv">Alice and Bob still equal = {String(model.mitm.aliceBobStillEqual)}</p>
        </div>
      </div>
    </section>
  );
}
