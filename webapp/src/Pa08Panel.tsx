import { useMemo, useState } from "react";
import { pa08HashText, pa08HashNBits, textToBytes } from "./pa08hash";

export default function Pa08Panel() {
  const [message, setMessage] = useState("PA08-message-one");
  const [nBits, setNBits] = useState(16);

  const digest = useMemo(() => pa08HashText(message), [message]);
  const truncated = useMemo(() => pa08HashNBits(textToBytes(message), nBits), [message, nBits]);

  return (
    <section className="panel" aria-label="PA08 panel">
      <h3>PA #8: DLP-Style Compression Hash</h3>
      <p className="panel-note">
        Merkle-Damgard domain extension with toy DLP-style compression. Use this panel to inspect digest output and n-bit truncation.
      </p>

      <div className="control-grid">
        <div className="control-card" style={{ gridColumn: "1 / -1" }}>
          <div className="control-field">
            <label htmlFor="pa08-msg">Message</label>
            <input
              id="pa08-msg"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type any message"
              spellCheck={false}
            />
          </div>
        </div>

        <div className="control-card">
          <h2>Digest</h2>
          <p className="kv">H(M) (32-bit hex)</p>
          <div className="hex">{digest}</div>
        </div>

        <div className="control-card">
          <h2>Truncation</h2>
          <div className="control-field">
            <label htmlFor="pa08-nbits">Output bits n = {nBits}</label>
            <input
              id="pa08-nbits"
              type="range"
              min={8}
              max={32}
              value={nBits}
              onChange={(e) => setNBits(Number(e.target.value))}
            />
          </div>
          <p className="kv">H_n(M)</p>
          <div className="hex">{truncated.toString(16).padStart(Math.max(2, Math.ceil(nBits / 4)), "0")}</div>
        </div>
      </div>

      <div className="warn" style={{ marginTop: "0.8rem" }}>
        Security note: truncated outputs are intentionally vulnerable to birthday attacks (PA09).
      </div>
    </section>
  );
}
