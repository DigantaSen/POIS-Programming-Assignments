import { useMemo, useState } from "react";
import {
  CBCTraceBlock,
  CTRTraceBlock,
  ModeId,
  OFBTraceBlock,
  bytesToHex,
  cbcDecryptRaw,
  cbcEncrypt,
  ctrDecrypt,
  ctrEncrypt,
  mutateCipherBlockBit,
  normalizeToThreeBlocks,
  ofbDecrypt,
  ofbEncrypt,
  randomBlock,
  splitToDisplayBlocks,
} from "./modes";

function randomKeyHex(): string {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function changedBlocks(a: string[], b: string[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) out.push(i);
  }
  return out;
}

export default function Pa04Panel() {
  const [keyHex, setKeyHex] = useState(randomKeyHex);
  const [mode, setMode] = useState<ModeId>("CBC");
  const [message, setMessage] = useState("BLOCKMODEDEMO");
  const [animSeed, setAnimSeed] = useState(0);
  const [flipIndex, setFlipIndex] = useState<number | null>(null);

  const [reuseIv, setReuseIv] = useState(false);
  const [reuseA, setReuseA] = useState("HEAD_same_AAA");
  const [reuseB, setReuseB] = useState("HEAD_same_BBB");

  const isKeyValid = /^[0-9a-fA-F]{1,16}$/.test(keyHex);

  const normMsg = useMemo(() => normalizeToThreeBlocks(message), [message]);
  const ptBlocks = useMemo(() => splitToDisplayBlocks(normMsg, 3), [normMsg]);

  const run = useMemo(() => {
    if (!isKeyValid) return null;
    const ivOrNonce = randomBlock();

    if (mode === "CBC") {
      const enc = cbcEncrypt(keyHex, normMsg, ivOrNonce);
      const decRaw = cbcDecryptRaw(keyHex, enc.iv, enc.ct);
      const decBlocks = splitToDisplayBlocks(decRaw.slice(0, 12), 3);

      const mutated =
        flipIndex !== null ? mutateCipherBlockBit(enc.ct, flipIndex) : enc.ct;
      const decMutRaw = cbcDecryptRaw(keyHex, enc.iv, mutated);
      const decMutBlocks = splitToDisplayBlocks(decMutRaw.slice(0, 12), 3);

      return {
        ivHex: bytesToHex(enc.iv),
        ctBlocks: splitToDisplayBlocks(enc.ct, 3),
        decBlocks,
        decMutBlocks,
        affected: changedBlocks(decBlocks, decMutBlocks),
        trace: enc.trace,
      };
    }

    if (mode === "OFB") {
      const enc = ofbEncrypt(keyHex, normMsg, ivOrNonce);
      const dec = ofbDecrypt(keyHex, enc.iv, enc.ct);
      const decBlocks = splitToDisplayBlocks(dec, 3);

      const mutated =
        flipIndex !== null ? mutateCipherBlockBit(enc.ct, flipIndex) : enc.ct;
      const decMut = ofbDecrypt(keyHex, enc.iv, mutated);
      const decMutBlocks = splitToDisplayBlocks(decMut, 3);

      return {
        ivHex: bytesToHex(enc.iv),
        ctBlocks: splitToDisplayBlocks(enc.ct, 3),
        decBlocks,
        decMutBlocks,
        affected: changedBlocks(decBlocks, decMutBlocks),
        trace: enc.trace,
      };
    }

    const enc = ctrEncrypt(keyHex, normMsg, ivOrNonce);
    const dec = ctrDecrypt(keyHex, enc.nonce, enc.ct);
    const decBlocks = splitToDisplayBlocks(dec, 3);

    const mutated =
      flipIndex !== null ? mutateCipherBlockBit(enc.ct, flipIndex) : enc.ct;
    const decMut = ctrDecrypt(keyHex, enc.nonce, mutated);
    const decMutBlocks = splitToDisplayBlocks(decMut, 3);

    return {
      ivHex: bytesToHex(enc.nonce),
      ctBlocks: splitToDisplayBlocks(enc.ct, 3),
      decBlocks,
      decMutBlocks,
      affected: changedBlocks(decBlocks, decMutBlocks),
      trace: enc.trace,
    };
  }, [flipIndex, isKeyValid, keyHex, mode, normMsg, animSeed]);

  const reuseDemo = useMemo(() => {
    if (!isKeyValid) return null;
    const a = normalizeToThreeBlocks(reuseA);
    const b = normalizeToThreeBlocks(reuseB);
    const iv = randomBlock();
    const ca = cbcEncrypt(keyHex, a, iv).ct;
    const cb = cbcEncrypt(keyHex, b, iv).ct;

    const caBlocks = splitToDisplayBlocks(ca, 3);
    const cbBlocks = splitToDisplayBlocks(cb, 3);
    const matches = caBlocks.map((blk, i) => blk === cbBlocks[i]);
    return { ivHex: bytesToHex(iv), caBlocks, cbBlocks, matches };
  }, [isKeyValid, keyHex, reuseA, reuseB, animSeed]);

  const expected = mode === "CBC" ? "2 blocks" : "same block only";

  return (
    <div className="pa04-shell">
      <section className="pa04-hero">
        <div className="pa01-hero-badge" style={{ background: "rgba(92,44,18,0.25)", borderColor: "rgba(238,159,87,0.45)", color: "#f0c78e" }}>
          PA #4
        </div>
        <h2 className="pa04-hero-title">Modes of Operation Animator</h2>
        <p className="pa04-hero-sub">
          CBC, OFB, CTR with 3-block live trace, ciphertext bit-flip impact, and CBC IV-reuse leak visualization.
        </p>
      </section>

      <section className="pa04-controls">
        <div className="pa04-control-card">
          <div className="pa01-control-label">
            <label htmlFor="pa04-key">Key k (hex)</label>
            <button
              type="button"
              className="pa01-random-btn"
              onClick={() => {
                setKeyHex(randomKeyHex());
                setAnimSeed((n) => n + 1);
                setFlipIndex(null);
              }}
            >
              ↻ New Key
            </button>
          </div>
          <input
            id="pa04-key"
            className={`pa01-hex-input${isKeyValid ? "" : " error"}`}
            value={keyHex}
            onChange={(e) => setKeyHex(e.target.value)}
            spellCheck={false}
          />
        </div>

        <div className="pa04-control-card">
          <div className="pa01-control-label">
            <label htmlFor="pa04-msg">3-block message (12 bytes)</label>
            <button
              type="button"
              className="pa01-random-btn"
              onClick={() => {
                setAnimSeed((n) => n + 1);
                setFlipIndex(null);
              }}
            >
              Rerun Animation
            </button>
          </div>
          <input
            id="pa04-msg"
            className="pa01-hex-input"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
          <div className="pa04-note">Normalized to exactly 12 bytes for visualization.</div>
        </div>
      </section>

      <section className="pa04-mode-tabs">
        {(["CBC", "OFB", "CTR"] as ModeId[]).map((m) => (
          <button
            key={m}
            type="button"
            className={`pa04-mode-btn${mode === m ? " active" : ""}`}
            onClick={() => {
              setMode(m);
              setFlipIndex(null);
              setAnimSeed((n) => n + 1);
            }}
          >
            {m}
          </button>
        ))}
      </section>

      {!run ? (
        <div className="pa01-warn">Enter a valid hex key first.</div>
      ) : (
        <>
          <section className="pa04-chain" key={`${mode}-${animSeed}`}>
            <div className="pa04-chain-head">
              <span className="pa01-output-title">{mode} Chain (3 blocks)</span>
              <span className="pa01-output-meta">
                {mode === "CTR" ? "nonce" : "iv"} = {run.ivHex}
              </span>
            </div>

            <div className="pa04-block-grid">
              {ptBlocks.map((pt, i) => (
                <div key={`pt-${i}`} className="pa04-block-col">
                  <div className="pa04-tag">M{i + 1}</div>
                  <div className="pa04-block">{pt}</div>
                  <div className="pa04-arrow">↓</div>
                  <TraceCell mode={mode} trace={run.trace} index={i} />
                  <div className="pa04-arrow">↓</div>
                  <button
                    type="button"
                    className={`pa04-block pa04-ct${flipIndex === i ? " chosen" : ""}`}
                    onClick={() => setFlipIndex(i)}
                    title="Flip one bit in this ciphertext block"
                  >
                    {run.ctBlocks[i]}
                  </button>
                  <div className="pa04-tag">C{i + 1}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="pa04-flip-section">
            <div className="pa04-chain-head">
              <span className="pa01-output-title">Flip Ciphertext Bit</span>
              <span className="pa01-output-meta">Expected pattern: {expected}</span>
            </div>

            <div className="pa04-flip-row">
              <button
                type="button"
                className="pa03-primary-btn"
                onClick={() => setFlipIndex((idx) => (idx === null ? 0 : (idx + 1) % 3))}
              >
                Flip Next Block Bit
              </button>
              <button
                type="button"
                className="pa01-random-btn"
                onClick={() => setFlipIndex(null)}
              >
                Reset Flip
              </button>
            </div>

            <div className="pa04-dec-grid">
              {run.decMutBlocks.map((blk, i) => (
                <div key={`d-${i}`} className={`pa04-dec-card${run.affected.includes(i) ? " corrupt" : ""}`}>
                  <div className="pa04-tag">P{i + 1} after decrypt</div>
                  <div className="pa04-block">{blk}</div>
                </div>
              ))}
            </div>
            <div className="pa04-note">
              Corrupted plaintext blocks: {run.affected.length ? run.affected.map((i) => i + 1).join(", ") : "none"}
            </div>
          </section>

          <section className="pa04-reuse-section">
            <div className="pa04-chain-head">
              <span className="pa01-output-title">CBC IV-Reuse Demo</span>
              <label className="pa04-toggle">
                <input
                  type="checkbox"
                  checked={reuseIv}
                  onChange={(e) => setReuseIv(e.target.checked)}
                />
                Reuse IV
              </label>
            </div>

            <div className="pa04-reuse-inputs">
              <input
                className="pa01-hex-input"
                value={reuseA}
                onChange={(e) => setReuseA(e.target.value)}
                placeholder="message A"
              />
              <input
                className="pa01-hex-input"
                value={reuseB}
                onChange={(e) => setReuseB(e.target.value)}
                placeholder="message B"
              />
            </div>

            {reuseIv && reuseDemo && (
              <>
                <div className="pa04-note">Shared IV: {reuseDemo.ivHex}</div>
                <div className="pa04-reuse-grid">
                  {reuseDemo.caBlocks.map((blk, i) => (
                    <div key={`ra-${i}`} className={`pa04-reuse-card${reuseDemo.matches[i] ? " match" : ""}`}>
                      <div className="pa04-tag">C{i + 1}(A)</div>
                      <div className="pa04-block">{blk}</div>
                    </div>
                  ))}
                </div>
                <div className="pa04-reuse-grid">
                  {reuseDemo.cbBlocks.map((blk, i) => (
                    <div key={`rb-${i}`} className={`pa04-reuse-card${reuseDemo.matches[i] ? " match" : ""}`}>
                      <div className="pa04-tag">C{i + 1}(B)</div>
                      <div className="pa04-block">{blk}</div>
                    </div>
                  ))}
                </div>
                <div className="pa04-note">
                  Matching ciphertext blocks are highlighted in red when corresponding plaintext blocks are equal under reused IV.
                </div>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function TraceCell({ mode, trace, index }: { mode: ModeId; trace: CBCTraceBlock[] | OFBTraceBlock[] | CTRTraceBlock[]; index: number }) {
  const baseStyle = { animationDelay: `${index * 90}ms` };

  if (mode === "CBC") {
    const t = trace[index] as CBCTraceBlock;
    return (
      <div className="pa04-trace" style={baseStyle}>
        <div className="pa04-trace-line">XOR: {t.prevHex} ⊕ {t.ptHex}</div>
        <div className="pa04-trace-line">Eₖ: {t.xorHex}</div>
      </div>
    );
  }

  if (mode === "OFB") {
    const t = trace[index] as OFBTraceBlock;
    return (
      <div className="pa04-trace" style={baseStyle}>
        <div className="pa04-trace-line">state: {t.stateInHex}</div>
        <div className="pa04-trace-line">ks=Eₖ(state): {t.ksHex}</div>
      </div>
    );
  }

  const t = trace[index] as CTRTraceBlock;
  return (
    <div className="pa04-trace" style={baseStyle}>
      <div className="pa04-trace-line">ctr: {t.counterHex}</div>
      <div className="pa04-trace-line">ks=Eₖ(ctr): {t.ksHex}</div>
    </div>
  );
}
