import { useEffect, useMemo, useState } from "react";
import { decryptText, encryptText, hexToBytes } from "./enc";
import {
  fixedTimeHexEqual,
  forgeNaiveLengthExtension,
  hmacPa08TagHex,
  naiveMacTagHex,
  randomKeyHex,
  strBytes,
  verifyHmac,
  verifyNaive,
  // sha256 helpers
  hmacSha256TagHex,
  naiveSha256TagHex,
  verifyHmacSha256,
} from "./pa10hmac";

export default function Pa10Panel() {
  const [message, setMessage] = useState("amount=100&to=bob");
  const [suffix, setSuffix] = useState("&admin=true");
  const [keyHex, setKeyHex] = useState(randomKeyHex());
  const [hashBackend, setHashBackend] = useState<"PA08" | "SHA256">("PA08");
  const [macMode, setMacMode] = useState<"naive" | "hmac">("hmac");
  const [eufcmaRunning, setEufcmaRunning] = useState(false);
  const [eufcmaResult, setEufcmaResult] = useState<string | null>(null);

  // sync PA08 tags
  const pa08NaiveTag = useMemo(() => naiveMacTagHex(hexToBytes(keyHex), strBytes(message)), [keyHex, message]);
  const pa08HmacTag = useMemo(() => hmacPa08TagHex(hexToBytes(keyHex), strBytes(message)), [keyHex, message]);

  // async SHA-256 tags (cached in state)
  const [shaNaiveTag, setShaNaiveTag] = useState<string>("");
  const [shaHmacTag, setShaHmacTag] = useState<string>("");

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const k = hexToBytes(keyHex);
        const m = strBytes(message);
        const naive = await naiveSha256TagHex(k, m);
        const hmac = await hmacSha256TagHex(k, m);
        if (mounted) {
          setShaNaiveTag(naive);
          setShaHmacTag(hmac);
        }
      } catch (e) {
        // ignore
      }
    })();
    return () => {
      mounted = false;
    };
  }, [keyHex, message]);

  const naiveTag = hashBackend === "PA08" ? pa08NaiveTag : shaNaiveTag;
  const hmacTag = hashBackend === "PA08" ? pa08HmacTag : shaHmacTag;

  const forged = useMemo(() => forgeNaiveLengthExtension(strBytes(message), pa08NaiveTag, strBytes(suffix), 8), [message, pa08NaiveTag, suffix]);

  const naiveForgedValid = useMemo(() => verifyNaive(hexToBytes(keyHex), forged.forgedMsgBytes, forged.forgedTagHex), [forged, keyHex]);
  const hmacForgedValid = useMemo(() => verifyHmac(hexToBytes(keyHex), forged.forgedMsgBytes, forged.forgedTagHex), [forged, keyHex]);

  const [encKey] = useState(() => randomKeyHex());
  const etm = useMemo(() => {
    const c = encryptText(encKey, "transfer=42");
    const aad = `${c.nonce.toString(16).padStart(2, "0")}${c.ctHex}`;
    const tag = hmacPa08TagHex(hexToBytes(keyHex), hexToBytes(aad));

    const plain = decryptText(encKey, c.nonce, c.ctHex);

    const tamperedCt = c.ctHex.length >= 2 ? `${(parseInt(c.ctHex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0")}${c.ctHex.slice(2)}` : c.ctHex;
    const tamperedAad = `${c.nonce.toString(16).padStart(2, "0")}${tamperedCt}`;
    const tamperedTagOk = fixedTimeHexEqual(tag, hmacPa08TagHex(hexToBytes(keyHex), hexToBytes(tamperedAad)));

    return { c, tag, plain, tamperedCt, tamperedTagOk };
  }, [encKey, keyHex]);

  // Copy forged message bytes to clipboard
  const copyForged = async () => {
    try {
      await navigator.clipboard.writeText(forged.forgedMsgBytes.reduce((s, b) => s + b.toString(16).padStart(2, "0"), ""));
      // small feedback
      setEufcmaResult("Forged message copied to clipboard");
      setTimeout(() => setEufcmaResult(null), 1200);
    } catch {
      setEufcmaResult("Copy failed");
      setTimeout(() => setEufcmaResult(null), 1200);
    }
  };

  // EUF-CMA harness: query oracle 50 times and attempt a length-extension forgery
  const runEufcma = async () => {
    setEufcmaRunning(true);
    setEufcmaResult(null);
    const oracleCount = 50;
    const k = hexToBytes(keyHex);

    let lastMsg: Uint8Array | null = null;
    let lastTag: string | null = null;

    for (let i = 0; i < oracleCount; i++) {
      const rnd = crypto.getRandomValues(new Uint8Array(8));
      lastMsg = rnd;
      if (macMode === "naive") {
        if (hashBackend === "PA08") {
          lastTag = naiveMacTagHex(k, rnd);
        } else {
          lastTag = await naiveSha256TagHex(k, rnd);
        }
      } else {
        if (hashBackend === "PA08") {
          lastTag = hmacPa08TagHex(k, rnd);
        } else {
          lastTag = await hmacSha256TagHex(k, rnd);
        }
      }
    }

    // Attempt length-extension forgery only for PA08 naive case (we can glue/resume there).
    if (hashBackend === "PA08" && macMode === "naive" && lastMsg && lastTag) {
      const attempt = forgeNaiveLengthExtension(lastMsg, lastTag, strBytes(suffix), 8);
      const ok = verifyNaive(k, attempt.forgedMsgBytes, attempt.forgedTagHex);
      setEufcmaResult(`forged? ${String(ok)} after ${oracleCount} queries (PA08 naive)`);
    } else {
      // For HMAC or SHA-256 backed HMAC, length-extension should not work; report attempt and test using verification function if available.
      if (lastMsg && lastTag) {
        // Try naive verification where possible or HMAC verify for PA08
        let ok = false;
        if (hashBackend === "PA08") {
          // verify using naive or hmac depending on macMode
          ok = macMode === "naive" ? verifyNaive(k, forged.forgedMsgBytes, forged.forgedTagHex) : verifyHmac(k, forged.forgedMsgBytes, forged.forgedTagHex);
        } else {
          // SHA256-backed verification for HMAC
          if (macMode === "hmac") {
            ok = await verifyHmacSha256(k, forged.forgedMsgBytes, forged.forgedTagHex);
          } else {
            // naive SHA-256 forging not implemented; report not attempted
            setEufcmaResult("Naive length-extension for SHA-256 not attempted in this demo");
            setEufcmaRunning(false);
            return;
          }
        }
        setEufcmaResult(`forged? ${String(ok)} after ${oracleCount} queries (${hashBackend} ${macMode})`);
      }
    }

    setEufcmaRunning(false);
  };

  return (
    <section className="panel" aria-label="PA10 panel">
      <h3>PA #10: HMAC and Encrypt-then-HMAC</h3>
      <p className="panel-note">Length-extension breaks naive H(k||m), while HMAC and EtM protect integrity.</p>

      <div className="control-grid">
        <div className="control-card">
          <h2>Backend / Mode</h2>
          <div className="control-field">
            <label htmlFor="pa10-backend">Hash backend</label>
            <select id="pa10-backend" value={hashBackend} onChange={(e) => setHashBackend(e.target.value as any)}>
              <option value="PA08">PA08 (toy DLP hash)</option>
              <option value="SHA256">SHA-256</option>
            </select>
          </div>
          <div className="control-field">
            <label htmlFor="pa10-macmode">MAC mode</label>
            <select id="pa10-macmode" value={macMode} onChange={(e) => setMacMode(e.target.value as any)}>
              <option value="hmac">HMAC</option>
              <option value="naive">Naive H(k||m)</option>
            </select>
          </div>
          <div style={{ marginTop: "0.5rem" }}>
            <button type="button" className="segment-row button" onClick={runEufcma} disabled={eufcmaRunning}>
              {eufcmaRunning ? "Running EUF-CMA..." : "Run EUF-CMA (50 queries)"}
            </button>
            {eufcmaResult ? <span style={{ marginLeft: "0.6rem", fontWeight: 800 }}>{eufcmaResult}</span> : null}
          </div>
        </div>
        <div className="control-card" style={{ gridColumn: "1 / -1" }}>
          <div className="control-field">
            <label htmlFor="pa10-msg">Message</label>
            <input id="pa10-msg" value={message} onChange={(e) => setMessage(e.target.value)} spellCheck={false} />
          </div>
          <div className="control-field">
            <label htmlFor="pa10-suffix">Attacker suffix</label>
            <input id="pa10-suffix" value={suffix} onChange={(e) => setSuffix(e.target.value)} spellCheck={false} />
          </div>
          <button type="button" onClick={() => setKeyHex(randomKeyHex())}>New MAC Key</button>
        </div>

        <div className="control-card">
          <h2>Tags</h2>
          <p className="kv">Naive tag</p><div className="hex">{naiveTag || "..."}</div>
          <p className="kv">HMAC tag</p><div className="hex">{hmacTag || "..."}</div>
        </div>

        <div className="control-card">
          <h2>Length Extension</h2>
          <p className="kv">Glue pad: {forged.gluePadHex || "-"}</p>
          <p className="kv">Forged tag: {forged.forgedTagHex}</p>
          <p className="kv">Naive accepts forged: {String(naiveForgedValid)}</p>
          <p className="kv">HMAC accepts forged: {String(hmacForgedValid)}</p>
          <p className="kv">Forged message (hex)</p>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <div className="hex" style={{ flex: 1 }}>{forged.forgedMsgBytes.reduce((s, b) => s + b.toString(16).padStart(2, "0"), "")}</div>
            <button type="button" className="copy-btn" onClick={copyForged}>Copy</button>
          </div>
        </div>
      </div>

      <div className="control-card" style={{ marginTop: "0.8rem" }}>
        <h2>Encrypt-then-HMAC (CCA style)</h2>
        <p className="kv">Ciphertext nonce={etm.c.nonce}, ct={etm.c.ctHex}, tag={etm.tag}</p>
        <p className="kv">Decrypt(valid) = {etm.plain}</p>
        <p className="kv">Tampered ct accepted by tag check = {String(etm.tamperedTagOk)} (expected false)</p>
      </div>
    </section>
  );
}
