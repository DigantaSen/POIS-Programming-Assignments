import { useMemo, useState } from "react";
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
} from "./pa10hmac";

export default function Pa10Panel() {
  const [message, setMessage] = useState("amount=100&to=bob");
  const [suffix, setSuffix] = useState("&admin=true");
  const [keyHex, setKeyHex] = useState(randomKeyHex());

  const naiveTag = useMemo(() => naiveMacTagHex(hexToBytes(keyHex), strBytes(message)), [keyHex, message]);
  const hmacTag = useMemo(() => hmacPa08TagHex(hexToBytes(keyHex), strBytes(message)), [keyHex, message]);

  const forged = useMemo(
    () => forgeNaiveLengthExtension(strBytes(message), naiveTag, strBytes(suffix), 8),
    [message, naiveTag, suffix],
  );

  const naiveForgedValid = useMemo(
    () => verifyNaive(hexToBytes(keyHex), forged.forgedMsgBytes, forged.forgedTagHex),
    [forged, keyHex],
  );
  const hmacForgedValid = useMemo(
    () => verifyHmac(hexToBytes(keyHex), forged.forgedMsgBytes, forged.forgedTagHex),
    [forged, keyHex],
  );

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

  return (
    <section className="panel" aria-label="PA10 panel">
      <h3>PA #10: HMAC and Encrypt-then-HMAC</h3>
      <p className="panel-note">Length-extension breaks naive H(k||m), while HMAC and EtM protect integrity.</p>

      <div className="control-grid">
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
          <p className="kv">Naive tag</p><div className="hex">{naiveTag}</div>
          <p className="kv">HMAC tag</p><div className="hex">{hmacTag}</div>
        </div>

        <div className="control-card">
          <h2>Length Extension</h2>
          <p className="kv">Glue pad: {forged.gluePadHex || "-"}</p>
          <p className="kv">Forged tag: {forged.forgedTagHex}</p>
          <p className="kv">Naive accepts forged: {String(naiveForgedValid)}</p>
          <p className="kv">HMAC accepts forged: {String(hmacForgedValid)}</p>
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
