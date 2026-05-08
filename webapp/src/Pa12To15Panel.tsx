import { useState } from "react";

type Pa12To15Assignment = "pa12" | "pa13" | "pa14" | "pa15";

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
	let result = 1n;
	let b = base % mod;
	if (b < 0n) b += mod;
	let e = exp;
	while (e > 0n) {
		if (e & 1n) result = (result * b) % mod;
		b = (b * b) % mod;
		e >>= 1n;
	}
	return result;
}

function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
	if (a === 0n) return [b, 0n, 1n];
	const [g, y, x] = egcd(b % a, a);
	return [g, x - (b / a) * y, y];
}

function modInverse(a: bigint, mod: bigint): bigint {
	const [g, x] = egcd(a, mod);
	if (g !== 1n) throw new Error("Inverse does not exist");
	return ((x % mod) + mod) % mod;
}



function randomBytes(length: number): Uint8Array {
	const bytes = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		bytes[i] = Math.floor(Math.random() * 255) + 1;
	}
	return bytes;
}

// ---- PA13 Math ----
function millerRabin(n: bigint, k: number): { prime: boolean, witnesses: string[] } {
	if (n <= 1n) return { prime: false, witnesses: [] };
	if (n <= 3n) return { prime: true, witnesses: [] };
	if (n % 2n === 0n) return { prime: false, witnesses: [] };

	let d = n - 1n;
	let s = 0n;
	while (d % 2n === 0n) {
		d /= 2n;
		s += 1n;
	}

	const witnesses: string[] = [];
	for (let i = 0; i < k; i++) {
		// Just random base
		const a = BigInt(Math.floor(Math.random() * (Number(n > 100000n ? 100000n : n) - 2)) + 2);
		let x = modPow(a, d, n);
		witnesses.push(`Round ${i + 1}: base a=${a}, x=${x}`);

		if (x === 1n || x === n - 1n) continue;

		let composite = true;
		for (let r = 1n; r < s; r++) {
			x = modPow(x, 2n, n);
			if (x === n - 1n) {
				composite = false;
				break;
			}
		}

		if (composite) {
			witnesses.push(`Composite detected at round ${i + 1}`);
			return { prime: false, witnesses };
		}
	}

	return { prime: true, witnesses };
}

function fermatTest(n: bigint): boolean {
	if (n <= 1n) return false;
	if (n <= 3n) return true;
	const a = 2n;
	return modPow(a, n - 1n, n) === 1n;
}

// ---- PA12 Math ----
interface RsaKey {
	n: bigint;
	e: bigint;
	d?: bigint;
}

function rsaEncrypt(pk: RsaKey, m: bigint): bigint {
	return modPow(m, pk.e, pk.n);
}

// Fixed toy 256-bit RSA key to prevent UI blocking during keygen
const TOY_RSA_KEY: RsaKey = {
	n: 66141445763155823528476839352668581005886470438171120401768688407421115160867n,
	e: 65537n,
	d: 13917540454341997232231011684705574041793393510903333116868512403698059635713n
};

// ---- PA14 Math ----
function crt(residues: bigint[], moduli: bigint[]): bigint {
	let N = 1n;
	for (const m of moduli) N *= m;

	let x = 0n;
	for (let i = 0; i < residues.length; i++) {
		const a = residues[i];
		const m = moduli[i];
		const m_i = N / m;
		const y = modInverse(m_i, m);
		x = (x + a * m_i * y) % N;
	}
	return x;
}

function intCubeRoot(x: bigint): bigint {
	if (x === 0n) return 0n;
	let high = 1n;
	while (high ** 3n <= x) high *= 2n;
	let low = high / 2n;
	while (low < high) {
		const mid = (low + high) / 2n;
		const mid3 = mid ** 3n;
		if (mid3 === x) return mid;
		if (mid3 < x) {
			if (low === mid) break;
			low = mid;
		} else {
			high = mid;
		}
	}
	return low;
}

// ---- PA15 Math ----
function hashToBigInt(msg: string): bigint {
	let hash = 2166136261n;
	for (let i = 0; i < msg.length; i++) {
		hash ^= BigInt(msg.charCodeAt(i));
		hash = (hash * 16777619n) % 100000000000000000n; // Basic large modulus
	}
	return hash;
}

// Components

function Pa12Card() {
	const [message, setMessage] = useState("yes");
	const [ciphertexts, setCiphertexts] = useState<string[]>([]);
	const [mode, setMode] = useState<"textbook" | "pkcs">("textbook");
	const [paddingBytes, setPaddingBytes] = useState<string[]>([]);

	const handleEncrypt = () => {
		const msgBytes = new TextEncoder().encode(message);
		const cList: string[] = [];
		const pList: string[] = [];

		for (let i = 0; i < 2; i++) {
			let mInt: bigint;
			if (mode === "textbook") {
				// Convert raw bytes to bigint directly
				let hex = "0x";
				for (const b of msgBytes) hex += b.toString(16).padStart(2, "0");
				mInt = BigInt(hex);
			} else {
				// PKCS#1 v1.5 Toy Pad (Total 32 bytes)
				const k = 32;
				const psLen = k - msgBytes.length - 3;
				const ps = randomBytes(psLen);
				pList.push(Array.from(ps).map(b => b.toString(16).padStart(2, "0")).join(" "));

				let hex = "0x0002";
				for (const b of ps) hex += b.toString(16).padStart(2, "0");
				hex += "00";
				for (const b of msgBytes) hex += b.toString(16).padStart(2, "0");
				mInt = BigInt(hex);
			}
			cList.push(rsaEncrypt(TOY_RSA_KEY, mInt).toString());
		}

		setCiphertexts(cList);
		setPaddingBytes(pList);
	};

	const identical = ciphertexts.length === 2 && ciphertexts[0] === ciphertexts[1];

	return (
		<>
			<div className="control-card">
				<div className="control-field">
					<label>Message (Vote/Coin flip)</label>
					<input value={message} onChange={e => setMessage(e.target.value)} maxLength={10} />
				</div>

				<div className="segment-row" style={{ marginTop: 10, marginBottom: 10 }}>
					<button className={mode === "textbook" ? "active" : ""} onClick={() => setMode("textbook")}>
						Textbook Mode
					</button>
					<button className={mode === "pkcs" ? "active" : ""} onClick={() => setMode("pkcs")}>
						PKCS#1 v1.5 Mode
					</button>
				</div>

				<button onClick={handleEncrypt} className="action-btn">Encrypt Twice</button>
			</div>

			{ciphertexts.length > 0 && (
				<div className="step-card">
					<div className="step-head">
						<strong>Encryption Results</strong>
						{identical ? (
							<span className="status-pill warn">Identical ciphertexts: plaintext leaked</span>
						) : (
							<span className="status-pill ready">Secure: Ciphertexts differ</span>
						)}
					</div>
					<p className="kv">Ciphertext 1</p>
					<div className="hex" style={{ wordBreak: "break-all" }}>{ciphertexts[0]}</div>
					<p className="kv">Ciphertext 2</p>
					<div className="hex" style={{ wordBreak: "break-all" }}>{ciphertexts[1]}</div>

					{mode === "pkcs" && paddingBytes.length === 2 && (
						<div style={{ marginTop: 15 }}>
							<p className="kv">Random Padding Bytes (PS) used:</p>
							<div className="hex">Enc 1: {paddingBytes[0]}</div>
							<div className="hex">Enc 2: {paddingBytes[1]}</div>
						</div>
					)}
				</div>
			)}
		</>
	);
}

function Pa13Card() {
	const [numStr, setNumStr] = useState("561");
	const [rounds, setRounds] = useState(40);
	const [result, setResult] = useState<{ prime: boolean, time: number, witnesses: string[], fermatOk: boolean } | null>(null);

	const runTest = (targetVal: string) => {
		try {
			const n = BigInt(targetVal);
			const iter = 100;
			let fermatResult = false;
			let mr: { prime: boolean, witnesses: string[] } | null = null;
			
			const st = performance.now();
			for (let i = 0; i < iter; i++) {
				fermatResult = fermatTest(n);
				mr = millerRabin(n, rounds);
			}
			const time = Math.max((performance.now() - st) / iter, 0.0001); // fallback to min 0.1us
			setResult({ prime: mr!.prime, time, witnesses: mr!.witnesses, fermatOk: fermatResult });
		} catch (e) {
			alert("Invalid integer");
		}
	};

	return (
		<>
			<div className="control-card">
				<div className="segment-row" style={{ marginBottom: 15 }}>
					<button onClick={() => { setNumStr("561"); runTest("561"); }}>561 (Carmichael)</button>
					<button onClick={() => { setNumStr("104729"); runTest("104729"); }}>104729 (Known Prime)</button>
					<button onClick={() => { setNumStr("65535"); runTest("65535"); }}>65535 (Composite)</button>
				</div>

				<div className="control-field">
					<label>Number to test</label>
					<input value={numStr} onChange={e => setNumStr(e.target.value)} />
				</div>
				<div className="control-field">
					<label>Rounds (k: 1-40) : {rounds}</label>
					<input type="range" min={1} max={40} value={rounds} onChange={e => setRounds(Number(e.target.value))} />
				</div>
				<button onClick={() => runTest(numStr)} className="action-btn" style={{ marginTop: 10 }}>Test Primality</button>
			</div>

			{result && (
				<div className="step-card">
					<div className="step-head">
						<strong>Result: {result.prime ? "PROBABLY PRIME" : "COMPOSITE"}</strong>
						<span className="status-pill">{result.time < 0.01 ? (result.time * 1000).toFixed(1) + " µs" : result.time.toFixed(2) + " ms"}</span>
					</div>
					<p className="kv">Fermat Test (Base 2): {result.fermatOk ? "PRIME" : "COMPOSITE"}</p>
					{numStr === "561" && (
						<p className="warn">Notice that Fermat returns PRIME for 561! It is fooled because 561 is a Carmichael number. Miller-Rabin catches it.</p>
					)}
					<p className="kv" style={{ marginTop: 10 }}>Witness Logs:</p>
					<div className="hex" style={{ maxHeight: 200, overflowY: "auto" }}>
						{result.witnesses.map((w, i) => <div key={i}>{w}</div>)}
					</div>
				</div>
			)}
		</>
	);
}

function Pa14Card() {
	const [messageStr, setMessageStr] = useState("42");
	const [usePadding, setUsePadding] = useState(false);
	const [attackResult, setAttackResult] = useState<{ recovered: string, m3: string, cTexts: bigint[], moduli: bigint[] } | null>(null);

	// Static small moduli for Hastad Demo (64 bit size)
	const M = [
		11029272338421874211n,
		14983050411130386123n,
		10459521360061803713n
	];

	const runAttack = () => {
		try {
			const m = BigInt(messageStr);
			if (m > 1000n) {
				alert("Keep message small (e.g. under 1000) for unpadded e=3 toy demo");
				return;
			}

			const e = 3n;
			const ciphertexts: bigint[] = [];
			for (let i = 0; i < 3; i++) {
				let padded = m;
				if (usePadding) {
					// Simulate PKCS by adding random high bits
					padded = m + (BigInt(Math.floor(Math.random() * 1000000) + 1000) << 20n);
				}
				ciphertexts.push(modPow(padded, e, M[i]));
			}

			// Attacker reconstructs
			const m3 = crt(ciphertexts, M);
			let recovered = "";
			try {
				const root = intCubeRoot(m3);
				recovered = root.toString();
			} catch (err) {
				recovered = "Garbage/Error (not a perfect cube)";
			}

			setAttackResult({ recovered, m3: m3.toString(), cTexts: ciphertexts, moduli: M });

		} catch (e) {
			alert("Invalid message integer");
		}
	};

	return (
		<>
			<div className="control-card">
				<div className="control-field">
					<label>Short Message (Integer)</label>
					<input value={messageStr} onChange={e => setMessageStr(e.target.value)} />
				</div>
				<div className="control-field" style={{ flexDirection: "row", alignItems: "center", gap: 10, marginTop: 10 }}>
					<input type="checkbox" id="use-pad" checked={usePadding} onChange={e => setUsePadding(e.target.checked)} />
					<label htmlFor="use-pad">Use PKCS Padding simulation</label>
				</div>
				<button onClick={runAttack} className="action-btn" style={{ marginTop: 10 }}>Broadcast & Attack</button>
			</div>

			{attackResult && (
				<div className="step-card">
					<div className="step-head">
						<strong>Attacker Intercept Log</strong>
					</div>
					{attackResult.cTexts.map((c, i) => (
						<div key={i} style={{ marginBottom: 10 }}>
							<p className="kv">Recipient {i + 1} (Modulus {attackResult.moduli[i].toString()})</p>
							<div className="hex">c = {c.toString()}</div>
						</div>
					))}

					<div style={{ marginTop: 15, borderTop: "1px solid #444", paddingTop: 10 }}>
						<p className="kv">CRT Recovered m³ mod N1*N2*N3:</p>
						<div className="hex">{attackResult.m3}</div>
						<p className="kv" style={{ marginTop: 10 }}>Extracted Plaintext (Integer Cube Root):</p>
						<div className="hex">{attackResult.recovered}</div>
					</div>

					{usePadding ? (
						<p className="warn" style={{ marginTop: 10 }}>Attack FAILS because padding randomized the m value per recipient. The CRT output is no longer a perfect cube.</p>
					) : (
						<p className="status-pill ready" style={{ marginTop: 10 }}>Attack SUCCEEDS! Message recovered perfectly without any private keys.</p>
					)}
				</div>
			)}
		</>
	);
}

function Pa15Card() {
	const [message, setMessage] = useState("Hello");
	const [sigState, setSigState] = useState<{ sig: string, raw: boolean } | null>(null);
	const [m1Str, setM1] = useState("2");
	const [m2Str, setM2] = useState("3");
	const [forgeryLog, setForgeryLog] = useState<string[]>([]);

	const handleSign = (raw: boolean) => {
		if (raw) {
			try {
				const m = BigInt(message);
				const sig = modPow(m, TOY_RSA_KEY.d!, TOY_RSA_KEY.n);
				setSigState({ sig: sig.toString(), raw: true });
			} catch (e) {
				alert("Raw RSA requires integer message");
			}
		} else {
			const hashed = hashToBigInt(message);
			const sig = modPow(hashed, TOY_RSA_KEY.d!, TOY_RSA_KEY.n);
			setSigState({ sig: sig.toString(), raw: false });
		}
	};

	const handleVerify = (tamper: boolean) => {
		if (!sigState) return;
		let testMsg = message;
		if (tamper) testMsg += "X";

		if (sigState.raw) {
			try {
				const m = BigInt(testMsg);
				const s = BigInt(sigState.sig);
				const valid = modPow(s, TOY_RSA_KEY.e, TOY_RSA_KEY.n) === m;
				alert(`Verification: ${valid ? "VALID" : "INVALID"}`);
			} catch (e) {
				alert("Invalid state for raw verify");
			}
		} else {
			const hashed = hashToBigInt(testMsg);
			const s = BigInt(sigState.sig);
			const valid = modPow(s, TOY_RSA_KEY.e, TOY_RSA_KEY.n) === hashed;
			alert(`Verification: ${valid ? "VALID" : "INVALID"}`);
		}
	};

	const handleForgeAttack = () => {
		const logs: string[] = [];
		try {
			const m1 = BigInt(m1Str);
			const m2 = BigInt(m2Str);
			// Attacker sees these
			const s1 = modPow(m1, TOY_RSA_KEY.d!, TOY_RSA_KEY.n);
			const s2 = modPow(m2, TOY_RSA_KEY.d!, TOY_RSA_KEY.n);

			const m3 = (m1 * m2) % TOY_RSA_KEY.n;
			const s3Forged = (s1 * s2) % TOY_RSA_KEY.n;

			logs.push(`Intercepted raw signature for m1=${m1}: s1=${s1}`);
			logs.push(`Intercepted raw signature for m2=${m2}: s2=${s2}`);
			logs.push(`Attacker wants to forge signature for m3 = m1 * m2 = ${m3}`);
			logs.push(`Attacker computes s3 = (s1 * s2) mod N = ${s3Forged}`);

			const verifyPasses = modPow(s3Forged, TOY_RSA_KEY.e, TOY_RSA_KEY.n) === m3;
			logs.push(`Does forged signature pass raw verification? ${verifyPasses ? "YES (Broken)" : "NO"}`);
		} catch (e) {
			logs.push("Error executing forgery. Check integer inputs.");
		}
		setForgeryLog(logs);
	};

	return (
		<>
			<div className="control-card">
				<h4>1. Standard Signing</h4>
				<div className="control-field">
					<label>Message</label>
					<input value={message} onChange={e => setMessage(e.target.value)} />
				</div>
				<div className="segment-row" style={{ marginTop: 10 }}>
					<button onClick={() => handleSign(false)}>Secure Hash-then-Sign</button>
					<button onClick={() => handleSign(true)}>Raw RSA Sign (Ints Only)</button>
				</div>

				{sigState && (
					<div style={{ marginTop: 15 }}>
						<p className="kv">Signature Generated ({sigState.raw ? "Raw" : "Hashed"}):</p>
						<div className="hex" style={{ wordBreak: "break-all" }}>{sigState.sig}</div>
						<div className="segment-row" style={{ marginTop: 10 }}>
							<button onClick={() => handleVerify(false)}>Verify</button>
							<button onClick={() => handleVerify(true)}>Tamper & Verify</button>
						</div>
					</div>
				)}
			</div>

			<div className="control-card" style={{ marginTop: 20 }}>
				<h4>2. Multiplicative Forgery Attack on Raw RSA</h4>
				<p style={{ fontSize: "0.9rem", color: "#aaa", marginBottom: 10 }}>Given signatures on m1 and m2, forge a signature on m1 * m2 without the private key.</p>
				<div style={{ display: "flex", gap: 10 }}>
					<div className="control-field">
						<label>m1 (Integer)</label>
						<input value={m1Str} onChange={e => setM1(e.target.value)} />
					</div>
					<div className="control-field">
						<label>m2 (Integer)</label>
						<input value={m2Str} onChange={e => setM2(e.target.value)} />
					</div>
				</div>
				<button onClick={handleForgeAttack} className="action-btn" style={{ marginTop: 10 }}>Run Forgery</button>

				{forgeryLog.length > 0 && (
					<div className="step-card" style={{ marginTop: 15 }}>
						{forgeryLog.map((log, i) => (
							<p key={i} className="kv" style={{ marginBottom: 5 }}>{log}</p>
						))}
					</div>
				)}
			</div>
		</>
	);
}


export default function Pa12To15Panel({ assignment }: { assignment: Pa12To15Assignment }) {
	let title = "";
	let description = "";

	switch (assignment) {
		case "pa12":
			title = "Textbook RSA and PKCS#1 v1.5";
			description = "Interactive demonstration of Textbook RSA determinism vulnerabilities versus PKCS#1 v1.5 randomized padding.";
			break;
		case "pa13":
			title = "Miller-Rabin Primality Testing";
			description = "Interactive test comparing the Miller-Rabin primality tester against the naive Fermat test, exposing Carmichael numbers.";
			break;
		case "pa14":
			title = "Håstad's Broadcast Attack";
			description = "Interactive demonstration of the Chinese Remainder Theorem (CRT) used to break unpadded textbook RSA with small public exponent (e=3).";
			break;
		case "pa15":
			title = "Digital Signatures";
			description = "Interactive demonstration of Secure Hash-then-Sign versus the vulnerabilities of Raw RSA Multiplicative Forgeries.";
			break;
	}

	return (
		<section className="panel" aria-label="PA12 through PA15 panel">
			<h3>
				PA {assignment.slice(2)} — {title}
			</h3>
			<p className="panel-note">{description}</p>

			<div className="pa16-suite-scroll">
				<div className="control-grid pa16-suite-grid">
					{assignment === "pa12" && <Pa12Card />}
					{assignment === "pa13" && <Pa13Card />}
					{assignment === "pa14" && <Pa14Card />}
					{assignment === "pa15" && <Pa15Card />}
				</div>
			</div>
		</section>
	);
}
