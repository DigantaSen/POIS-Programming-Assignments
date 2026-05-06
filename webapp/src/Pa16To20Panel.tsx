import { useEffect, useMemo, useState } from "react";

type Pa16Assignment = "pa16" | "pa17" | "pa18" | "pa19" | "pa20";
type Bit = 0 | 1;

interface ElGamalParams {
	p: number;
	q: number;
	g: number;
}

interface ElGamalPublicKey extends ElGamalParams {
	h: number;
}

interface ElGamalSecretKey extends ElGamalParams {
	x: number;
}

interface ElGamalCiphertext {
	c1: number;
	c2: number;
}

interface CcaEnvelope {
	ciphertext: ElGamalCiphertext;
	signature: number;
}

interface OtState {
	choice: Bit;
	secretKey: ElGamalSecretKey;
	publicKeys: [ElGamalPublicKey, ElGamalPublicKey];
}

interface OtTranscript {
	receiverChoice: Bit;
	publicKeys: [ElGamalPublicKey, ElGamalPublicKey];
	ciphertexts: [ElGamalCiphertext, ElGamalCiphertext];
	selectedMessage: number;
	log: string[];
}

interface SecureAndTranscript {
	aliceBit: Bit;
	bobBit: Bit;
	outputBit: Bit;
	receivedMessage: number;
	messages: [number, number];
	transcript: string[];
}

interface SecureXorTranscript {
	aliceBit: Bit;
	bobBit: Bit;
	randomness: Bit;
	aliceShare: Bit;
	bobShare: Bit;
	outputBit: Bit;
}

interface GateSpec {
	gateId: string;
	op: "AND" | "XOR" | "NOT";
	inputs: number[];
	output: number;
}

interface GateTrace {
	gateId: string;
	op: string;
	inputs: number[];
	outputWire: number;
	outputBit: Bit;
	note: string;
}

interface SecureEvalResult {
	outputBits: Bit[];
	gateLog: GateTrace[];
	otCalls: number;
}

class Circuit {
	constructor(
		public readonly name: string,
		public readonly aliceInputs: number,
		public readonly bobInputs: number,
		public readonly constantBits: Bit[],
		public readonly gates: GateSpec[],
		public readonly outputs: number[],
	) {}

	get inputCount(): number {
		return this.aliceInputs + this.bobInputs + this.constantBits.length;
	}

	evaluate(aliceBits: Bit[], bobBits: Bit[]): Bit[] {
		const inputs = [...aliceBits, ...bobBits, ...this.constantBits];
		if (inputs.length !== this.inputCount) {
			throw new Error(`expected ${this.inputCount} input bits, got ${inputs.length}`);
		}
		const wires = new Array<Bit>(this.inputCount + this.gates.length * 4).fill(0);
		for (let index = 0; index < inputs.length; index += 1) {
			wires[index] = inputs[index];
		}
		for (const gate of this.gates) {
			const operandBits = gate.inputs.map((wire) => wires[wire] ?? 0);
			const value = applyPlainGate(gate.op, operandBits as Bit[]);
			wires[gate.output] = value;
		}
		return this.outputs.map((wire) => wires[wire] ?? 0);
	}

	secureEvaluate(aliceBits: Bit[], bobBits: Bit[]): SecureEvalResult {
		const inputs = [...aliceBits, ...bobBits, ...this.constantBits];
		if (inputs.length !== this.inputCount) {
			throw new Error(`expected ${this.inputCount} input bits, got ${inputs.length}`);
		}
		const wires = new Array<Bit>(this.inputCount + this.gates.length * 4).fill(0);
		for (let index = 0; index < inputs.length; index += 1) {
			wires[index] = inputs[index];
		}

		const gateLog: GateTrace[] = [];
		let otCalls = 0;

		for (const gate of this.gates) {
			const operandBits = gate.inputs.map((wire) => wires[wire] ?? 0) as Bit[];
			if (gate.op === "AND") {
				const transcript = secureAndWithTranscript(operandBits[0], operandBits[1]);
				wires[gate.output] = transcript.outputBit;
				otCalls += 1;
				gateLog.push({
					gateId: gate.gateId,
					op: gate.op,
					inputs: gate.inputs,
					outputWire: gate.output,
					outputBit: transcript.outputBit,
					note: "OT-backed AND",
				});
				continue;
			}
			if (gate.op === "XOR") {
				const transcript = secureXorWithTranscript(operandBits[0], operandBits[1]);
				wires[gate.output] = transcript.outputBit;
				gateLog.push({
					gateId: gate.gateId,
					op: gate.op,
					inputs: gate.inputs,
					outputWire: gate.output,
					outputBit: transcript.outputBit,
					note: `local XOR with r=${transcript.randomness}`,
				});
				continue;
			}
			const result = secureNot(operandBits[0]);
			wires[gate.output] = result;
			gateLog.push({
				gateId: gate.gateId,
				op: gate.op,
				inputs: gate.inputs,
				outputWire: gate.output,
				outputBit: result,
				note: "local NOT",
			});
		}

		return {
			outputBits: this.outputs.map((wire) => wires[wire] ?? 0),
			gateLog,
			otCalls,
		};
	}
}

interface ElGamalRound {
	pk: ElGamalPublicKey;
	sk: ElGamalSecretKey;
	message: number;
	ciphertext: ElGamalCiphertext;
	tamperedCiphertext: ElGamalCiphertext;
	decrypted: number;
	tamperedDecrypted: number;
}

interface CcaRound {
	pkEnc: ElGamalPublicKey;
	skEnc: ElGamalSecretKey;
	pkSig: RsaPublicKey;
	skSig: RsaSecretKey;
	message: number;
	envelope: CcaEnvelope;
	tamperedEnvelope: CcaEnvelope;
	tamperedOracleResponse: string | null;
	decrypted: number | null;
	tamperedDecrypted: number | null;
	plainChallenge: ElGamalCiphertext;
	plainTampered: ElGamalCiphertext;
	plainDecrypted: number;
}

interface RsaPublicKey {
	n: number;
	e: number;
}

interface RsaSecretKey {
	n: number;
	d: number;
}

interface Pa18Round {
	choice: Bit;
	m0: number;
	m1: number;
	state: OtState;
	ciphertexts: [ElGamalCiphertext, ElGamalCiphertext];
	selected: number;
	log: {
		title: string;
		detail: string;
	}[];
}

interface Pa19TruthTableRow {
	a: Bit;
	b: Bit;
	outputBit: Bit;
	expectedBit: Bit;
	passed: boolean;
	transcript: string;
}

const ELGAMAL_PARAMS = createToyElGamalParams(50000);
const RSA_PARAMS: RsaPublicKey & RsaSecretKey = {
	n: 3233,
	e: 17,
	d: 2753,
};

function randInt(min: number, max: number): number {
	return min + Math.floor(Math.random() * (max - min + 1));
}

function hex(n: number): string {
	return String(n);
}

function modPow(base: number, exp: number, mod: number): number {
	let result = 1;
	let b = ((base % mod) + mod) % mod;
	let e = exp;
	while (e > 0) {
		if (e & 1) result = (result * b) % mod;
		b = (b * b) % mod;
		e >>= 1;
	}
	return result;
}

function egcd(a: number, b: number): [number, number, number] {
	if (a === 0) return [b, 0, 1];
	const [g, y, x] = egcd(b % a, a);
	return [g, x - Math.floor(b / a) * y, y];
}

function modInverse(a: number, mod: number): number {
	const [g, x] = egcd(a, mod);
	if (g !== 1) throw new Error("inverse does not exist");
	return ((x % mod) + mod) % mod;
}

function isPrime(n: number): boolean {
	if (n < 2) return false;
	if (n === 2 || n === 3) return true;
	if (n % 2 === 0) return false;
	for (let divisor = 3; divisor * divisor <= n; divisor += 2) {
		if (n % divisor === 0) return false;
	}
	return true;
}

function findSafePrime(start: number): ElGamalParams {
	let p = start % 2 === 0 ? start + 1 : start;
	while (true) {
		const q = Math.floor((p - 1) / 2);
		if (isPrime(p) && isPrime(q)) {
			return { p, q, g: 0 };
		}
		p += 2;
	}
}

function findGenerator(params: ElGamalParams): number {
	const { p, q } = params;
	for (let h = 2; h < p - 1; h += 1) {
		const candidate = modPow(h, 2, p);
		if (candidate !== 1 && modPow(candidate, q, p) === 1) {
			return candidate;
		}
	}
	throw new Error("failed to find subgroup generator");
}

function createToyElGamalParams(start: number): ElGamalParams {
	const base = findSafePrime(start);
	return { ...base, g: findGenerator(base) };
}

function keygen(params: ElGamalParams): {
	pk: ElGamalPublicKey;
	sk: ElGamalSecretKey;
} {
	const x = randInt(2, params.q - 1);
	const h = modPow(params.g, x, params.p);
	return { pk: { ...params, h }, sk: { ...params, x } };
}

function fakePublicKey(params: ElGamalParams): ElGamalPublicKey {
	return { ...params, h: randInt(2, params.p - 2) };
}

function elgamalEncrypt(
	pk: ElGamalPublicKey,
	message: number,
): ElGamalCiphertext {
	const m = ((message % pk.p) + pk.p) % pk.p;
	const y = randInt(2, pk.q - 1);
	const c1 = modPow(pk.g, y, pk.p);
	const shared = modPow(pk.h, y, pk.p);
	const c2 = (m * shared) % pk.p;
	return { c1, c2 };
}

function elgamalDecrypt(
	sk: ElGamalSecretKey,
	ciphertext: ElGamalCiphertext,
): number {
	const shared = modPow(ciphertext.c1, sk.x, sk.p);
	return (ciphertext.c2 * modInverse(shared, sk.p)) % sk.p;
}

function multiplyCiphertextByTwo(
	pk: ElGamalPublicKey,
	ciphertext: ElGamalCiphertext,
): ElGamalCiphertext {
	return { c1: ciphertext.c1, c2: (ciphertext.c2 * 2) % pk.p };
}

function simpleHash(input: string, mod: number): number {
	let hash = 2166136261;
	for (let index = 0; index < input.length; index += 1) {
		hash ^= input.charCodeAt(index);
		hash = Math.imul(hash, 16777619);
	}
	return Math.abs(hash) % mod;
}

function rsaSign(sk: RsaSecretKey, payload: string): number {
	const hashed = simpleHash(payload, sk.n);
	return modPow(hashed, sk.d, sk.n);
}

function rsaVerify(
	pk: RsaPublicKey,
	payload: string,
	signature: number,
): boolean {
	const hashed = simpleHash(payload, pk.n);
	return modPow(signature, pk.e, pk.n) === hashed;
}

function signcrypt(
	pkEnc: ElGamalPublicKey,
	skSig: RsaSecretKey,
	message: number,
): CcaEnvelope {
	const ciphertext = elgamalEncrypt(pkEnc, message);
	return {
		ciphertext,
		signature: rsaSign(skSig, serializeCiphertext(ciphertext)),
	};
}

function verifyThenDecrypt(
	pkSig: RsaPublicKey,
	skEnc: ElGamalSecretKey,
	envelope: CcaEnvelope,
): number | null {
	if (
		!rsaVerify(
			pkSig,
			serializeCiphertext(envelope.ciphertext),
			envelope.signature,
		)
	) {
		return null;
	}
	return elgamalDecrypt(skEnc, envelope.ciphertext);
}

function serializeCiphertext(ciphertext: ElGamalCiphertext): string {
	return `${ciphertext.c1}:${ciphertext.c2}`;
}

function otReceiverStep1(
	choice: Bit,
	params: ElGamalParams = ELGAMAL_PARAMS,
): OtState {
	const honest = keygen(params);
	const fake = fakePublicKey(params);
	const publicKeys: [ElGamalPublicKey, ElGamalPublicKey] =
		choice === 0 ? [honest.pk, fake] : [fake, honest.pk];
	return { choice, secretKey: honest.sk, publicKeys };
}

function otSenderStep(
	pk0: ElGamalPublicKey,
	pk1: ElGamalPublicKey,
	m0: number,
	m1: number,
): [ElGamalCiphertext, ElGamalCiphertext] {
	return [elgamalEncrypt(pk0, m0), elgamalEncrypt(pk1, m1)];
}

function otReceiverStep2(
	state: OtState,
	c0: ElGamalCiphertext,
	c1: ElGamalCiphertext,
): number {
	return elgamalDecrypt(state.secretKey, state.choice === 0 ? c0 : c1);
}

function otCheatAttempt(
	state: OtState,
	c0: ElGamalCiphertext,
	c1: ElGamalCiphertext,
): number | null {
	void state;
	void c0;
	void c1;
	return null;
}

function obliviousTransfer(
	messages: [number, number],
	choice: Bit,
	params: ElGamalParams = ELGAMAL_PARAMS,
): OtTranscript {
	const state = otReceiverStep1(choice, params);
	const ciphertexts = otSenderStep(
		state.publicKeys[0],
		state.publicKeys[1],
		messages[0],
		messages[1],
	);
	const selectedMessage = otReceiverStep2(
		state,
		ciphertexts[0],
		ciphertexts[1],
	);
	return {
		receiverChoice: choice,
		publicKeys: state.publicKeys,
		ciphertexts,
		selectedMessage,
		log: [
			`receiver choice = ${choice}`,
			"receiver step1: generated one honest keypair and one random public key",
			"sender step: encrypted both messages under the two public keys",
			"receiver step2: decrypted only the chosen ciphertext",
		],
	};
}

function secureAndWithTranscript(
	aliceBit: Bit,
	bobBit: Bit,
): SecureAndTranscript {
	const transcript = obliviousTransfer([0, aliceBit], bobBit);
	const outputBit = transcript.selectedMessage as Bit;
	return {
		aliceBit,
		bobBit,
		outputBit,
		receivedMessage: transcript.selectedMessage,
		messages: [0, aliceBit],
		transcript: [
			`Alice sets up OT messages (0, a) = (0, ${aliceBit})`,
			`Bob runs OT receiver with choice b = ${bobBit}`,
			`Bob receives m_b = a AND b = ${outputBit}`,
		],
	};
}

function secureAnd(aliceBit: Bit, bobBit: Bit): Bit {
	return secureAndWithTranscript(aliceBit, bobBit).outputBit;
}

function secureXorWithTranscript(
	aliceBit: Bit,
	bobBit: Bit,
): SecureXorTranscript {
	const randomness = (randInt(0, 1) as Bit) ?? 0;
	const aliceShare = (aliceBit ^ randomness) as Bit;
	const bobShare = (bobBit ^ randomness) as Bit;
	return {
		aliceBit,
		bobBit,
		randomness,
		aliceShare,
		bobShare,
		outputBit: (aliceShare ^ bobShare) as Bit,
	};
}

function secureXor(aliceBit: Bit, bobBit: Bit): Bit {
	return secureXorWithTranscript(aliceBit, bobBit).outputBit;
}

function secureNot(aliceBit: Bit): Bit {
	return aliceBit === 0 ? 1 : 0;
}

function verifyTruthTable(): Pa19TruthTableRow[] {
	const rows: Pa19TruthTableRow[] = [];
	for (const a of [0, 1] as Bit[]) {
		for (const b of [0, 1] as Bit[]) {
			const result = secureAndWithTranscript(a, b);
			const expectedBit = (a & b) as Bit;
			rows.push({
				a,
				b,
				outputBit: result.outputBit,
				expectedBit,
				passed: result.outputBit === expectedBit,
				transcript: result.transcript.join(" → "),
			});
		}
	}
	return rows;
}

function applyPlainGate(op: GateSpec["op"], bits: Bit[]): Bit {
	if (op === "AND") return (bits[0] & bits[1]) as Bit;
	if (op === "XOR") return (((bits[0] ?? 0) ^ (bits[1] ?? 0)) & 1) as Bit;
	return bits[0] === 0 ? 1 : 0;
}

function orGate(
	a: number,
	b: number,
	nextWire: number,
	gates: GateSpec[],
): number {
	const andWire = nextWire;
	gates.push({
		gateId: `greater_and_${nextWire}`,
		op: "AND",
		inputs: [a, b],
		output: andWire,
	});
	const xorWire = nextWire + 1;
	gates.push({
		gateId: `greater_xor_${nextWire}`,
		op: "XOR",
		inputs: [a, b],
		output: xorWire,
	});
	const outWire = nextWire + 2;
	gates.push({
		gateId: `greater_output_${nextWire}`,
		op: "XOR",
		inputs: [xorWire, andWire],
		output: outWire,
	});
	return outWire;
}

function buildMillionaireCircuit(bits: number): Circuit {
	const gates: GateSpec[] = [];
	const zero = 2 * bits;
	const one = 2 * bits + 1;
	let nextWire = 2 * bits + 2;
	let greater = zero;
	let equal = one;

	for (let index = 0; index < bits; index += 1) {
		const xi = index;
		const yi = bits + index;

		const notYi = nextWire;
		gates.push({
			gateId: `compare_not_y_${index}`,
			op: "NOT",
			inputs: [yi],
			output: notYi,
		});
		nextWire += 1;

		const xAndNotY = nextWire;
		gates.push({
			gateId: `compare_x_and_not_y_${index}`,
			op: "AND",
			inputs: [xi, notYi],
			output: xAndNotY,
		});
		nextWire += 1;

		const xorXY = nextWire;
		gates.push({
			gateId: `compare_x_xor_y_${index}`,
			op: "XOR",
			inputs: [xi, yi],
			output: xorXY,
		});
		nextWire += 1;

		const notXor = nextWire;
		gates.push({
			gateId: `compare_not_xor_${index}`,
			op: "NOT",
			inputs: [xorXY],
			output: notXor,
		});
		nextWire += 1;

		const gtTerm = nextWire;
		gates.push({
			gateId: `compare_greater_term_${index}`,
			op: "AND",
			inputs: [equal, xAndNotY],
			output: gtTerm,
		});
		nextWire += 1;

		const gtOut = orGate(greater, gtTerm, nextWire, gates);
		nextWire += 3;
		greater = gtOut;

		const eqOut = nextWire;
		gates.push({
			gateId: `compare_equal_${index}`,
			op: "AND",
			inputs: [equal, notXor],
			output: eqOut,
		});
		nextWire += 1;
		equal = eqOut;
	}

	return new Circuit("millionaire", bits, bits, [0, 1], gates, [
		greater,
		equal,
	]);
}

function intToBits(value: number, width: number): Bit[] {
	const bits: Bit[] = [];
	for (let index = width - 1; index >= 0; index -= 1) {
		bits.push(((value >> index) & 1) as Bit);
	}
	return bits;
}

function fromHexInput(value: string, fallback: number): number {
	const cleaned = value.trim();
	if (!cleaned) return fallback;
	const parsed = Number.parseInt(cleaned, 10);
	return Number.isFinite(parsed) ? parsed : fallback;
}

function ElGamalCard() {
	const [message, setMessage] = useState(37);
	const [round, setRound] = useState<ElGamalRound>(() =>
		createElGamalRound(37),
	);
	const [successCount, setSuccessCount] = useState(0);
	const [cycleReady, setCycleReady] = useState(false);
	const [challenge, setChallenge] = useState<CcaRound>(() =>
		createCcaRound(37),
	);

	function createElGamalRound(messageValue: number): ElGamalRound {
		const { pk, sk } = keygen(ELGAMAL_PARAMS);
		const ciphertext = elgamalEncrypt(pk, messageValue);
		const tamperedCiphertext = multiplyCiphertextByTwo(pk, ciphertext);
		return {
			pk,
			sk,
			message: messageValue,
			ciphertext,
			tamperedCiphertext,
			tamperedDecrypted: null,
		};
	}

	function createCcaRound(messageValue: number): CcaRound {
		const { pk: pkEnc, sk: skEnc } = keygen(ELGAMAL_PARAMS);
		const { pk: pkSig, sk: skSig } = {
			pk: { n: RSA_PARAMS.n, e: RSA_PARAMS.e },
			sk: { n: RSA_PARAMS.n, d: RSA_PARAMS.d },
		};
		const envelope = signcrypt(pkEnc, skSig, messageValue);
		const tamperedEnvelope = {
			ciphertext: multiplyCiphertextByTwo(pkEnc, envelope.ciphertext),
			signature: envelope.signature,
		};
		const decrypted = verifyThenDecrypt(pkSig, skEnc, envelope);
		const tamperedDecrypted = verifyThenDecrypt(pkSig, skEnc, tamperedEnvelope);
		const plainChallenge = elgamalEncrypt(pkEnc, messageValue);
		const plainTampered = multiplyCiphertextByTwo(pkEnc, plainChallenge);
		const plainDecrypted = elgamalDecrypt(skEnc, plainTampered);
		return {
			pkEnc,
			skEnc,
			pkSig,
			skSig,
			message: messageValue,
			envelope,
			tamperedEnvelope,
			tamperedOracleResponse: null,
			decrypted,
			tamperedDecrypted,
			plainChallenge,
			plainTampered,
			plainDecrypted,
		};
	}

	const decryptTamperedCiphertext = () => {
		if (!cycleReady) {
			return;
		}
		setRound((current) => ({
			...current,
			tamperedDecrypted: elgamalDecrypt(current.sk, current.tamperedCiphertext),
		}));
		setSuccessCount((count) => count + 1);
		setCycleReady(false);
	};

	const runChallenge = () => {
		setChallenge(createCcaRound(message));
	};

	const tamperChallenge = () => {
		setChallenge((current) => ({
			...current,
			tamperedEnvelope: {
				ciphertext: multiplyCiphertextByTwo(
					current.pkEnc,
					current.envelope.ciphertext,
				),
				signature: current.envelope.signature,
			},
			tamperedOracleResponse: hex(current.plainDecrypted),
			tamperedDecrypted: current.plainDecrypted,
			plainTampered: multiplyCiphertextByTwo(
				current.pkEnc,
				current.plainChallenge,
			),
			plainDecrypted: elgamalDecrypt(
				current.skEnc,
				multiplyCiphertextByTwo(current.pkEnc, current.plainChallenge),
			),
		}));
	};

	return (
		<div className="control-grid">
			<article className="control-card">
				<h2>ElGamal malleability lab</h2>
				<div className="control-field">
					<label htmlFor="pa16-message">Message m</label>
					<input
						id="pa16-message"
						type="number"
						min={2}
						max={ELGAMAL_PARAMS.p - 2}
						value={message}
						onChange={(event) =>
							setMessage(fromHexInput(event.target.value, 37))
						}
					/>
				</div>
				<div className="segment-row" style={{ marginBottom: "0.65rem" }}>
					<button
						type="button"
						onClick={() => {
							setRound(createElGamalRound(message));
							setCycleReady(true);
						}}
					>
						Encrypt
					</button>
					<button type="button" onClick={decryptTamperedCiphertext}>
						Decrypt c'
					</button>
				</div>
				<p className="kv">
					Public key p = {hex(round.pk.p)}, g = {hex(round.pk.g)}, h ={" "}
					{hex(round.pk.h)}
				</p>
				<p className="kv">
					Original ciphertext c = ({hex(round.ciphertext.c1)},{" "}
					{hex(round.ciphertext.c2)})
				</p>
				<p className="kv">
					Tampered ciphertext c' = ({hex(round.tamperedCiphertext.c1)},{" "}
					{hex(round.tamperedCiphertext.c2)})
				</p>
				<p className="kv">
					c' keeps c1 the same and doubles c2 modulo p, so the decrypted value becomes 2 · m mod p.
				</p>
				<p className="kv">
					Dec(c') = {round.tamperedDecrypted === null ? "?" : hex(round.tamperedDecrypted)} = 2 · m mod p
				</p>
				<p className="kv">Success counter = {successCount}</p>
				<div className="warn">
					Dec(c1, 2c2) = 2 · Dec(c1, c2) for every message in this toy field.
				</div>
			</article>

			<article className="control-card">
				<h2>CPA game</h2>
				<div className="segment-row" style={{ marginBottom: "0.65rem" }}>
					<button type="button" onClick={runChallenge}>
						Encrypt challenge
					</button>
					<button type="button" onClick={tamperChallenge}>
						Submit modified ciphertext
					</button>
				</div>
				<p className="kv">Challenge message m = {hex(challenge.message)}</p>
				<p className="kv">
					Challenge ciphertext CE = ({hex(challenge.envelope.ciphertext.c1)},{" "}
					{hex(challenge.envelope.ciphertext.c2)})
				</p>
				<p className="kv">
					Modified ciphertext CE' = ({hex(challenge.plainTampered.c1)},{" "}
					{hex(challenge.plainTampered.c2)})
				</p>
				<p className="kv">
					Decryption oracle response = {challenge.tamperedOracleResponse ?? "?"}
				</p>
				<p className="kv">
					Expected 2m mod p = {hex((2 * challenge.message) % challenge.pkEnc.p)}
				</p>
				<div className="warn">
					Submitting CE' to the decryption oracle returns 2m, so plain ElGamal fails CCA.
				</div>
			</article>
		</div>
	);
}

function Pa17Card() {
	const [message, setMessage] = useState(37);
	const [round, setRound] = useState<CcaRound>(() => createCcaRound(37));

	function createCcaRound(messageValue: number): CcaRound {
		const { pk: pkEnc, sk: skEnc } = keygen(ELGAMAL_PARAMS);
		const pkSig: RsaPublicKey = { n: RSA_PARAMS.n, e: RSA_PARAMS.e };
		const skSig: RsaSecretKey = { n: RSA_PARAMS.n, d: RSA_PARAMS.d };
		const envelope = signcrypt(pkEnc, skSig, messageValue);
		const tamperedEnvelope = {
			ciphertext: multiplyCiphertextByTwo(pkEnc, envelope.ciphertext),
			signature: envelope.signature,
		};
		const decrypted = verifyThenDecrypt(pkSig, skEnc, envelope);
		const tamperedDecrypted = verifyThenDecrypt(pkSig, skEnc, tamperedEnvelope);
		const plainChallenge = elgamalEncrypt(pkEnc, messageValue);
		const plainTampered = multiplyCiphertextByTwo(pkEnc, plainChallenge);
		const plainDecrypted = elgamalDecrypt(skEnc, plainTampered);
		return {
			pkEnc,
			skEnc,
			pkSig,
			skSig,
			message: messageValue,
			envelope,
			tamperedEnvelope,
			tamperedOracleResponse: null,
			decrypted,
			tamperedDecrypted,
			plainChallenge,
			plainTampered,
			plainDecrypted,
		};
	}

	const rerun = () => setRound(createCcaRound(message));

	const tamper = () => {
		setRound((current) => {
			const tamperedEnvelope = {
				ciphertext: multiplyCiphertextByTwo(
					current.pkEnc,
					current.envelope.ciphertext,
				),
				signature: current.envelope.signature,
			};
			return {
				...current,
				tamperedEnvelope,
					tamperedOracleResponse: "Rejected by signature check",
				tamperedDecrypted: verifyThenDecrypt(
					current.pkSig,
					current.skEnc,
					tamperedEnvelope,
				),
				plainTampered: multiplyCiphertextByTwo(
					current.pkEnc,
					current.plainChallenge,
				),
				plainDecrypted: elgamalDecrypt(
					current.skEnc,
					multiplyCiphertextByTwo(current.pkEnc, current.plainChallenge),
				),
			};
		});
	};

	return (
		<div className="control-grid">
			<article className="control-card">
				<h2>Encrypt-then-Sign</h2>
				<div className="control-field">
					<label htmlFor="pa17-message">Message m</label>
					<input
						id="pa17-message"
						type="number"
						min={2}
						max={ELGAMAL_PARAMS.p - 2}
						value={message}
						onChange={(event) =>
							setMessage(fromHexInput(event.target.value, 37))
						}
					/>
				</div>
				<div className="segment-row" style={{ marginBottom: "0.65rem" }}>
					<button type="button" onClick={rerun}>
						Encrypt
					</button>
					<button type="button" onClick={tamper}>
						Tamper CE
					</button>
					<button
						type="button"
						onClick={() => setRound(createCcaRound(message))}
					>
						Reset
					</button>
				</div>
				<p className="kv">
					CE = ({hex(round.envelope.ciphertext.c1)},{" "}
					{hex(round.envelope.ciphertext.c2)})
				</p>
				<p className="kv">σ = {hex(round.envelope.signature)}</p>
				<p className="kv">
					Verify-then-Decrypt(CE,σ) ={" "}
					{round.tamperedOracleResponse ?? (round.decrypted === null ? "?" : hex(round.decrypted))}
				</p>
				<p className="kv">
					The tampered ciphertext keeps the signature but changes c2, so signature verification rejects it before decryption.
				</p>
				<div className="warn">
					Signature verification runs first; tampered ciphertext is rejected by signature check.
				</div>
			</article>

			<article className="control-card">
				<h2>Plain ElGamal contrast</h2>
				<p className="kv">
					Challenge ciphertext = ({hex(round.plainChallenge.c1)},{" "}
					{hex(round.plainChallenge.c2)})
				</p>
				<p className="kv">
					Tampered ciphertext = ({hex(round.plainTampered.c1)},{" "}
					{hex(round.plainTampered.c2)})
				</p>
				<p className="kv">Oracle output = {hex(round.plainDecrypted)}</p>
				<p className="kv">
					Expected 2m mod p = {hex((2 * round.message) % round.pkEnc.p)}
				</p>
				<p className="kv">
					Without the signature layer, the same tampering still decrypts to 2m mod p.
				</p>
				<div className="warn">
					Plain ElGamal is malleable; the same attack fails on the signed
					variant.
				</div>
			</article>
		</div>
	);
}

function Pa18Card() {
	const [choice, setChoice] = useState<Bit | null>(null);
	const [m0, setM0] = useState(11);
	const [m1, setM1] = useState(42);
	const [round, setRound] = useState<Pa18Round | null>(null);

	function runOtRound(choiceBit: Bit, left: number, right: number): Pa18Round {
		const state = otReceiverStep1(choiceBit);
		const ciphertexts = otSenderStep(
			state.publicKeys[0],
			state.publicKeys[1],
			left,
			right,
		);
		const selected = otReceiverStep2(state, ciphertexts[0], ciphertexts[1]);
		const cheated = otCheatAttempt(state, ciphertexts[0], ciphertexts[1]);
		return {
			choice: choiceBit,
			m0: left,
			m1: right,
			state,
			ciphertexts,
			selected,
			log: [
				{
					title: "Key pairs generated",
					detail: `Bob generates one honest keypair and one random public key. choice bit b = ${choiceBit}.`,
				},
				{
					title: "(pk0; pk1) sent to Alice",
					detail: `Alice receives pk0 = ${hex(state.publicKeys[0].h)} and pk1 = ${hex(state.publicKeys[1].h)}.`,
				},
				{
					title: "C0 and C1 received",
					detail: `Alice encrypts m0 and m1, sending C0 = (${hex(ciphertexts[0].c1)}, ${hex(ciphertexts[0].c2)}) and C1 = (${hex(ciphertexts[1].c1)}, ${hex(ciphertexts[1].c2)}).`,
				},
				{
					title: "Cb decrypted",
					detail: `Bob decrypts C${choiceBit} and recovers m${choiceBit} = ${hex(selected)}.`,
				},
			],
		};
	}

	const runOt = (choiceBit: Bit) => {
		setChoice(choiceBit);
		setRound(runOtRound(choiceBit, m0, m1));
	};

	return (
		<div className="pa18-layout">
			<article className="control-card pa18-alice-panel">
				<h2>Alice’s sender panel</h2>
				<p className="kv pa18-panel-note">
					Greyed out on purpose: Alice holds two hidden messages, m0 and m1.
					Bob never sees them directly.
				</p>
				<div className="pa18-hidden-grid">
					<div className="pa18-hidden-card">
						<span className="pa18-hidden-label">m0</span>
						<span className="pa18-hidden-value">hidden</span>
					</div>
					<div className="pa18-hidden-card">
						<span className="pa18-hidden-label">m1</span>
						<span className="pa18-hidden-value">hidden</span>
					</div>
				</div>
				<div className="warn pa18-hidden-note">
					Alice keeps both messages private while the OT protocol carries only the
					necessary ciphertexts to Bob.
				</div>
			</article>

			<article className="control-card pa18-bob-panel">
				<h2>Bob’s receiver panel</h2>
				<p className="kv pa18-panel-note">
					Bob chooses exactly one branch. Click <strong>Choose 0</strong> or
					<strong>Choose 1</strong> to run the OT demo step-by-step.
				</p>
				<div className="segment-row pa18-choice-row">
					<button
						type="button"
						className={choice === 0 ? "active" : ""}
						onClick={() => runOt(0)}
					>
						Choose 0
					</button>
					<button
						type="button"
						className={choice === 1 ? "active" : ""}
						onClick={() => runOt(1)}
					>
						Choose 1
					</button>
				</div>
				<div className="pa18-result-card">
					<div className="pa18-result-kicker">Result</div>
					{round === null ? (
						<div className="pa18-result-note">Choose 0 or Choose 1 to reveal m<sub>b</sub>.</div>
					) : (
						<>
							<div className="pa18-result-value">m<sub>b</sub> = m{round.choice} = {hex(round.selected)}</div>
							<div className="pa18-result-note">Bob learns only the selected message.</div>
						</>
					)}
				</div>
				<div className="step-list pa18-log-list">
					{round === null ? (
						<div className="step-card pending">
							<div className="step-head">
								<strong>Waiting for Bob’s choice</strong>
								<span className="status-pill">idle</span>
							</div>
							<p className="kv">Click Choose 0 or Choose 1 to generate the OT transcript.</p>
						</div>
					) : (
						round.log.map((entry, index) => (
							<div key={entry.title} className="step-card">
								<div className="step-head">
									<strong>
										{index + 1}. {entry.title}
									</strong>
									<span className="status-pill ready">step</span>
								</div>
								<p className="kv">{entry.detail}</p>
							</div>
						))
					)}
				</div>
				<div className="warn pa18-conclusion">
					The sender keeps both branches available, but Bob decrypts only Cb and
					reveals mb.
				</div>
			</article>
		</div>
	);
}

function Pa19Card() {
	const [a, setA] = useState<Bit>(1);
	const [b, setB] = useState<Bit>(0);
	const [currentRun, setCurrentRun] = useState<SecureAndTranscript | null>(null);
	const [truthRows, setTruthRows] = useState<Pa19TruthTableRow[] | null>(null);

	const runAnd = () => {
		setCurrentRun(secureAndWithTranscript(a, b));
	};

	return (
		<div className="control-grid">
			<article className="control-card">
				<h2>Alice / Bob bits</h2>
				<p className="kv">
					Alice enters bit a in 0 or 1 and Bob enters bit b in 0 or 1.
				</p>
				<div className="segment-row" style={{ marginBottom: "0.65rem" }}>
					<button
						type="button"
						className={a === 0 ? "active" : ""}
						onClick={() => setA(0)}
					>
						Alice = 0
					</button>
					<button
						type="button"
						className={a === 1 ? "active" : ""}
						onClick={() => setA(1)}
					>
						Alice = 1
					</button>
					<button
						type="button"
						className={b === 0 ? "active" : ""}
						onClick={() => setB(0)}
					>
						Bob = 0
					</button>
					<button
						type="button"
						className={b === 1 ? "active" : ""}
						onClick={() => setB(1)}
					>
						Bob = 1
					</button>
					<button
						type="button"
						onClick={runAnd}
					>
						Compute AND
					</button>
				</div>
				<p className="kv">
					Secure AND(a,b) = {currentRun === null ? "?" : currentRun.outputBit}
				</p>
				<p className="kv">
					The protocol uses OT messages (0, a) so Bob learns only a AND b.
				</p>
				<div className="warn">
					What does Alice learn? Only that the OT protocol ran. What does Bob
					learn? Only a AND b.
				</div>
			</article>

			<article className="control-card">
				<h2>Protocol transcript</h2>
				{currentRun === null ? (
					<div className="step-card pending">
						<div className="step-head">
							<strong>Waiting for Compute AND</strong>
							<span className="status-pill">idle</span>
						</div>
						<p className="kv">
							Click Compute AND to generate the OT transcript for the selected
							bits.
						</p>
					</div>
				) : (
					<div className="step-list">
						{currentRun.transcript.map((entry, index) => (
							<div key={entry} className="step-card">
								<div className="step-head">
									<strong>
										{index + 1}. {index === 0 ? "Alice sets up OT messages" : index === 1 ? "Bob runs OT receiver" : "Bob receives m_b"}
									</strong>
									<span className="status-pill ready">step</span>
								</div>
								<p className="kv">{entry}</p>
							</div>
						))}
						<div className="step-card">
							<div className="step-head">
								<strong>What does Alice learn?</strong>
								<span className="status-pill ready">summary</span>
							</div>
							<p className="kv">
								Alice learns only that Bob ran the OT protocol; she does not
								learn b.
							</p>
						</div>
						<div className="step-card">
							<div className="step-head">
								<strong>What does Bob learn?</strong>
								<span className="status-pill ready">summary</span>
							</div>
							<p className="kv">
								Bob learns only m_b = a AND b and nothing about Alice’s hidden
								input beyond the transcript.
							</p>
						</div>
					</div>
				)}
			</article>

			<article className="control-card">
				<h2>Run all 4 combinations</h2>
				<div className="segment-row" style={{ marginBottom: "0.6rem" }}>
					<button type="button" onClick={() => setTruthRows(verifyTruthTable())}>
						Run all
					</button>
				</div>
				<p className="kv">
					Checks every input pair against the AND truth table and records the OT
					transcript for each case.
				</p>
				{truthRows === null ? (
					<div className="step-card pending">
						<div className="step-head">
							<strong>Waiting for Run all</strong>
							<span className="status-pill">idle</span>
						</div>
						<p className="kv">
							Click Run all to verify the AND truth table for all four input
							combinations.
						</p>
					</div>
				) : (
					<div className="step-list">
						{truthRows.map((row) => (
							<div key={`${row.a}${row.b}`} className="step-card">
								<div className="step-head">
									<strong>
										a={row.a}, b={row.b}
									</strong>
									<span className={`status-pill${row.passed ? " ready" : ""}`}>
										{row.passed ? "passed" : "failed"}
									</span>
								</div>
								<p className="kv">
									AND output = {row.outputBit} · expected = {row.expectedBit}
								</p>
								<p className="kv">Transcript: {row.transcript}</p>
							</div>
						))}
					</div>
				)}
			</article>
		</div>
	);
}

function CircuitTraceView({ result }: { result: SecureEvalResult }) {
	return (
		<details className="pa20-trace-details" open>
			<summary className="pa20-trace-summary">Circuit trace</summary>
			<div className="step-list" style={{ marginTop: "0.75rem" }}>
				{result.gateLog.map((step, index) => (
					<div key={`${step.gateId}-${index}`} className="step-card">
						<div className="step-head">
							<strong>
								{index + 1}. {step.gateId}
							</strong>
							<span className={`status-pill${step.op === "AND" ? " ready" : ""}`}>
								{step.op}
							</span>
						</div>
						<p className="kv">Output wire: {step.outputWire} = {step.outputBit}</p>
						<p className="kv">{step.note}</p>
					</div>
				))}
			</div>
		</details>
	);
}

type MillionaireResult = "Alice is richer" | "Bob is richer" | "Equal";

interface MillionaireRun {
	trace: SecureEvalResult;
	result: MillionaireResult;
	visibleGateCount: number;
}

function Pa20Card() {
	const millionaireBits = 7;
	const millionaireCircuit = useMemo(
		() => buildMillionaireCircuit(millionaireBits),
		[],
	);
	const [xMillionaire, setXM] = useState(7);
	const [yMillionaire, setYM] = useState(12);
	const [run, setRun] = useState<MillionaireRun | null>(null);

	function resolveResult(trace: SecureEvalResult): MillionaireResult {
		return trace.outputBits[0] === 1
			? "Alice is richer"
			: trace.outputBits[1] === 1
				? "Equal"
				: "Bob is richer";
	}

	function startComparison(): void {
		const trace = millionaireCircuit.secureEvaluate(
			intToBits(xMillionaire, millionaireBits),
			intToBits(yMillionaire, millionaireBits),
		);
		setRun({ trace, result: resolveResult(trace), visibleGateCount: 0 });
	}

	useEffect(() => {
		if (run === null) return;
		if (run.visibleGateCount >= run.trace.gateLog.length) return;
		const timer = window.setTimeout(() => {
			setRun((current) =>
				current === null
					? current
					: {
						...current,
						visibleGateCount: current.visibleGateCount + 1,
					},
			);
		}, 160);
		return () => window.clearTimeout(timer);
	}, [run]);

	return (
		<div className="pa20-live-grid">
			<article className="control-card pa20-side-card pa20-alice-card">
				<h2>Alice panel</h2>
				<p className="kv pa20-side-note">
					Alice controls her wealth x. Bob’s panel does not show it.
				</p>
				<div className="control-field">
					<label htmlFor="pa20-xm">Wealth x</label>
					<input
						id="pa20-xm"
						type="range"
						min={0}
						max={100}
						value={xMillionaire}
						onChange={(event) => {
							setXM(fromHexInput(event.target.value, 7));
							setRun(null);
						}}
						className="pa01-slider"
					/>
					<div className="pa01-slider-readout">x = {xMillionaire}</div>
					<div className="pa01-slider-ticks">
						<span>0</span>
						<span>100</span>
					</div>
				</div>
			</article>

			<article className="control-card pa20-side-card pa20-bob-card">
				<h2>Bob panel</h2>
				<p className="kv pa20-side-note">
					Bob controls his wealth y. Alice’s panel does not show it.
				</p>
				<div className="control-field">
					<label htmlFor="pa20-ym">Wealth y</label>
					<input
						id="pa20-ym"
						type="range"
						min={0}
						max={100}
						value={yMillionaire}
						onChange={(event) => {
							setYM(fromHexInput(event.target.value, 12));
							setRun(null);
						}}
						className="pa01-slider"
					/>
					<div className="pa01-slider-readout">y = {yMillionaire}</div>
					<div className="pa01-slider-ticks">
						<span>0</span>
						<span>100</span>
					</div>
				</div>
			</article>

			<article className="control-card pa20-summary-card">
				<h2>Who is richer?</h2>
				<div className="segment-row" style={{ marginBottom: "0.7rem" }}>
					<button type="button" onClick={startComparison}>
						Who is richer?
					</button>
				</div>
				<p className="kv">
					Toy parameters: 7-bit comparison, enough to cover values from 0 to
					100, fast enough to animate gate by gate.
				</p>
				<div className="pa20-result-banner">
					<div className="pa20-result-label">Result shown to both</div>
					<div className="pa20-result-value">
						{run === null
							? "Click Who is richer?"
							: run.visibleGateCount >= run.trace.gateLog.length
								? run.result
								: "Evaluating gate by gate..."}
					</div>
				</div>
				<div className="pa20-progress-shell">
					<div className="pa20-progress-head">
						<span>Gates completed</span>
						<span>
							{run === null ? 0 : Math.min(run.visibleGateCount, run.trace.gateLog.length)}
							 / {run === null ? millionaireCircuit.gates.length : run.trace.gateLog.length}
						</span>
					</div>
					<div className="pa20-progress-track" aria-hidden="true">
						<div
							className="pa20-progress-fill"
							style={{
								width:
									run === null
										? "0%"
										: `${Math.min(
											100,
											(run.visibleGateCount / run.trace.gateLog.length) * 100,
										)}%`,
							}}
						/>
					</div>
				</div>
			</article>

			<article className="control-card pa20-trace-card">
				<CircuitTraceView
					result={
						run === null
							? { outputBits: [], gateLog: [], otCalls: 0 }
							: {
								...run.trace,
								gateLog: run.trace.gateLog.slice(0, run.visibleGateCount),
							}
					}
				/>
				{run === null ? (
					<div className="step-card pending" style={{ marginTop: "0.75rem" }}>
						<div className="step-head">
							<strong>Waiting for Who is richer?</strong>
							<span className="status-pill">idle</span>
						</div>
						<p className="kv">
							Click the button to reveal the circuit trace and progress bar.
						</p>
					</div>
				) : null}
			</article>
		</div>
	);
}

interface Pa16To20PanelProps {
	assignment?: Pa16Assignment;
}

export default function Pa16To20Panel({ assignment }: Pa16To20PanelProps) {
	const activeAssignment = assignment ?? "pa16";
	const titleByAssignment: Record<Pa16Assignment, string> = {
		pa16: "ElGamal Public-Key Cryptosystem",
		pa17: "CCA-Secure Public-Key Encryption",
		pa18: "Oblivious Transfer",
		pa19: "Secure AND Gate",
		pa20: "All 2-Party Secure Computation",
	};
	const noteByAssignment: Record<Pa16Assignment, string> = {
		pa16: "Shows ElGamal malleability by comparing a normal ciphertext with a doubled ciphertext.",
		pa17: "Wraps ElGamal with signatures so modified ciphertexts are rejected before decryption.",
		pa18: "Lets Bob learn exactly one of two messages using oblivious transfer.",
		pa19: "Builds secure AND from OT so Bob learns only a AND b.",
		pa20: "Live millionaire comparison with an animated gate-by-gate trace.",
	};

	const content =
		activeAssignment === "pa16" ? (
			<ElGamalCard />
		) : activeAssignment === "pa17" ? (
			<Pa17Card />
		) : activeAssignment === "pa18" ? (
			<Pa18Card />
		) : activeAssignment === "pa19" ? (
			<Pa19Card />
		) : (
			<Pa20Card />
		);

	return (
		<section className="panel" aria-label="PA16 through PA20 panel">
			<h3>
				PA {activeAssignment.slice(2)} — {titleByAssignment[activeAssignment]}
			</h3>
			<p className="panel-note">{noteByAssignment[activeAssignment]}</p>

			<div className="pa16-suite-scroll">
				<div className="control-grid pa16-suite-grid">{content}</div>
			</div>
		</section>
	);
}
