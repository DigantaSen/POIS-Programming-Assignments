import { useMemo, useState } from "react";

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
			throw new Error(
				`expected ${this.inputCount} input bits, got ${inputs.length}`,
			);
		}
		const wires = new Array<Bit>(this.inputCount + this.gates.length * 4).fill(
			0,
		);
		for (let i = 0; i < inputs.length; i += 1) {
			wires[i] = inputs[i];
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
			throw new Error(
				`expected ${this.inputCount} input bits, got ${inputs.length}`,
			);
		}
		const wires = new Array<Bit>(this.inputCount + this.gates.length * 4).fill(
			0,
		);
		for (let i = 0; i < inputs.length; i += 1) {
			wires[i] = inputs[i];
		}

		const gateLog: GateTrace[] = [];
		let otCalls = 0;

		for (const gate of this.gates) {
			const operandBits = gate.inputs.map((wire) => wires[wire] ?? 0) as Bit[];
			if (gate.op === "AND") {
				const transcript = secureAndWithTranscript(
					operandBits[0],
					operandBits[1],
				);
				wires[gate.output] = transcript.outputBit;
				otCalls += 1;
				gateLog.push({
					gateId: gate.gateId,
					op: gate.op,
					inputs: gate.inputs,
					outputWire: gate.output,
					outputBit: transcript.outputBit,
					note: `OT-backed AND; ${transcript.transcript.join(" · ")}`,
				});
				continue;
			}
			if (gate.op === "XOR") {
				const transcript = secureXorWithTranscript(
					operandBits[0],
					operandBits[1],
				);
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
	cheated: number | null;
	log: string[];
}

interface Pa19TruthTableRow {
	a: Bit;
	b: Bit;
	andOk: boolean;
	xorOk: boolean;
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
	return `0x${n.toString(16).toUpperCase()}`;
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

function otCorrectnessTrials(trials: number = 100): number {
	let successes = 0;
	for (let index = 0; index < trials; index += 1) {
		const choice = (randInt(0, 1) as Bit) ?? 0;
		const m0 = randInt(1, 1200);
		const m1 = randInt(1, 1200);
		const transcript = obliviousTransfer([m0, m1], choice);
		const expected = choice === 0 ? m0 : m1;
		if (transcript.selectedMessage === expected) successes += 1;
	}
	return successes;
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
		transcript: transcript.log,
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

function verifyTruthTable(trials: number = 50): Pa19TruthTableRow[] {
	const rows: Pa19TruthTableRow[] = [];
	for (const a of [0, 1] as Bit[]) {
		for (const b of [0, 1] as Bit[]) {
			let andOk = true;
			let xorOk = true;
			for (let index = 0; index < trials; index += 1) {
				andOk = andOk && secureAnd(a, b) === (a & b);
				xorOk = xorOk && secureXor(a, b) === (a ^ b);
			}
			const transcript = secureAndWithTranscript(a, b).transcript.join(" → ");
			rows.push({ a, b, andOk, xorOk, transcript });
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
		gateId: `or_and_${nextWire}`,
		op: "AND",
		inputs: [a, b],
		output: andWire,
	});
	const xorWire = nextWire + 1;
	gates.push({
		gateId: `or_xor_${nextWire}`,
		op: "XOR",
		inputs: [a, b],
		output: xorWire,
	});
	const outWire = nextWire + 2;
	gates.push({
		gateId: `or_out_${nextWire}`,
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
			gateId: `cmp_noty_${index}`,
			op: "NOT",
			inputs: [yi],
			output: notYi,
		});
		nextWire += 1;

		const xAndNotY = nextWire;
		gates.push({
			gateId: `cmp_xnoty_${index}`,
			op: "AND",
			inputs: [xi, notYi],
			output: xAndNotY,
		});
		nextWire += 1;

		const xorXY = nextWire;
		gates.push({
			gateId: `cmp_xor_${index}`,
			op: "XOR",
			inputs: [xi, yi],
			output: xorXY,
		});
		nextWire += 1;

		const notXor = nextWire;
		gates.push({
			gateId: `cmp_nx_${index}`,
			op: "NOT",
			inputs: [xorXY],
			output: notXor,
		});
		nextWire += 1;

		const gtTerm = nextWire;
		gates.push({
			gateId: `cmp_gtterm_${index}`,
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
			gateId: `cmp_eq_${index}`,
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

function buildEqualityCircuit(bits: number): Circuit {
	const gates: GateSpec[] = [];
	const one = 2 * bits;
	let nextWire = 2 * bits + 1;
	let equal = one;

	for (let index = 0; index < bits; index += 1) {
		const xi = index;
		const yi = bits + index;
		const xorXY = nextWire;
		gates.push({
			gateId: `eq_xor_${index}`,
			op: "XOR",
			inputs: [xi, yi],
			output: xorXY,
		});
		nextWire += 1;

		const notXor = nextWire;
		gates.push({
			gateId: `eq_not_${index}`,
			op: "NOT",
			inputs: [xorXY],
			output: notXor,
		});
		nextWire += 1;

		const eqOut = nextWire;
		gates.push({
			gateId: `eq_and_${index}`,
			op: "AND",
			inputs: [equal, notXor],
			output: eqOut,
		});
		nextWire += 1;
		equal = eqOut;
	}

	return new Circuit("equality", bits, bits, [1], gates, [equal]);
}

function buildAdditionCircuit(bits: number): Circuit {
	const gates: GateSpec[] = [];
	const zero = 2 * bits;
	let nextWire = 2 * bits + 1;
	let carry = zero;
	const outputs: number[] = [];

	for (let index = bits - 1; index >= 0; index -= 1) {
		const xi = index;
		const yi = bits + index;

		const xorXY = nextWire;
		gates.push({
			gateId: `add_xor_${index}`,
			op: "XOR",
			inputs: [xi, yi],
			output: xorXY,
		});
		nextWire += 1;

		const sumBit = nextWire;
		gates.push({
			gateId: `add_sum_${index}`,
			op: "XOR",
			inputs: [xorXY, carry],
			output: sumBit,
		});
		nextWire += 1;
		outputs.push(sumBit);

		const andXY = nextWire;
		gates.push({
			gateId: `add_andxy_${index}`,
			op: "AND",
			inputs: [xi, yi],
			output: andXY,
		});
		nextWire += 1;

		const andCarry = nextWire;
		gates.push({
			gateId: `add_andc_${index}`,
			op: "AND",
			inputs: [carry, xorXY],
			output: andCarry,
		});
		nextWire += 1;

		const carryOut = orGate(andXY, andCarry, nextWire, gates);
		nextWire += 3;
		carry = carryOut;
	}

	return new Circuit("addition", bits, bits, [0], gates, outputs.reverse());
}

function intToBits(value: number, width: number): Bit[] {
	const bits: Bit[] = [];
	for (let index = width - 1; index >= 0; index -= 1) {
		bits.push(((value >> index) & 1) as Bit);
	}
	return bits;
}

function bitsToInt(bits: Bit[]): number {
	let value = 0;
	for (const bit of bits) {
		value = (value << 1) | bit;
	}
	return value;
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
	const [attemptCount, setAttemptCount] = useState(0);
	const [challenge, setChallenge] = useState<CcaRound>(() =>
		createCcaRound(37),
	);

	function createElGamalRound(messageValue: number): ElGamalRound {
		const { pk, sk } = keygen(ELGAMAL_PARAMS);
		const ciphertext = elgamalEncrypt(pk, messageValue);
		const tamperedCiphertext = multiplyCiphertextByTwo(pk, ciphertext);
		const decrypted = elgamalDecrypt(sk, ciphertext);
		const tamperedDecrypted = elgamalDecrypt(sk, tamperedCiphertext);
		return {
			pk,
			sk,
			message: messageValue,
			ciphertext,
			tamperedCiphertext,
			decrypted,
			tamperedDecrypted,
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

	const runMalleabilityTrials = () => {
		const { pk, sk } = keygen(ELGAMAL_PARAMS);
		let successes = 0;
		for (let index = 0; index < 100; index += 1) {
			const m = randInt(2, Math.min(ELGAMAL_PARAMS.p - 2, 2000));
			const ciphertext = elgamalEncrypt(pk, m);
			const tampered = multiplyCiphertextByTwo(pk, ciphertext);
			if (elgamalDecrypt(sk, tampered) === (2 * m) % pk.p) successes += 1;
		}
		setSuccessCount(successes);
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
				tamperedOracleResponse: "Rejected by signature check",
			tamperedDecrypted: verifyThenDecrypt(current.pkSig, current.skEnc, {
				ciphertext: multiplyCiphertextByTwo(
					current.pkEnc,
					current.envelope.ciphertext,
				),
				signature: current.envelope.signature,
			}),
			plainTampered: multiplyCiphertextByTwo(
				current.pkEnc,
				current.plainChallenge,
			),
			plainDecrypted: elgamalDecrypt(
				current.skEnc,
				multiplyCiphertextByTwo(current.pkEnc, current.plainChallenge),
			),
		}));
		setAttemptCount((count) => count + 1);
	};

	const reroll = () => {
		setRound(createElGamalRound(message));
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
						onClick={() => setRound(createElGamalRound(message))}
					>
						Encrypt
					</button>
					<button type="button" onClick={reroll}>
						New Keys
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
				<p className="kv">Dec(c) = {hex(round.decrypted)}</p>
				<p className="kv">
					Dec(c') = {hex(round.tamperedDecrypted)} = 2 · m mod p
				</p>
				<p className="kv">Tamper attempts = {attemptCount}</p>
				<div className="warn">
					Dec(c1, 2c2) = 2 · Dec(c1, c2) for every message in this toy field.
				</div>
			</article>

			<article className="control-card">
				<h2>CPA / CCA game</h2>
				<div className="segment-row" style={{ marginBottom: "0.65rem" }}>
					<button type="button" onClick={runChallenge}>
						Encrypt challenge
					</button>
					<button type="button" onClick={tamperChallenge}>
						Submit modified ciphertext
					</button>
					<button type="button" onClick={runMalleabilityTrials}>
						Run 100 trials
					</button>
				</div>
				<p className="kv">Challenge message m = {hex(challenge.message)}</p>
				<p className="kv">
					Challenge ciphertext CE = ({hex(challenge.envelope.ciphertext.c1)},{" "}
					{hex(challenge.envelope.ciphertext.c2)})
				</p>
				<p className="kv">
					Tampered oracle response = {" "}
					{challenge.tamperedOracleResponse ?? "?"}
				</p>
				<p className="kv">
					Plain ElGamal response = {hex(challenge.plainDecrypted)}
				</p>
				<p className="kv">Success counter = {successCount}/100</p>
				<div className="warn">
					The signature gate blocks the modified ciphertext, while plain ElGamal
					returns 2m.
				</div>
			</article>
		</div>
	);
}

function Pa17Card() {
	const [message, setMessage] = useState(37);
	const [round, setRound] = useState<CcaRound>(() => createCcaRound(37));
	const [tamperCount, setTamperCount] = useState(0);

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
		setTamperCount((count) => count + 1);
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
					{round.decrypted === null ? "?" : hex(round.decrypted)}
				</p>
				<p className="kv">
					Tampered CE &gt; {round.tamperedOracleResponse ?? "?"}
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
				<p className="kv">Tamper clicks = {tamperCount}</p>
				<div className="warn">
					Plain ElGamal is malleable; the same attack fails on the signed
					variant.
				</div>
			</article>
		</div>
	);
}

function Pa18Card() {
	const [choice, setChoice] = useState<Bit>(0);
	const [m0, setM0] = useState(11);
	const [m1, setM1] = useState(42);
	const [round, setRound] = useState<Pa18Round>(() => runOtRound(0, 11, 42));
	const [correctCount, setCorrectCount] = useState(0);

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
			cheated,
			log: [
				`receiver step1: choice=${choiceBit}, pk0=${hex(state.publicKeys[0].h)}, pk1=${hex(state.publicKeys[1].h)}`,
				`sender step: C0=(${hex(ciphertexts[0].c1)}, ${hex(ciphertexts[0].c2)})`,
				`sender step: C1=(${hex(ciphertexts[1].c1)}, ${hex(ciphertexts[1].c2)})`,
				`receiver step2: mb=${hex(selected)}`,
			],
		};
	}

	const runOt = () => setRound(runOtRound(choice, m0, m1));

	const runTrials = () => {
		setCorrectCount(otCorrectnessTrials(100));
	};

	return (
		<div className="control-grid">
			<article className="control-card">
				<h2>Bob’s receiver panel</h2>
				<div className="segment-row" style={{ marginBottom: "0.65rem" }}>
					<button
						type="button"
						className={choice === 0 ? "active" : ""}
						onClick={() => setChoice(0)}
					>
						Choose 0
					</button>
					<button
						type="button"
						className={choice === 1 ? "active" : ""}
						onClick={() => setChoice(1)}
					>
						Choose 1
					</button>
					<button type="button" onClick={runOt}>
						Run OT
					</button>
				</div>
				<div className="control-field">
					<label htmlFor="pa18-m0">m0</label>
					<input
						id="pa18-m0"
						type="number"
						value={m0}
						onChange={(event) => setM0(fromHexInput(event.target.value, 11))}
					/>
				</div>
				<div className="control-field">
					<label htmlFor="pa18-m1">m1</label>
					<input
						id="pa18-m1"
						type="number"
						value={m1}
						onChange={(event) => setM1(fromHexInput(event.target.value, 42))}
					/>
				</div>
				<div className="segment-row" style={{ marginBottom: "0.5rem" }}>
					<button type="button" onClick={runTrials}>
						Run 100 trials
					</button>
				</div>
				<p className="kv">Selected message = {hex(round.selected)}</p>
				<p className="kv">Hidden other message = ??</p>
				<p className="kv">
					Cheat attempt ={" "}
					{round.cheated === null ? "failed" : hex(round.cheated)}
				</p>
				<p className="kv">Correctness = {correctCount}/100</p>
			</article>

			<article className="control-card">
				<h2>Message log</h2>
				<div className="step-list">
					{round.log.map((entry, index) => (
						<div key={entry} className="step-card">
							<div className="step-head">
								<strong>
									{index + 1}. {entry.split(":")[0]}
								</strong>
								<span className="status-pill ready">step</span>
							</div>
							<p className="kv">{entry}</p>
						</div>
					))}
				</div>
				<div className="warn">
					Receiver learns only m_b. Sender sees two public keys but not Bob’s
					choice bit.
				</div>
			</article>
		</div>
	);
}

function Pa19Card() {
	const [a, setA] = useState<Bit>(1);
	const [b, setB] = useState<Bit>(0);
	const [truthRows, setTruthRows] = useState<Pa19TruthTableRow[]>(() =>
		verifyTruthTable(50),
	);
	const andTranscript = secureAndWithTranscript(a, b);
	const xorTranscript = secureXorWithTranscript(a, b);
	const andResult = secureAnd(a, b);
	const xorResult = secureXor(a, b);
	const notResult = secureNot(a);

	return (
		<div className="control-grid">
			<article className="control-card">
				<h2>Alice / Bob bits</h2>
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
						onClick={() => setTruthRows(verifyTruthTable(50))}
					>
						Run all
					</button>
				</div>
				<p className="kv">Secure AND(a,b) = {andResult}</p>
				<p className="kv">Secure XOR(a,b) = {xorResult}</p>
				<p className="kv">Secure NOT(a) = {notResult}</p>
				<div className="warn">
					Bob learns only a ∧ b via OT; Alice learns nothing about b beyond the
					protocol transcript.
				</div>
			</article>

			<article className="control-card">
				<h2>Protocol transcript</h2>
				<p className="kv">
					OT messages = ({andTranscript.messages[0]},{" "}
					{andTranscript.messages[1]})
				</p>
				<p className="kv">Received mb = {andTranscript.receivedMessage}</p>
				<p className="kv">
					XOR shares = ({xorTranscript.aliceShare}, {xorTranscript.bobShare})
				</p>
				<div className="step-list">
					{andTranscript.transcript.map((entry) => (
						<div key={entry} className="step-card">
							<p className="kv">{entry}</p>
						</div>
					))}
				</div>
			</article>

			<article className="control-card">
				<h2>Truth table check</h2>
				<div className="step-list">
					{truthRows.map((row) => (
						<div key={`${row.a}${row.b}`} className="step-card">
							<div className="step-head">
								<strong>
									a={row.a}, b={row.b}
								</strong>
								<span
									className={`status-pill${row.andOk && row.xorOk ? " ready" : ""}`}
								>
									{row.andOk && row.xorOk ? "passed" : "failed"}
								</span>
							</div>
							<p className="kv">
								AND ok = {String(row.andOk)} · XOR ok = {String(row.xorOk)}
							</p>
							<p className="kv">Transcript: {row.transcript}</p>
						</div>
					))}
				</div>
			</article>
		</div>
	);
}

function CircuitTraceView({ result }: { result: SecureEvalResult }) {
	return (
		<div className="control-card" style={{ marginTop: "0.75rem" }}>
			<h2>Gate trace</h2>
			<div className="warn" style={{ marginBottom: "0.65rem" }}>
				OT calls used: {result.otCalls}
			</div>
			<div
				className="hex"
				style={{
					marginBottom: "0.65rem",
					background:
						"linear-gradient(90deg, rgba(15, 138, 127, 0.18), rgba(215, 108, 47, 0.12))",
				}}
			>
				Gates completed: {result.gateLog.length}
			</div>
			<div className="step-list">
				{result.gateLog.map((step, index) => (
					<div key={`${step.gateId}-${index}`} className="step-card">
						<div className="step-head">
							<strong>
								{index + 1}. {step.gateId}
							</strong>
							<span
								className={`status-pill${step.op === "AND" ? " ready" : ""}`}
							>
								{step.op}
							</span>
						</div>
						<p className="kv">Inputs: {step.inputs.join(", ")}</p>
						<p className="kv">
							Output wire: {step.outputWire} = {step.outputBit}
						</p>
						<p className="kv">{step.note}</p>
					</div>
				))}
			</div>
		</div>
	);
}

function Pa20Card() {
	const millionaireCircuit = useMemo(() => buildMillionaireCircuit(4), []);
	const equalityCircuit = useMemo(() => buildEqualityCircuit(4), []);
	const additionCircuit = useMemo(() => buildAdditionCircuit(4), []);

	const [xMillionaire, setXM] = useState(7);
	const [yMillionaire, setYM] = useState(12);
	const [xEquality, setXE] = useState(9);
	const [yEquality, setYE] = useState(9);
	const [xAddition, setXA] = useState(7);
	const [yAddition, setYA] = useState(12);

	const millionaireDemo = useMemo(() => {
		const trace = millionaireCircuit.secureEvaluate(
			intToBits(xMillionaire, 4),
			intToBits(yMillionaire, 4),
		);
		const output =
			trace.outputBits[0] === 1
				? "Alice is richer"
				: trace.outputBits[1] === 1
					? "Equal"
					: "Bob is richer";
		return { trace, output };
	}, [millionaireCircuit, xMillionaire, yMillionaire]);

	const equalityDemo = useMemo(() => {
		const trace = equalityCircuit.secureEvaluate(
			intToBits(xEquality, 4),
			intToBits(yEquality, 4),
		);
		return { trace, output: trace.outputBits[0] };
	}, [equalityCircuit, xEquality, yEquality]);

	const additionDemo = useMemo(() => {
		const trace = additionCircuit.secureEvaluate(
			intToBits(xAddition, 4),
			intToBits(yAddition, 4),
		);
		return { trace, output: bitsToInt(trace.outputBits) };
	}, [additionCircuit, xAddition, yAddition]);

	return (
		<div className="control-grid">
			<article className="control-card">
				<h2>Millionaire’s problem</h2>
				<div className="control-field">
					<label htmlFor="pa20-xm">Alice x</label>
					<input
						id="pa20-xm"
						type="number"
						min={0}
						max={15}
						value={xMillionaire}
						onChange={(event) =>
							setXM(fromHexInput(event.target.value, 7) % 16)
						}
					/>
				</div>
				<div className="control-field">
					<label htmlFor="pa20-ym">Bob y</label>
					<input
						id="pa20-ym"
						type="number"
						min={0}
						max={15}
						value={yMillionaire}
						onChange={(event) =>
							setYM(fromHexInput(event.target.value, 12) % 16)
						}
					/>
				</div>
				<p className="kv">Result: {millionaireDemo.output}</p>
				<p className="kv">OT calls: {millionaireDemo.trace.otCalls}</p>
				<p className="kv">
					Circuit trace shows AND/XOR/NOT gates in topological order.
				</p>
				<CircuitTraceView result={millionaireDemo.trace} />
			</article>

			<article className="control-card">
				<h2>Secure equality</h2>
				<div className="control-field">
					<label htmlFor="pa20-xe">Alice x</label>
					<input
						id="pa20-xe"
						type="number"
						min={0}
						max={15}
						value={xEquality}
						onChange={(event) =>
							setXE(fromHexInput(event.target.value, 9) % 16)
						}
					/>
				</div>
				<div className="control-field">
					<label htmlFor="pa20-ye">Bob y</label>
					<input
						id="pa20-ye"
						type="number"
						min={0}
						max={15}
						value={yEquality}
						onChange={(event) =>
							setYE(fromHexInput(event.target.value, 9) % 16)
						}
					/>
				</div>
				<p className="kv">Equal = {equalityDemo.output}</p>
				<p className="kv">OT calls: {equalityDemo.trace.otCalls}</p>
				<CircuitTraceView result={equalityDemo.trace} />
			</article>

			<article className="control-card">
				<h2>Secure bit-addition</h2>
				<div className="control-field">
					<label htmlFor="pa20-xa">Alice x</label>
					<input
						id="pa20-xa"
						type="number"
						min={0}
						max={15}
						value={xAddition}
						onChange={(event) =>
							setXA(fromHexInput(event.target.value, 7) % 16)
						}
					/>
				</div>
				<div className="control-field">
					<label htmlFor="pa20-ya">Bob y</label>
					<input
						id="pa20-ya"
						type="number"
						min={0}
						max={15}
						value={yAddition}
						onChange={(event) =>
							setYA(fromHexInput(event.target.value, 12) % 16)
						}
					/>
				</div>
				<p className="kv">Sum mod 2⁴ = {additionDemo.output}</p>
				<p className="kv">OT calls: {additionDemo.trace.otCalls}</p>
				<CircuitTraceView result={additionDemo.trace} />
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
		pa16: "PA #16",
		pa17: "PA #17",
		pa18: "PA #18",
		pa19: "PA #19",
		pa20: "PA #20",
	};
	const noteByAssignment: Record<Pa16Assignment, string> = {
		pa16: "Shows ElGamal malleability by comparing a normal ciphertext with a doubled ciphertext.",
		pa17: "Wraps ElGamal with signatures so modified ciphertexts are rejected before decryption.",
		pa18: "Lets Bob learn exactly one of two messages using oblivious transfer.",
		pa19: "Builds secure AND, XOR, and NOT from OT and local bit sharing.",
		pa20: "Evaluates small secure circuits using the PA19 primitives.",
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
			<h3>{titleByAssignment[activeAssignment]}: Public-Key Crypto and MPC</h3>
			<p className="panel-note">{noteByAssignment[activeAssignment]}</p>

			<div className="pa16-suite-scroll">
				<div className="control-grid pa16-suite-grid">{content}</div>
			</div>
		</section>
	);
}
