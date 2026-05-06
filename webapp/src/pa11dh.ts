export interface DHParams {
  p: number;
  q: number;
  g: number;
}

export interface DHKeyPair {
  sk: number;
  pk: number;
}

export interface MITMReport {
  aliceCompromised: boolean;
  bobCompromised: boolean;
  aliceBobStillEqual: boolean;
}

const TOY_DH_PARAMS: DHParams = {
  // Safe prime close to 2^32 for instant UI computation.
  p: 4294967087,
  q: 2147483543,
  // Generator for the order-q subgroup.
  g: 4,
};

export function dhModPow(base: number, exp: number, mod: number): number {
  const modulus = BigInt(mod);
  let b = BigInt(base) % modulus;
  let e = BigInt(exp);
  let acc = 1n;
  while (e > 0n) {
    if ((e & 1n) === 1n) acc = (acc * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return Number(acc);
}

function randInt(lo: number, hi: number): number {
  return lo + Math.floor(Math.random() * (hi - lo + 1));
}

export function randomSecret(params: DHParams): number {
  return randInt(2, params.p - 2);
}

export function clampSecret(params: DHParams, secret: number): number {
  const asInt = Number.isFinite(secret) ? Math.floor(secret) : 2;
  return Math.min(params.p - 2, Math.max(2, asInt));
}

export function publicFromSecret(params: DHParams, secret: number): number {
  return dhModPow(params.g, clampSecret(params, secret), params.p);
}

export function genSafePrime(bits = 30): DHParams {
  void bits;
  // Avoid expensive prime search in React render path.
  return TOY_DH_PARAMS;
}

export function keygen(params: DHParams): DHKeyPair {
  const sk = randomSecret(params);
  const pk = publicFromSecret(params, sk);
  return { sk, pk };
}

export function shared(params: DHParams, sk: number, peerPk: number): number {
  return dhModPow(peerPk, clampSecret(params, sk), params.p);
}

export function mitmDemo(params: DHParams): MITMReport {
  const alice = keygen(params);
  const bob = keygen(params);
  const mallory1 = keygen(params);
  const mallory2 = keygen(params);

  const aliceK = shared(params, alice.sk, mallory1.pk);
  const bobK = shared(params, bob.sk, mallory2.pk);

  const malloryAlice = shared(params, mallory1.sk, alice.pk);
  const malloryBob = shared(params, mallory2.sk, bob.pk);

  return {
    aliceCompromised: aliceK === malloryAlice,
    bobCompromised: bobK === malloryBob,
    aliceBobStillEqual: aliceK === bobK,
  };
}
