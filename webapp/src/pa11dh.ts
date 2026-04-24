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
  // Matches the backend PA11 toy-size setup class of values.
  p: 1460213603,
  q: 730106801,
  g: 34946565,
};

function modPow(base: number, exp: number, mod: number): number {
  let b = base % mod;
  let e = exp;
  let acc = 1;
  while (e > 0) {
    if (e & 1) acc = (acc * b) % mod;
    b = (b * b) % mod;
    e >>= 1;
  }
  return acc;
}

function randInt(lo: number, hi: number): number {
  return lo + Math.floor(Math.random() * (hi - lo + 1));
}

export function genSafePrime(bits = 30): DHParams {
  void bits;
  // Avoid expensive prime search in React render path.
  return TOY_DH_PARAMS;
}

export function keygen(params: DHParams): DHKeyPair {
  const sk = randInt(2, params.p - 2);
  const pk = modPow(params.g, sk, params.p);
  return { sk, pk };
}

export function shared(params: DHParams, sk: number, peerPk: number): number {
  return modPow(peerPk, sk, params.p);
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
