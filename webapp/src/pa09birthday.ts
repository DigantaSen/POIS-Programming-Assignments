import { pa08HashNBits, u64ToBytes } from "./pa08hash";

export interface BirthdayResult {
  found: boolean;
  steps: number;
  digest?: number;
  x1?: number;
  x2?: number;
}

export function theoreticalK50(nBits: number): number {
  return Math.sqrt((2 ** (nBits + 1)) * Math.log(2));
}

function hN(x: number, nBits: number): number {
  return pa08HashNBits(u64ToBytes(x), nBits);
}

export function birthdayNaive(nBits: number, maxTrials = 120000): BirthdayResult {
  const seen = new Map<number, number>();
  for (let i = 1; i <= maxTrials; i++) {
    const x = Math.floor(Math.random() * 0xffff_ffff);
    const d = hN(x, nBits);
    const prev = seen.get(d);
    if (prev !== undefined && prev !== x) {
      return { found: true, steps: i, digest: d, x1: prev, x2: x };
    }
    seen.set(d, x);
  }
  return { found: false, steps: maxTrials };
}

export function birthdayFloyd(nBits: number): BirthdayResult {
  const mask = nBits === 32 ? 0xffff_ffff : ((1 << nBits) - 1);
  const f = (x: number) => hN(x, nBits) & mask;

  const x0 = Math.floor(Math.random() * (mask + 1));
  let tortoise = f(x0);
  let hare = f(f(x0));
  let steps = 1;

  while (tortoise !== hare && steps < (1 << Math.min(nBits + 2, 20))) {
    tortoise = f(tortoise);
    hare = f(f(hare));
    steps++;
  }

  if (tortoise !== hare) {
    return { found: false, steps };
  }

  let mu = 0;
  tortoise = x0;
  while (tortoise !== hare) {
    tortoise = f(tortoise);
    hare = f(hare);
    mu++;
  }

  let lambda = 1;
  hare = f(tortoise);
  while (tortoise !== hare) {
    hare = f(hare);
    lambda++;
  }

  if (mu === 0) {
    return { found: false, steps: steps + lambda };
  }

  let a = x0;
  for (let i = 0; i < mu - 1; i++) a = f(a);
  let b = x0;
  for (let i = 0; i < mu + lambda - 1; i++) b = f(b);

  const da = f(a);
  const db = f(b);
  return {
    found: a !== b && da === db,
    steps: steps + mu + lambda,
    digest: da,
    x1: a,
    x2: b,
  };
}
