import { makeRng } from "./rng";

export interface BindingTrial {
  unboundHits: number;
  boundHits: number;
  tries: number;
  target: number;
}

/**
 * Shows why a binding coefficient exists.
 * Unbound: the last signer sees the others and forces the sum into a bucket.
 * Bound: their second nonce changes the coefficient, so the same search mostly misses.
 * Toy integers — not an attack on a real curve.
 */
export function bindingTrial(seed: number, tries = 48): BindingTrial {
  const rng = makeRng(seed);
  const target = 3;
  const mod = 17;
  let unboundHits = 0;
  let boundHits = 0;
  for (let i = 0; i < tries; i++) {
    const honest = [1 + Math.floor(rng() * 12), 1 + Math.floor(rng() * 12), 1 + Math.floor(rng() * 12)];
    const sumH = honest.reduce((a, x) => a + x, 0);
    const needed = (target - (sumH % mod) + mod) % mod;
    const unbound = (sumH + needed) % mod;
    if (unbound === target) unboundHits += 1;

    let hit = false;
    for (let guess = 0; guess < 12; guess++) {
      const n1 = 1 + ((seed + i) % 9);
      const n2 = guess + 1;
      const all = [...honest, n1, n2];
      const b = (all.reduce((a, x) => a + x * 3, 7) + i) % 7;
      const effective = (sumH + n1 + b * n2) % mod;
      if (effective === target) {
        hit = true;
        break;
      }
    }
    if (hit) boundHits += 1;
  }
  return { unboundHits, boundHits, tries, target };
}
