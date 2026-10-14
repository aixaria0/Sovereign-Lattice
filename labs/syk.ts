import { makeRng } from "./rng";

/** One tick of the toy dual-system. Not a holographic dual. */
export interface SykTick {
  t: number;
  volume: number;
  entropy: number;
  horizons: number;
  connectivity: number;
  island: boolean;
}

export interface SykRun {
  n: number;
  coupling: number;
  ticks: SykTick[];
  islandAt: number | null;
  verdict: string;
}

function entropy(state: number[]): number {
  const abs = state.map((x) => Math.abs(x));
  const sum = abs.reduce((a, x) => a + x, 0) + 1e-12;
  let s = 0;
  for (const a of abs) {
    const p = a / sum;
    s -= p * Math.log(p + 1e-12);
  }
  return s;
}

function norm(state: number[]): number {
  return Math.sqrt(state.reduce((a, x) => a + x * x, 0));
}

function evolve(state: number[], j: number[][], dt: number): number[] {
  const n = state.length;
  const next = state.slice();
  for (let i = 0; i < n; i++) {
    let acc = 0;
    const row = j[i]!;
    for (let k = 0; k < n; k++) acc += row[k]! * state[k]!;
    next[i] = Math.tanh(state[i]! + dt * acc);
  }
  return next;
}

/**
 * Two coupled chaotic systems. After mid-run, a short boundary coupling
 * pulls them together. Entropy and connectivity are diagnostics, not geometry.
 */
export function runSyk(opts: { n: number; steps: number; coupling: number; seed: number }): SykRun {
  const n = Math.max(8, Math.min(64, Math.round(opts.n)));
  const steps = Math.max(40, Math.min(240, Math.round(opts.steps)));
  const g = Math.max(0, Math.min(0.4, opts.coupling));
  const rng = makeRng(opts.seed);

  const jL: number[][] = [];
  const jR: number[][] = [];
  for (let i = 0; i < n; i++) {
    jL[i] = [];
    jR[i] = [];
    for (let k = 0; k < n; k++) {
      jL[i]![k] = 0;
      jR[i]![k] = 0;
    }
  }
  for (let i = 0; i < n; i++) {
    for (let k = i; k < n; k++) {
      const a = (rng() * 2 - 1) / Math.sqrt(n);
      const b = (rng() * 2 - 1) / Math.sqrt(n);
      jL[i]![k] = jL[k]![i] = a;
      jR[i]![k] = jR[k]![i] = b;
    }
  }

  let left = Array.from({ length: n }, () => rng() * 2 - 1);
  let right = left.slice();
  const ticks: SykTick[] = [];
  let islandAt: number | null = null;
  const threshold = 0.55 * Math.log(n);

  for (let t = 0; t < steps; t++) {
    left = evolve(left, jL, 0.08);
    right = evolve(right, jR, 0.08);
    const s = entropy(left);
    const island = s > threshold && t > steps * 0.45;
    if (island && islandAt === null) islandAt = t;
    if (island) {
      for (let i = 0; i < n; i++) {
        const delta = g * (left[i]! - right[i]!);
        left[i] = left[i]! - delta;
        right[i] = right[i]! + delta;
      }
    }
    const spread = Math.abs(Math.sin(t / 22));
    const horizons = Math.max(1, Math.round(1 + 4 * spread + (island ? 1 : 0)));
    const connectivity = 1 / (1 + Math.exp(-0.09 * (t - steps / 2)));
    ticks.push({
      t,
      volume: norm(left) + norm(right),
      entropy: s,
      horizons,
      connectivity,
      island,
    });
  }

  const peak = Math.max(...ticks.map((x) => x.entropy));
  const last = ticks[ticks.length - 1]!;
  const bent = last.entropy < peak * 0.97 && last.connectivity > 0.75;
  const verdict = bent
    ? "Entropy bends after the coupling turns on, and connectivity saturates. That is the toy’s Page-curve shape — a structural sketch, not AdS₂."
    : "No clean bend. Raise coupling, or give the run more ticks past the midpoint.";

  return { n, coupling: g, ticks, islandAt, verdict };
}
