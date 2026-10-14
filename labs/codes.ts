export interface CodeFamily {
  family: string;
  example: string;
  distance: string;
  strength: string;
  hardware: string;
}

export const CODE_FAMILIES: CodeFamily[] = [
  {
    family: "Surface",
    example: "Rotated surface",
    distance: "grows with patch",
    strength: "Local checks, ~1% threshold class",
    hardware: "Superconducting",
  },
  {
    family: "Color",
    example: "2D 6.6.6",
    distance: "grows with patch",
    strength: "Transversal Cliffords",
    hardware: "Trapped ion",
  },
  {
    family: "qLDPC",
    example: "Bivariate bicycle",
    distance: "growing, constant rate",
    strength: "Fewer physical qubits per logical",
    hardware: "Research / next devices",
  },
  {
    family: "Small codes",
    example: "Steane [[7,1,3]]",
    distance: "3",
    strength: "Already demonstrated",
    hardware: "Early logical demos",
  },
  {
    family: "Subsystem",
    example: "Bacon-Shor",
    distance: "grows",
    strength: "Simpler measurements",
    hardware: "Near-term experiments",
  },
];

export interface HashStep {
  name: string;
  detail: string;
}

export const HASH_TO_CURVE: HashStep[] = [
  {
    name: "expand_message_xmd",
    detail: "Message plus a unique DST expands into field elements. Reusing a DST across protocols breaks the random-oracle assumption.",
  },
  {
    name: "Simplified SWU",
    detail: "Each field element maps onto an isogenous curve, then a fixed degree-11 isogeny lands on BLS12-381.",
  },
  {
    name: "Clear cofactor",
    detail: "A short scalar, not the full (p^12−1)/r, puts the point in the prime-order subgroup.",
  },
  {
    name: "Random-oracle sum",
    detail: "Two mapped points are combined so the hash is indifferentiable. Same message, same point — required for aggregation.",
  },
];

/** Fidelity of an MPS approximation versus bond dimension. Variational beats plain SVD at the same χ. */
export function compressionCurve(entanglement: number): { chi: number; variational: number; svd: number }[] {
  const xi = 2.2 + entanglement * 6;
  const rows = [];
  for (let chi = 2; chi <= 24; chi += 2) {
    const discardedV = Math.exp(-chi / xi);
    const discardedS = Math.exp(-chi / (xi * 1.45));
    rows.push({
      chi,
      variational: Math.min(0.999, 1 - 0.42 * discardedV),
      svd: Math.min(0.995, 1 - 0.55 * discardedS),
    });
  }
  return rows;
}

/** Textbook 15-to-1 magic-state scaling, p_out ≈ 35 p³, for the distillation panel. */
export function distill(pIn: number, rounds: number): { round: number; error: number; states: number }[] {
  let p = Math.min(0.2, Math.max(1e-6, pIn));
  let states = 1;
  const out = [{ round: 0, error: p, states }];
  for (let r = 1; r <= rounds; r++) {
    p = Math.min(0.5, 35 * p * p * p);
    states *= 15;
    out.push({ round: r, error: p, states });
  }
  return out;
}
