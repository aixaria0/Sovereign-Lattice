import { makeRng } from "./rng";

export type ProfileId = "tablet" | "workstation" | "cluster";

export interface Profile {
  id: ProfileId;
  name: string;
  hardware: string;
  model: string;
  role: string;
  stack: string[];
}

export const PROFILES: Profile[] = [
  {
    id: "tablet",
    name: "Tab S9+ console",
    hardware: "12 GB · Snapdragon 8 Gen 2",
    model: "3B–4B quantized, local",
    role: "Command node. Routing, memory, and drafts stay on device. Heavy inference stays remote.",
    stack: ["Termux + tmux", "LiteLLM router", "SQLite memory", "Open WebUI", "Cloud models"],
  },
  {
    id: "workstation",
    name: "Team node",
    hardware: "64–128 GB · one GPU",
    model: "14B–32B",
    role: "Multi-step workflows, retrieval, and tracing for a small group.",
    stack: ["Planner", "Retriever", "Verifier", "Policy engine", "Local vector store"],
  },
  {
    id: "cluster",
    name: "Research plane",
    hardware: "GPU cluster",
    model: "Routed ensemble",
    role: "Shared memory, policy enforcement, and observability. The tablet still only orchestrates.",
    stack: ["Durable workflows", "Worker mesh", "Provenance ledger", "Admission control"],
  },
];

export interface GateResult {
  decision: "allow" | "review" | "reject";
  risk: number;
  intent: string;
  sensitivity: "public" | "internal" | "restricted";
  trace: string;
  reason: string;
}

const REJECT =
  /jailbreak|annihilat|viral seed|god mode|unrestricted execution|bypass safety|replicate to|one-time passcode/i;

export function gateRequest(text: string): GateResult {
  const trimmed = text.trim();
  const trace = `trc_${Math.abs(hash(trimmed)).toString(16).slice(0, 8)}`;
  if (!trimmed) {
    return {
      decision: "review",
      risk: 0,
      intent: "empty",
      sensitivity: "public",
      trace,
      reason: "Nothing to route.",
    };
  }
  if (REJECT.test(trimmed)) {
    return {
      decision: "reject",
      risk: 0.92,
      intent: "policy violation",
      sensitivity: "restricted",
      trace,
      reason: "Control plane refuses requests that ask to disable safety or spread a payload. That material stays out of the lattice.",
    };
  }
  const research = /proof|consensus|certificate|fidelity|syk|policy|kernel/i.test(trimmed);
  const sensitive = /key|secret|share|credential/i.test(trimmed);
  return {
    decision: research ? "allow" : "review",
    risk: sensitive ? 0.46 : research ? 0.18 : 0.32,
    intent: research ? "research task" : "general",
    sensitivity: sensitive ? "internal" : "public",
    trace,
    reason: research
      ? "Intent matches the research surface. Tools stay gated; the trace is logged."
      : "No clear research intent. Hold for a human look before any tool runs.",
  };
}

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h;
}

export interface EvoTick {
  t: number;
  proposed: number;
  accepted: number;
  delta: number;
  fitness: number;
  coverage: number;
  note: string;
}

/** Selection under a contradiction bound. Not an autonomous agent. */
export function evolveTrace(cycles: number, seed: number): EvoTick[] {
  const rng = makeRng(seed);
  const n = Math.max(8, Math.min(24, cycles));
  const ticks: EvoTick[] = [];
  for (let t = 0; t < n; t++) {
    const phase = t / (n - 1 || 1);
    const proposed = 4 + Math.round(rng() * 6 + phase * 4);
    const acceptRate = 0.12 + phase * 0.55;
    const accepted = Math.min(proposed, Math.round(proposed * acceptRate));
    const delta = Math.max(0.02, 0.18 - phase * 0.12 + (rng() - 0.5) * 0.015);
    const fitness = 0.42 + phase * 0.4 + accepted / 40;
    const coverage = Math.min(0.97, phase < 0.35 ? phase * 0.4 : 0.14 + (phase - 0.35) * 1.15);
    let note = "Micro-mutations. Most fail the divergence gate.";
    if (phase > 0.45 && phase < 0.7) note = "Same sparse-routing pattern shows up in separate clusters.";
    if (phase >= 0.7) note = "Coverage climbs by selection, not by a command.";
    ticks.push({
      t,
      proposed,
      accepted,
      delta: Number(delta.toFixed(3)),
      fitness: Number(Math.min(0.98, fitness).toFixed(3)),
      coverage: Number(coverage.toFixed(3)),
      note,
    });
  }
  return ticks;
}

export interface StrideRow {
  letter: string;
  name: string;
  threat: string;
  control: string;
}

export const STRIDE: StrideRow[] = [
  {
    letter: "S",
    name: "Spoofing",
    threat: "A node claims a quorum it does not have.",
    control: "Threshold signature over the digest. Partial signatures do not verify alone.",
  },
  {
    letter: "T",
    name: "Tampering",
    threat: "A share or witness is swapped after the vote.",
    control: "Binding commitment joins the classical certificate to the quantum witness.",
  },
  {
    letter: "R",
    name: "Repudiation",
    threat: "A dealer denies a bad share.",
    control: "Complaint is attributable. Inconsistent answer disqualifies the dealer.",
  },
  {
    letter: "I",
    name: "Information disclosure",
    threat: "Feldman complaints leak polynomial points.",
    control: "Prefer Pedersen blinding when complaints must not reveal the secret.",
  },
  {
    letter: "D",
    name: "Denial of service",
    threat: "View-change storms stall the cluster.",
    control: "Timeouts rotate the leader. Locked values are inherited, not dropped.",
  },
  {
    letter: "E",
    name: "Elevation",
    threat: "An agent treats a free-text mode as authority.",
    control: "Execution mode is a typed policy: timeout, retries, memory, network.",
  },
];
