# 💠 Sovereign Lattice

[![Rust Build](https://img.shields.io/badge/CI-see_GitHub_Actions-informational)](https://github.com/aixaria0/Sovereign-Lattice/actions)


**[Consensus Observatory](https://aixaria0.github.io/Sovereign-Lattice/)** — interactive PBFT, quorum, view-change, and safety visualization.

**Sovereign Lattice** is a research-stage Byzantine Fault Tolerant (BFT/PBFT) consensus implementation in Rust. It combines a protocol state machine, BLS12-381-based message authentication, asynchronous networking, a write-ahead log (WAL), implementation tests, and selected Lean 4 models.

The repository is not currently presented as production-ready. A successful build or CI run demonstrates only that the configured checks passed for a particular commit; it does not establish end-to-end protocol safety, crash consistency, liveness, or production performance. See [formal verification coverage](PROOF_COVERAGE.md), the [threat model](THREAT_MODEL.md), and the [protocol specification](SPEC.md) for explicit boundaries.

https://aixaria0.github.io/Sovereign-Lattice/


## Research console labs

Three labs sit next to the consensus engine. They are structural models, not hardware claims and not an unrestricted runtime.

* **Field** — coupled chaotic pair. Entropy and connectivity are diagnostics, not a wormhole.
* **Codes** — surface, color, and qLDPC families, bond-dimension compression, 15-to-1 distillation scaling, BLS12-381 hash-to-curve steps.
* **Fabric** — request gate, Tab S9+ command-node profile, selection trace, STRIDE, nonce-binding demo.

Source: [`labs/`](labs/).

## 🏗 Core Architecture

* **Protocol model:** Selected quorum and state-machine properties have Lean 4 proofs. The mapping from those abstract properties to every Rust execution path is incomplete.
* **Cryptography:** The Rust engine uses BLS12-381 primitives for message signatures and certificate checks. Constant-time behavior, key lifecycle, and end-to-end cryptographic composition require independent review.
* **Transport:** Asynchronous TCP networking is implemented with `tokio`. Peer authentication and transport encryption remain explicit security work, not an assumed feature.
* **Parsing:** The base PBFT message format is fixed-width (101 bytes); other protocol messages have their own formats and validation paths. This is not a blanket guarantee against resource-exhaustion or parser defects.
* **Persistence:** WAL append/replay hardening is under review in [PR #5](https://github.com/aixaria0/Sovereign-Lattice/pull/5). It is not yet merged and does not prove complete crash consistency or application-state recovery.

## ⚙️ Protocol Flow (PBFT)
1. **Pre-Prepare:** Leader broadcasts a cryptographically bound proposal.
2. **Prepare:** Replicas validate the BLS signature and broadcast a state vote.
3. **Commit:** Replicas wait for $2f + 1$ quorum to generate a `PreparedCertificate` and lock the state.
4. **View-Change (Strict):** Timeouts trigger a view replacement backed by a cryptographically proven `NewViewCertificate`.

## 🚀 Getting Started

### Prerequisites
* **Rust:** `1.70.0` or higher (Cargo package manager).
* **Lean 4:** Required only if you intend to run the formal verification proofs locally.

### Build & Run
Clone the repository and build the engine:

```bash
git clone [https://github.com/aixaria0/SOVEREIGN_LATTICE.git](https://github.com/aixaria0/SOVEREIGN_LATTICE.git)
cd SOVEREIGN_LATTICE/rust_engine

# Run the standard build
cargo build --release

# Run internal adversarial tests (Ghost Certificate Attack, Malicious Forgery, etc.)
cargo test
```

### Running a Node

```bash
The engine automatically boots the TCP transport daemon and awaits consensus messages.
cargo run --release
```

## 🛡️ Security & Formal Verification
Lean 4 currently checks selected abstract invariants, including quorum-intersection properties. Protocol liveness and WAL recovery safety are not formally verified, and the refinement relation between the Lean model and the Rust implementation is incomplete. The transport, operating-system I/O, key management, and cryptographic-library assumptions remain part of the trusted computing base. See [PROOF_COVERAGE.md](PROOF_COVERAGE.md) for the current matrix.

Aixaria, Aria Fani

📜 License

Apache-2.0 license

## Assurance fabric role

Sovereign-Lattice is an **optional independent evidence-root attestor** in the v1 assurance fabric. The repair attestation module domain-separates and binds the propagation-envelope digest, Sentinel observation digest, repair problem identity, and native-replay eligibility. This attestation is not a replacement for Casper consensus and does not independently prove target-protocol safety or finality.
