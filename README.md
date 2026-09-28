# 💠 Sovereign Lattice

[![Rust Build](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](#)
[![Lean 4 Verified](https://img.shields.io/badge/Formal_Verification-Lean_4-blue.svg)](#)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](#)

**Sovereign Lattice** is a high-performance, Byzantine Fault Tolerant (PBFT) consensus engine built in Rust. Designed for deterministic state transitions, it enforces cryptographic integrity via BLS12-381 threshold signatures with selected protocol invariants modeled and checked in Lean 4 alongside Rust implementation tests.

The repository combines explicit protocol invariants, Rust implementation tests, cryptographic checks, asynchronous networking, and state-machine replication.

https://aixaria0.github.io/SOVEREIGN_LATTICE/

## 🏗 Core Architecture

* **Formally Verified Consensus:** Core PBFT state transitions and quorum rules ($N = 3f + 1$) are formally verified using Lean 4.
* **Cryptographic Engine:** Implements `bls12-381` for constant-time pairing checks, signature aggregation, and malicious forgery rejection.
* **Asynchronous Transport:** Asynchronous, non-blocking TCP P2P networking powered by `tokio`.
* **Zero-Panic Parsing:** Network payloads are strictly bound to a 101-byte fixed-size binary parser, eliminating memory exhaustion vectors and deserialization panics.
* **Crash-Fault Resilience:** Integrated Write-Ahead Log (WAL) ensures atomic state recovery during unexpected node failures.

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
The unique proposition of Sovereign Lattice is its rigorous approach to safety. The system does not rely solely on unit tests; its core logic is subjected to Lean 4 formal verification.
Any incoming network payload that violates the established topology, cryptographic bounds, or state sequence is deterministically dropped before it can mutate the state machine.

Aixaria, Aria Fani

📜 License

Apache-2.0 license

## Assurance fabric role

Sovereign-Lattice is an **optional independent evidence-root attestor** in the v1 assurance fabric. The repair attestation module domain-separates and binds the propagation-envelope digest, Sentinel observation digest, repair problem identity, and native-replay eligibility. This attestation is not a replacement for Casper consensus and does not independently prove target-protocol safety or finality.
