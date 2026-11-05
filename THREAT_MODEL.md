# Sovereign Lattice: Threat Model & Security Assumptions

This document records the threat assumptions and current mitigation status in the Sovereign Lattice PBFT research implementation. An implemented mitigation is not automatically a formally verified or independently audited security guarantee.

## 1. Core Assumptions

To guarantee safety and eventual liveness, Sovereign Lattice operates under the standard Byzantine Fault Tolerance (BFT) assumptions:
* **Network Topology:** The network consists of `N` nodes, where `N = 3f + 1`, and `f` is the maximum number of Byzantine (malicious or faulty) nodes.
* **Cryptography:** The BLS12-381 elliptic curve and its underlying pairing-based cryptography are secure against classical polynomial-time adversaries.
* **Network Synchrony:** The network is assumed to be partially synchronous. Safety is guaranteed under complete asynchrony, while liveness relies on periods of synchrony.
* **Authenticated Channels:** Required by the deployment model, but mTLS/Noise peer authentication is pending in the transport layer. Until implemented and tested, the network must be treated as lacking authenticated transport channels.

## 2. Threat Mitigation Matrix

| Attack Vector | Status | Mitigation Mechanism |
| :--- | :--- | :--- |
| **Double Commit (Safety Violation)** | ⚠️ Model-level theorem; implementation correspondence incomplete | Quorum intersection is checked in Lean under the stated assumptions. This does not prove every Rust execution path. |
| **Leader Equivocation** | ⚠️ Implementation checks present; adversarial review required | The state machine contains duplicate/conflicting proposal checks. End-to-end network and recovery behavior still require adversarial testing. |
| **Ghost Certificate Attack** | ⚠️ Partial mitigation; protocol issue open | Certificate validation exists, but canonical signed view-change evidence and complete selection semantics remain tracked in [issue #6](https://github.com/aixaria0/Sovereign-Lattice/issues/6). |
| **Signature Forgery** | ⚠️ Cryptographic checks implemented; independent review pending | The engine verifies BLS signatures at protocol boundaries. Key generation, key custody, domain separation, primitive configuration, and end-to-end composition require review. |
| **Network Partition / Split Brain** | ⚠️ Safety behavior requires fault-injection evidence | Quorum checks constrain progress, but partition, reconnect, duplicate, delay, and reordering behavior need deterministic network-scheduler tests. |
| **Replay Attacks** | ⏳ Partially mitigated | Protocol view/sequence checks exist; transport-level peer identity, nonce binding, and replay-window behavior remain incomplete. |
| **Sybil Attacks** | ⏳ Out of Scope | PBFT assumes a permissioned registry. A Sybil-resistance mechanism (e.g., PoS) must be implemented at the application layer. |

## 3. Detailed Attack Vectors

### 3.1 Ghost Certificate Attack (View-Change Exploitation)
**Threat:** A malicious leader constructs a `NewView` message claiming a high-sequence prepared certificate that was never actually prepared by an honest quorum, attempting to force the network to adopt a malicious state.
**Mitigation:** The `cross_view_inheritance` logic requires the leader to embed the exact `PreparedCertificate` matching the highest sequence claimed by the quorum. The Rust engine verifies all `2f + 1` signatures on this embedded certificate. (Covered by internal adversarial test: `test_ghost_certificate_attack_rejected`).

### 3.2 Leader Equivocation
**Threat:** A Byzantine primary sends different `PrePrepare` blocks to different replicas for the same sequence number, attempting to split the network.
**Mitigation:** The Rust state machine caches `pre_prepared_proposals`. If a replica receives a valid signature from the primary but the digest differs from an already cached proposal for that view/sequence, it immediately drops the payload and logs an `EQUIVOCATION_DETECTED` error.

### 3.3 Crash Faults & State Loss
**Threat:** An honest node crashes after voting, loses its state in RAM, reboots, and votes differently, violating the `f` Byzantine assumption.
**Mitigation status:** WAL persistence and replay are implemented, and [PR #5](https://github.com/aixaria0/Sovereign-Lattice/pull/5) proposes stronger sync, torn-record rejection, authenticated replay, rollback, and fail-stop behavior. That PR is not merged. Even after it is merged, crash-injection testing, filesystem-specific validation, snapshot semantics, and proof of recovery invariants remain necessary. Do not describe recovery as atomic or deterministic until those properties are demonstrated.


## 4. Assurance limits

The threat model is not a security audit. Lean theorems prove only the abstract properties and assumptions encoded in their statements. There is no complete Rust-to-Lean refinement proof. TCP peer authentication/encryption is pending. WAL durability calls do not establish power-loss safety on every filesystem or storage device. The fixed-width WAL record has no version field or checksum and does not by itself detect all deletion, reordering, or rollback events. No reproducible sustained-throughput benchmark currently establishes the 10-million-transactions-per-day target.

See [PROOF_COVERAGE.md](PROOF_COVERAGE.md) for the formal/implementation boundary and [ROADMAP.md](ROADMAP.md) for planned verification work.
