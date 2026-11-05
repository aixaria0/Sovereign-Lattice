# Formal Verification Coverage (Lean 4)

Lean 4 is used to check selected abstract properties of the protocol model. These theorems do not, by themselves, prove that the Rust implementation refines the model or that transport, cryptography, storage, and recovery satisfy the model's assumptions.

This document distinguishes a machine-checked theorem from its implementation correspondence. A green `lake build` confirms that the Lean project builds; it is not an end-to-end proof of the deployed consensus engine. Status below reflects the documented repository state and must be updated alongside code and test changes.

## Verification Matrix

| Property | Description | Lean 4 Proof | Rust Enforcement |
| :--- | :--- | :--- | :--- |
| **Quorum Intersection** | For `N = 3f+1`, two quorums of size `2f+1` intersect in at least `f+1` members; at most `f` are Byzantine under the model assumptions. | ✅ Abstract theorem | ⚠️ Runtime correspondence requires review |
| **Single-View Safety** | No conflicting commits at the same sequence and view under the model's state invariants. | ✅ Abstract theorem | ⚠️ Partial implementation mapping; adversarial validation required |
| **Cross-View Inheritance** | The abstract model preserves the selected prepared value across a valid view change. | ✅ Abstract theorem | ⚠️ Issue [#6](https://github.com/aixaria0/Sovereign-Lattice/issues/6) tracks canonical signed evidence and full implementation alignment |
| **Multi-View Safety** | No conflicting commits across views, given the model assumptions and transition rules. | ✅ Abstract theorem | ❌ Not established for all Rust view-change/recovery paths |
| **Protocol Liveness** | Progress under stated synchrony and failure assumptions. | ❌ Unverified | ❌ Timeout/liveness implementation and proof incomplete |
| **WAL Recovery Safety** | Crash/restart replay preserves protocol invariants and durable state. | ❌ Unverified | ⚠️ Hardening proposed in open PR #5; not a complete proof or snapshot guarantee |

## Theorem Highlights

### 1. Quorum Intersection (`quorum_intersection`)
Located in the `SovereignLattice` namespace, this theorem proves that for any network of size `N = 3f + 1`, any two subsets of size `2f + 1` will mathematically intersect by at least `f + 1` nodes. By extension, this guarantees at least one completely honest node exists in the intersection.
* **Status:** Fully machine-checked. No `sorry` axioms.

### 2. PBFT Safety (`PBFT_Safety`)
Proves that if a quorum commits digest `d1` and a quorum commits digest `d2` for the same sequence and view, `d1` must equal `d2`. It relies heavily on the immutability of honest nodes' preparation phases.
* **Status:** Fully machine-checked. 

### 3. Multi-View Safety (`Multi_View_Safety`)
The hardest invariant in BFT systems. It proves that if a digest `d1` is committed in view `v1`, no other digest `d2` can be committed at the same sequence in any future view `v2`. It inductively relies on `cross_view_inheritance`.
* **Status:** Proven in Lean 4. The strict integration of this specific theorem into the Rust `handle_message` router is currently heavily enforced via the `selected_prepared_certificate` bindings.

## A Note on "Provably Infallible"

We aim for absolute transparency. Sovereign Lattice formally verifies **PBFT safety properties under standard Byzantine assumptions**. The proofs currently focus on the state machine transition logic. 
Components interacting with the OS layer (TCP Tokio transport, Disk I/O for WAL, and BLS cryptography primitives) are assumed to be secure and behave as specified by their respective crates.


## Assurance boundary and next evidence required

- **Model correctness:** The Lean theorems establish only the propositions and assumptions encoded in the Lean sources.
- **Implementation correspondence:** No complete refinement proof currently connects all Rust state transitions, message validation, and WAL replay to the Lean model.
- **Cryptographic assumptions:** The model does not prove the correctness of the BLS12-381 crate, key generation/storage, signature encoding, or operational key lifecycle.
- **Persistence assumptions:** WAL sync calls and replay tests do not prove filesystem/device behavior under power loss, torn writes, deletion, reordering, rollback, or storage-controller failure.
- **Liveness:** Safety properties do not imply progress. Timeout behavior, partial synchrony assumptions, scheduler fairness, and network recovery need a separate model and test program.

Required evidence before a production claim: canonical protocol specification; signed view-change evidence including prepared-certificate source view; Rust-to-model refinement or an equivalent trace-conformance argument; adversarial stateful tests; crash-injection tests on target filesystems; independent protocol/cryptography review; and reproducible load, latency, and recovery benchmarks.
