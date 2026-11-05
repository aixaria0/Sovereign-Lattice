# Engineering remediation baseline

This document tracks the evidence required to move Sovereign Lattice from a research implementation toward a reviewable production candidate. It is a plan, not a claim that the listed work is complete.

## Guardrails

- Keep protocol changes isolated on short-lived branches and reviewable pull requests.
- Do not merge or deploy based only on green CI.
- Preserve the distinction between a Lean theorem, Rust test coverage, an integration result, and a production guarantee.
- Do not delete tracked build artifacts until their provenance, generated status, and repository history impact have been checked.
- Tie performance claims to reproducible benchmark commands, hardware, topology, workload, and raw results.

## Workstreams and acceptance gates

### 1. Repository hygiene

- [x] Add ignore rules for Rust build output and local node/WAL files.
- [ ] Remove already tracked generated artifacts in a dedicated reviewed change after confirming they are reproducible and not required inputs. `.gitignore` does not untrack existing files.
- [ ] Add a CI check that rejects newly tracked build output and accidental WAL/log files.

### 2. Protocol safety and view change

- [ ] Resolve [issue #6](https://github.com/aixaria0/Sovereign-Lattice/issues/6) with a canonical signed view-change statement binding target view, prepared-certificate source view, sequence, digest, and signer identity.
- [ ] Specify deterministic new-view selection and reject conflicting highest-sequence claims without relying on map iteration order.
- [ ] Add tests for duplicate signers, tampered certificates, same-sequence certificates from different views, conflicting digests, and restart/replay after view change.
- [ ] Demonstrate accepted/rejected implementation traces against the written protocol rule.

### 3. WAL and recovery

- [ ] Review [PR #5](https://github.com/aixaria0/Sovereign-Lattice/pull/5) as proposed durability hardening; it is not merged by this plan.
- [ ] Design a versioned WAL envelope with record type/version, length, checksum or authenticated integrity, and explicit migration behavior.
- [ ] Define snapshot/checkpoint semantics and the recovery invariant precisely.
- [ ] Add fault injection for partial writes, failed sync, rename, directory sync, compaction, deletion, reordering, and stale-storage rollback where feasible.
- [ ] Run crash/restart tests on target filesystems and storage stack.

### 4. Formal assurance

- [ ] Keep abstract quorum theorems separate from implementation claims.
- [ ] Define a trace/state correspondence between Rust transitions and the Lean model.
- [ ] Extend the model only after canonical protocol rules are settled.
- [ ] Model liveness separately, including partial synchrony, timeout assumptions, and scheduler fairness.

### 5. Transport and cryptographic review

- [ ] Implement and test authenticated peer identity and transport encryption (mTLS or Noise).
- [ ] Review BLS message domain separation, key generation/distribution, key custody, signature aggregation, and constant-time assumptions.
- [ ] Add replay protection binding authenticated peer identity, protocol version, view, sequence, and message type.

### 6. Performance and capacity

The target of 10,000,000 transactions/day is an average of approximately 115.74 transactions/second. That average is not a sufficient benchmark target.

- [ ] Define transaction size, payload mix, validator count, fault model, durability mode, and geographic topology.
- [ ] Benchmark sustained throughput, p50/p95/p99 latency, CPU, memory, network, WAL write amplification, and recovery time.
- [ ] Test burst load and degraded modes (one unavailable validator, slow disk, network delay/loss, leader change).
- [ ] Publish reproducible scripts, machine specs, configuration, raw results, and confidence intervals.

## Current inspected baseline

As inspected on 2026-11-05, the default branch was main at `78fad9f`. PR #5 (`fix/wal-crash-recovery`) had three passing workflows on head `fff1629` (Rust CI, Lean build, and four-node smoke test), but remained open and unmerged. These results are branch-specific CI evidence, not a production-readiness determination.

The Desktop Commander device was offline during this review, so no local checkout or local test execution was available. GitHub Actions must provide validation for this documentation-only baseline PR.
