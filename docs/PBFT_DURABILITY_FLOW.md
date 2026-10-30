# PBFT durability and crash-recovery flow

This diagram describes the ordering enforced by the Rust message handler and write-ahead log (WAL). It is an implementation guide, not a proof of the full PBFT protocol.

```mermaid
flowchart TD
    A[Receive PBFT message] --> B{Sender registered and signature valid?}
    B -- No --> X[Reject without state mutation or WAL append]
    B -- Yes --> C[Validate view, leader, phase prerequisites, and certificates]
    C --> D{Phase prerequisites valid?}
    D -- No --> X
    D -- Yes --> E[Take rollback image and stage protocol-state changes]
    E --> Q{Did this view-change message form a quorum?}
    Q -- No --> F[Append signed message record to WAL]
    Q -- Yes --> U{One unambiguous digest at the highest sequence?}
    U -- No --> Y[Restore rollback image and reject conflicting view change]
    U -- Yes --> F
    F --> G[write_all then sync_data]
    G --> H{Durable append succeeded?}
    H -- No --> I[Restore in-memory state; mark WAL unavailable]
    I --> J[Fail-stop until restart and replay]
    H -- Yes --> K[Transition may be acknowledged or exposed]
    K --> L{Did this message stabilize a checkpoint?}
    L -- No --> M[Return response]
    L -- Yes --> N[Compact WAL, retaining checkpoint-sequence evidence and later records]
    N --> O{Compaction and required syncs succeeded?}
    O -- Yes --> M
    O -- No --> P[Mark WAL unavailable; stop accepting messages]
    P --> J

    R[Process restart] --> S[Open and replay complete fixed-width WAL records]
    S --> T{Every record complete, decodable, authenticated, and protocol-consistent?}
    T -- No --> U[Fail closed; require operator investigation]
    T -- Yes --> V[Rebuild proposals, votes, quorum certificates, view, and stable checkpoint]
    V --> W[Resume only from reconstructed durable state]
    J --> R
```

## Durability invariants

1. **No acknowledgment before durability.** A handled message is appended and `sync_data()` completes before the handler returns success.
2. **Failed append means rollback and fail-stop.** A failed append can leave a partial record, so the current node restores its in-memory rollback image and stops processing messages until restart/replay.
3. **Checkpoint evidence must survive compaction.** The WAL retains records at the stable checkpoint sequence so replay can reconstruct the checkpoint quorum; older records can be removed only after the replacement WAL has been written and synced.
4. **Conflicting highest-sequence view-change claims are rejected.** If votes at the maximum prepared sequence report different digests, the new view is not selected based on nondeterministic map iteration.
5. **Recovery fails closed.** A truncated record, invalid compressed point, unknown phase, unregistered signer, invalid signature, or inconsistent protocol prerequisite must not be silently accepted.
6. **A passing workflow is not a proof of crash consistency.** Filesystem-specific crash injection, independent protocol review, and real workload benchmarking remain required.

## Scope and open protocol question

The current view-change message abstraction carries a target view, sequence, and digest, while a full PBFT view-change proof must also preserve enough information to identify and compare prepared certificates from earlier views. This change rejects conflicting digests at the highest reported sequence, eliminating a nondeterministic selection path. It does not yet settle the full PBFT rule for selecting the highest *prepared view* when multiple valid certificates exist for the same sequence. That question still needs protocol-level specification and adversarial tests. See issue #6 before treating this implementation as production-ready.
