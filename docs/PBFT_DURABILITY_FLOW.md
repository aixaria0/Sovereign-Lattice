# PBFT durability and crash-recovery flow

This diagram describes the ordering enforced by the Rust message handler and write-ahead log (WAL). It is an implementation guide, not a proof of the full PBFT protocol.

```mermaid
flowchart TD
    A[Receive PBFT message] --> B{Sender registered and signature valid?}
    B -- No --> X[Reject without state mutation or WAL append]
    B -- Yes --> C[Validate view, leader, phase prerequisites, and certificates]
    C --> D{Transition valid?}
    D -- No --> X
    D -- Yes --> E[Take rollback image and stage protocol-state changes]
    E --> F[Append signed message record to WAL]
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
4. **Recovery fails closed.** A truncated record, invalid compressed point, unknown phase, unregistered signer, invalid signature, or inconsistent protocol prerequisite must not be silently accepted.
5. **A passing workflow is not a proof of crash consistency.** Filesystem-specific crash injection, independent protocol review, and real workload benchmarking remain required.

## Scope and open protocol question

The current view-change message abstraction carries a target view, sequence, and digest, while a full PBFT view-change proof must also preserve enough information to identify and compare prepared certificates from earlier views. The recent fix allows a valid prepared certificate from an earlier view to support a transition, but the certificate-selection rules still need a dedicated protocol review and adversarial tests for competing prepared certificates at the same sequence. See the follow-up issue linked from this change before treating this implementation as production-ready.
