# WAL durability and recovery contract

The current fixed-width WAL record is 101 bytes: view (8), sequence (8), phase (1), sender ID (4), digest (32), compressed signature point (48).

Changes on branch \`fix/wal-crash-recovery\`:
- Append calls \`sync_data()\` before returning.
- Replay distinguishes clean EOF from a truncated final record and returns \`UnexpectedEof\` instead of silently accepting a partial tail.
- Replay rejects invalid compressed signature points. PBFT startup additionally rejects unknown phases, unregistered senders, unauthenticated BLS signatures, invalid leader proposals, prepare/commit records without their required preceding evidence, and invalid reconstructed certificates.
- Recovery does not advance the current view because of a lone view-change vote. It rebuilds and verifies a quorum-backed new-view certificate before advancing from view-change evidence. A quorum of authenticated ordinary records or same-view checkpoint votes can also establish a previously active view after compaction.
- Checkpoint signatures are grouped by view, sequence, and digest, matching the fields signed by each vote. The live handler rejects checkpoint votes for a view other than the local current view; recovery will not combine votes from different views into a false quorum.
- Pruning validates complete records, syncs the replacement file, atomically renames it, reopens the replacement WAL before syncing the parent directory on Unix, and retains checkpoint-sequence records as recovery evidence.
- PBFT rolls back in-memory protocol changes when a transition is rejected or its WAL append fails. After an append or checkpoint-compaction error, the node enters a fail-stop state until restart/replay.
- Tests cover WAL edge cases, relative-path pruning, append-failure rollback, rejected view-change rollback, checkpoint recovery, rejection of unauthenticated WAL rows, quorum-backed view recovery, and mixed-view checkpoint quorum rejection.

## Remaining risks

This is a targeted hardening step, not a complete crash-consistency proof. The WAL format remains versionless and has no record checksum or explicit application-state snapshot format. Signature authentication detects invalid or forged rows, but it does not by itself detect every deletion, reordering, or storage rollback. File and directory sync guarantees vary by filesystem and platform. Crash-injection testing on target filesystems, independent security review, protocol-level review, and realistic throughput benchmarks are still required. This PR does not establish production readiness or prove the 10-million-transactions/day target. Speculative quantum-theory claims in research notes are not treated as production security guarantees.
