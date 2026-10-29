# WAL durability and recovery contract

The current fixed-width record is 101 bytes: view (8), sequence (8), phase (1), sender ID (4), digest (32), compressed signature point (48).

Changes on branch `fix/wal-crash-recovery`:
- Append now calls `sync_data()` before returning, instead of only flushing userspace buffers.
- Replay distinguishes clean EOF from a truncated final record and returns `UnexpectedEof` instead of silently accepting a partial tail.
- Replay rejects invalid compressed signature points instead of silently skipping them.
- Pruning rejects truncated records, syncs the replacement file, atomically renames it, reopens the replacement WAL before syncing the parent directory on Unix, and retains checkpoint-sequence records as recovery evidence.
- PBFT rolls back in-memory protocol changes when a transition is rejected or its WAL append fails. After an append or checkpoint-compaction error, the node enters a fail-stop state and rejects further protocol messages until restart/replay.
- Tests cover record round-trip, truncated tail rejection, invalid point rejection, pruning retention, relative-path handling, failed-append state rollback, and recovery of a stable checkpoint after compaction and restart.

## Remaining risks

This is a targeted hardening step, not a complete crash-consistency proof. The PBFT code treats persistence errors as fail-stop conditions because a failed write may have partially extended the WAL; on restart, truncated records are rejected rather than silently ignored. The record format still has no version or checksum, and a valid curve point is not proof that its signature authenticates the record. Callers must independently verify protocol signatures and enforce state-transition rules. File and directory sync guarantees vary by filesystem and platform. Crash-injection testing on target filesystems is still required.
