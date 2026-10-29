# WAL durability and recovery contract

The current fixed-width record is 101 bytes: view (8), sequence (8), phase (1), sender ID (4), digest (32), compressed signature point (48).

Changes on branch `fix/wal-crash-recovery`:
- Append now calls `sync_data()` before returning, instead of only flushing userspace buffers.
- Replay distinguishes clean EOF from a truncated final record and returns `UnexpectedEof` instead of silently accepting a partial tail.
- Replay rejects invalid compressed signature points instead of silently skipping them.
- Pruning rejects truncated records, syncs the replacement file, atomically renames it, and syncs the parent directory on Unix before reopening the WAL.
- Tests cover record round-trip, truncated tail rejection, invalid point rejection, pruning retention, and relative-path handling.

## Remaining risks

This is a targeted hardening step, not a complete crash-consistency proof. The record format still has no version or checksum, and a valid curve point is not proof that its signature authenticates the record. Callers must independently verify protocol signatures and enforce state-transition rules. File and directory sync guarantees vary by filesystem and platform. Crash-injection testing on target filesystems is still required.
