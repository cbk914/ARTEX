# ADR 0005: Bounded task archive transactions

Status: proposed; the current package and restore implementation remains in use.

## Source review

`archiveTask` stops task admission, cancels chat and waits for task agents and
side questions to drain before taking a PostgreSQL snapshot. File staging
renames task files, spills and transcripts under a private archive directory;
its journal supports replay or rollback after interruption. The package writer
uses a temporary `.partial` file, SHA-256 and a final rename. Restore checks
the package checksum, extracts into a temporary directory and uses a restore
journal. Existing round-trip, path-traversal, symlink, interrupted-stage and
remote-journal tests exercise parts of this design.

The package writer and extractor have no `context.Context` or operation
deadline. Their disk reads, zstd work and writes can continue after a queued
job is cancelled or the server begins shutdown. Extraction checks tar headers
against `maxArchiveFiles = 1_000_000` and `maxArchiveBytes = 128 TiB`. Those are
corruption ceilings, not practical per-job resource budgets. A compact zstd
archive can therefore demand far more disk and time than the operator expects.
The local remediation branch replaced the additive size check with an
overflow-safe subtraction and capped zstd decoder memory at 64 MiB; the
existing archive format is unchanged. The checksum
is verified by reading the entire compressed file before extraction, but that
does not itself bound decompressed output or prove that mutable source bytes
matched the PostgreSQL snapshot.

These observations confirm ARTEX-007 as a partial transaction and resource
isolation gap. The code review does not prove that a live task can mutate the
private staging directory after drain, or that an archive currently contains
inconsistent records. Those require targeted race and integration tests.

## Required implementation

1. Add explicit operator-configurable, conservative defaults for compressed
   size, extracted bytes, entry count, single-file size, manifest size and
   runtime. Record the applied policy and measured sizes per archive. Do not
   make existing archives unreadable merely because new creation defaults are
   lower: provide a reviewed restore override and a migration procedure.
2. Stream package and extraction through cancellable, byte-counted readers and
   writers. Check cancellation between entries and during large copies. Keep
   overflow-safe arithmetic before allocating or writing each entry. Test the
   zstd decoder memory ceiling independently of tar header limits.
3. Open staged source files through a private directory handle; reject a
   replaced path, symlink, or nonregular descriptor. Verify the descriptor's
   metadata against the entry chosen for the archive and record a per-file
   checksum. Keep the stage inaccessible to executors. Define what happens if
   an authorized external writer changes a file in place during packaging.
4. Couple the file and database snapshot to a stable generation or a durable
   mutation barrier. The archive should contain enough provenance to detect
   a mismatch before deleting the hot task. Preserve the existing journal
   rollback behavior for any failure, timeout or cancellation.
5. On restore, validate the manifest and all package metadata before installing
   task files, evidence or database rows. Write into a private temporary root,
   then make the installation atomic at the supported granularity. Retain the
   original package until both file and database commit are confirmed.

## Acceptance tests

- Package a task while a synthetic writer repeatedly changes a file; either
  obtain a proven consistent generation or fail and restore the hot task.
- Cancel packaging and extraction during a large stream; bound exit time and
  verify no partial archive is advertised and no hot data is lost.
- Reject malformed tar names, duplicates, oversized headers, decompression
  bombs, symlink/hardlink entries, integer-overflow sizes and truncated data.
- Restore a valid legacy package under a reviewed override, then simulate
  failure before and after database commit and verify journal recovery.
- Run on disposable PostgreSQL and volumes with concurrent task activity;
  compare task records and file hashes before archive and after restore.

No current test or static limit is by itself evidence of transaction-wide
consistency. Do not deploy the new format or delete old packages until the
recovery and compatibility tests pass.
