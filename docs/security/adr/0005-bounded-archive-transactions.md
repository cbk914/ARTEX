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

The package writer and extractor now receive the server context and check it
between entries and file-copy chunks. A cancelled package is not advertised;
the worker's existing rollback removes its staging tree. The paths still have
no per-job cancellation or operation deadline, and a single blocking filesystem
read cannot be interrupted promptly by a context check. At baseline,
extraction checked tar headers against one million entries and 128 TiB.
Those were corruption ceilings, not practical per-job resource budgets.
The local remediation branch replaced the additive size check with an
overflow-safe subtraction and capped zstd decoder memory at 64 MiB; the
existing archive format is unchanged. The checksum
is verified by reading the entire compressed file before extraction, but that
does not itself bound decompressed output or prove that mutable source bytes
matched the PostgreSQL snapshot.

Packaging and restoration now share configurable defaults for compressed
bytes (8 GiB), expanded bytes (16 GiB), one file (4 GiB), manifest (32 MiB),
entries (100,000) and path depth (64). Fixed ceilings are 32 GiB, 64 GiB,
32 GiB, 128 MiB, 250,000 and 128 respectively. A bounded writer stops
compressed output before the cap and leaves no published `.partial` package.
The extractor checks compressed input before checksum verification, applies
overflow-safe header budgets before file creation, and limits its decoder
input. Remote restore checks recorded compressed size before downloading.
Invalid settings fail the operation. A stored legacy archive above a default
is retained; an operator can review it and raise a setting within its fixed
ceiling for restoration. Packages above a fixed ceiling need a separately
reviewed migration. These limits do not bound job runtime, total campaign
storage or in-place file mutation. The applied policy is not yet recorded in
archive metadata, and full legacy restore migration has not been tested.

The package writer now walks the private staging tree through `os.Root.FS()`
and opens regular files relative to that root. It compares the selected entry
with the opened descriptor and rejects changes to the file size or modification
time during a copy. Deterministic tests cover a replaced file, a parent changed
to a link outside the stage, and a changed path to the staging root. This closes
the path-based reopen in the package writer. It does not prevent an authorized
writer from changing bytes in place and restoring the same metadata, prove a
database/file generation match, or enforce a mount boundary inside the root.

The extractor now opens its destination as an `os.Root` and creates tar
directories and files relative to that descriptor. A synthetic pre-fix test
placed a link from the restore directory to an outside directory and showed
that a regular tar entry followed it; the test passes after the change and
the outside directory remains untouched. Package round trips, traversal and
overflow checks passed, along with focused race tests, vet, Windows cross
compilation and native Windows round-trip/symlink tests. The caller still creates the outer restore directory by path;
this change does not prove a mount boundary or transaction-wide consistency.

These observations confirm ARTEX-007 as a partial transaction and resource
isolation gap. The code review does not prove that a live task can mutate the
private staging directory after drain, or that an archive currently contains
inconsistent records. Those require targeted race and integration tests.

Traffic blob export now opens a regular source under the traffic store's
`os.Root`, checks its identity and size, copies with a configured single-file
limit, and checks its content-addressed SHA-256 before publication. Historical
two-level blob paths remain supported. Legacy request/response files are read
under the same root with a 64 MiB limit in both export and display. A symlinked
blob, escaping legacy SQLite path or changed content fails instead of entering
the archive. The export now streams version-2 exchanges into a private
temporary `traffic.json` under a configurable 256 MiB default total limit,
with a fixed 4 GiB ceiling. A rejected export leaves the prior manifest in
place. One SQLite row is still fetched and JSON encoded in memory after a
body-size preflight; metadata and legacy reads retain bounded allocations.
Blob hashes remain in a deduplicated set until the manifest is finalized.
Local restoration and S3 upload now open a stored package through the private
archive directory with `os.Root`, reject linked components and a substituted
final file, and retain the descriptor through checksum verification and
consumption. This closes the name-based reopen on those active paths. It does
not prevent a writer with access to the private directory from mutating the
opened inode or prove a transaction-wide generation match to PostgreSQL.
Claimed jobs now use a configurable 240-minute default deadline with a hard
1440-minute ceiling. The job context reaches package copy/extraction, traffic
export/import, remote storage operations and PostgreSQL snapshot, compaction,
restore and metadata deletion transactions. Extracted traffic manifests and
blobs have rooted, bounded reads; imported blobs are hashed before installation
and existing destinations must match their hashes. Cancellation is still
cooperative: filesystem renames, JSON decoding and some metadata operations can
run beyond the exact instant of the deadline. The traffic destination bucket
now opens beneath the traffic store's `os.Root`; directory components are
checked before the bucket descriptor is retained, and temporary creation and
rename use that descriptor. A synthetic outside symlink is rejected. A local
actor that can mutate the store can still race or corrupt files inside the
root, so a separate write boundary remains necessary. Cross-store generation
consistency remains open. Older legacy files above 64 MiB need a reviewed
migration path.

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
3. Keep descriptor-bound source opens and rejection of replaced paths, links
   and nonregular descriptors. Record a per-file checksum and define what
   happens if an authorized external writer changes a file in place during
   packaging. Keep the stage inaccessible to executors.
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
