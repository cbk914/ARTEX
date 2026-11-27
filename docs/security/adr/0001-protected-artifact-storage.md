# ADR 0001: Protected artifact storage and campaign-scoped delivery

Status: Proposed (2026-11-27). No runtime migration or deployment is authorized by this document.

## Context

ARTEX-001, ARTEX-002, ARTEX-003, ARTEX-007 and ARTEX-008 share a filesystem boundary. Agent run directories are writable by the common executor identity. A file left in `uploads/` can be changed or removed by an agent after the server acknowledges it. A path string or `os.Root` opened at a larger data directory cannot make an artifact immutable or prevent access by another process using the same executor identity. The current staging response also returns an absolute server path, and the web console appends that path to a task description. Archive and ask_operator evidence flows have separate staging and validation rules.

The partial ARTEX-003 change in `server/chatupload.go` reserves filenames with `O_EXCL` through a run-directory `os.Root`. It prevents the reproduced duplicate-name truncation and traversal out of that root during creation. Task and conversation message admission now reopens an attachment under that chat's `uploads/` root, rejects links and forged paths or metadata, and derives the size and SHA-256 from the opened file. The task/session upload response no longer includes an absolute server path; pre-task staging still requires one. This check does not make completed content immutable: an executor can alter its run directory after validation and before the agent reads the path. Legacy clients may omit the digest, and the server then hashes the current bytes without proving they are the original upload.

## Proposed direction

1. Keep a server-owned artifact store outside operator-browsable and executor-writable roots. Open it through descriptor-relative APIs. Reject links, special files and unexpected ownership; enforce per-file and aggregate quotas while streaming to random exclusive temporary names.
2. Finalize content only after the complete length, digest and cancellation state are checked. Store an immutable artifact identifier, digest, size, media type, campaign and origin in PostgreSQL. API responses use the identifier and display name, not a server path. A failed request removes only its own temporary object.
3. Provide campaign-scoped artifact delivery through a trusted broker. The broker checks the current campaign authorization and exposes read-only content to the corresponding sandbox. Explicitly shared artifacts require a separate operator-authorized grant. The agent's Bash and file tools must retain their documented ability to inspect authorized uploads without receiving access to the store itself.
4. Bind ask_operator evidence and archive inputs to finalized artifact identities where applicable. Display and approval read the recorded digest and provenance, not a mutable run-directory path.
5. Treat workspace upload replacement as a separate operation. It must preserve the current intentional replacement behavior through an atomic confined temporary-file-and-rename path, with explicit authorized roots.

## Dependencies and migration

Campaign-specific execution identities or sandboxes (ARTEX-001) and a brokered artifact path are prerequisites for strong cross-campaign confidentiality. The API, task description, attachment renderer and existing absolute-path staging workflow need a versioned migration. Existing `uploads/` files remain in place during migration; an explicit import process must verify their type, size, ownership and digest before assigning identifiers. Do not delete or rewrite them in place. Backup, restore and rollback must be tested against copies of operational data before any deployment.

## Acceptance evidence

Use two concurrent campaigns and sequential sandbox reuse. Test that a campaign cannot alter a finalized artifact, read another campaign's private artifact, or change content between approval and display. Test duplicate names, cancellation, quota exhaustion, malformed and linked files, archive/restore, renderer compatibility and legacy import. Treat any passing test of `os.Root` alone as confinement evidence, not as proof of campaign isolation or immutability.
