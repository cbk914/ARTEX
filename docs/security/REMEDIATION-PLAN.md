# ARTEX-Galactus security remediation plan

Baseline: `3cb06383fd99ffe7686abe1d375de11da7cfad54`. Work remains local until reviewed. Preserve data, keys, skills, authorized functions and existing isolation controls. Do not deploy or publish vulnerability details automatically.

1. **Batch A:** finish route, subprocess, filesystem, scope, credential, Docker and CI inventories. Obtain Go 1.26.11 and an isolated PostgreSQL database, then run baseline tests.
2. **Batch B:** validate ARTEX-002/003 with synthetic races. Consolidate descriptor-confined filesystem operations and migrate workspace and uploads.
3. **Batch C:** write an ADR for ARTEX-001/004/005. Specify campaign-scoped process, filesystem, HOME and network boundaries, broker interfaces, migration and rollback. A shared UID or parser-only gate is insufficient. Implement in reviewable increments.
4. **Batch D:** validate ARTEX-011 and address ARTEX-006/012. Preserve API bearer clients and browser streaming while removing browser token persistence and URL tokens.
5. **Batch E:** address ARTEX-007/008/009 through immutable evidence, bounded archive staging and explicit authorization provenance.
6. **Batch F:** bound ARTEX-010 resources, run dependency and SBOM checks, and provide ARTEX-013 Docker Desktop readiness without changing running volumes.
7. **Batch G:** run focused and full regression, race, frontend, dependency and Docker checks; review the final diff and document residual risks.

For each finding, record source-to-sink path and legitimate behavior, reproduce locally where feasible, fix the narrowest complete boundary, test an alternate bypass and normal control, and update `REGRESSION-MATRIX.md`. Do not mark a design limitation fixed through a partial mitigation.
