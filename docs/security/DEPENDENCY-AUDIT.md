# Dependency audit (2026-11-27)

This is a source and lockfile review of the local `codex/security-remediation` branch. It is not an assessment of the running image, the host, or a deployed revision.

## Scope and method

| Input | Tool | Result |
| --- | --- | --- |
| Go packages reachable from `./...` | `govulncheck -json ./...` v1.10.0, Go 1.26.11 | No vulnerabilities found in the call analysis. This does not prove that every dependency path is safe. |
| `web/package-lock.json`, production dependencies | `npm audit --omit=dev --json`, npm 11.19.0 | 0 reported vulnerabilities. |
| `web/package-lock.json`, all dependencies | `npm audit --json`, npm 11.19.0 | 19 affected development packages before the compatible lockfile refresh (1 critical, 11 high, 7 moderate); 0 after it. |
| `skills/api-recon/scripts/package-lock.json`, production dependencies | `npm audit --omit=dev --json`, npm 11.19.0 | 10 high affected packages before the Puppeteer upgrade; 0 after it. |
| Source manifests and lockfiles | Trivy 0.76.2, CycloneDX 1.7 | [Source SBOM](sbom/source-2026-11-27.cdx.json): 472 components, 0 vulnerability records after the Puppeteer update. It covers Go and both npm lockfiles; it is not an image or OS package SBOM. Trivy's default run suppresses development and test dependency vulnerabilities. |

OSV Scanner 2.7.0 independently reported affected packages in the web lockfile. Its standalone `go.mod` result contained no source package inventory, so it was not counted as Go coverage. The Go conclusion above comes from `govulncheck`.

## Go static analysis

`staticcheck` 2026.2.2 and `gosec` v2.30.0 ran on `./...` with Go 1.26.11 in a disposable container. Staticcheck returned 26 diagnostics, mainly error-string style, deprecated APIs and test-only issues. Gosec returned 348 candidates: 33 high, 121 medium and 194 low. Scanner severity is a triage priority, not proof of exploitability.

The high candidates include nine integer conversions (`G115`), three intentional or configurable TLS verification bypasses (`G402`), one template parse (`G708`), nine path operations (`G703`), six walk/path races (`G122`), two process exec paths (`G702`), and three other candidates. The `G703` and `G122` groups overlap the known filesystem and archive isolation work. The MCP client exposes an explicit `insecure` option and the enrichment client deliberately accepts target certificates during interception; their credential and network policy implications still require review. The template parser uses `text/template` and validates field names, but that observation alone does not close its resource or policy risks. No candidate has been dismissed solely because the code contains a guard. Keep these findings open for source-to-sink triage and targeted tests.

## Api-recon remediation

`api-recon` is a separate, optional Node runtime. Its `runtime_harvest.js` uses `puppeteer-core` to launch a system Chromium and automate an authorized local browser session. The old lockfile resolved Puppeteer 23 and vulnerable transitive packages. The direct dependency and lockfile now resolve Puppeteer 25.19.0. The new package requires Node 22.12 or newer.

Validation: `npm ci --ignore-scripts` in a temporary directory completed; `npm audit --omit=dev` reported zero vulnerabilities; the actual harvester ran with local Chrome against a loopback HTTP fixture, navigated and captured an `/api/check` request. This is a smoke test, not a complete compatibility test with a real target or the deployed container. Re-run the harvester with an approved test target before deployment.

## Web lockfile remediation

`npm audit fix --package-lock-only --ignore-scripts` refreshed compatible transitive versions without changing `web/package.json`. Both the production and full npm audits then reported zero vulnerabilities. In a disposable local copy, `npm ci --ignore-scripts`, `tsc --noEmit`, and `next build` passed. The polling, replay, tamper-hook, upload, traffic-stream, i18n and bash regression scripts passed. The i18n check initially found the ARTEX-Galactus title and logout-error keys missing from two catalogs; those keys were added with English values and the check passed. Translation of the new keys remains editorial work.

## Remaining work

- Exercise a deployed browser against the updated frontend before release; the local build and script tests do not validate the TLS proxy, cookie migration or live sessions.
- Triage the Go static-analysis candidates against source-to-sink paths and add targeted reproductions for actionable cases.
- Build the intended image and scan that exact image for OS and language packages; generate an image SBOM and record the image digest. The source SBOM does not cover the image.
- Re-run all dependency checks at release time. Advisory databases and registry resolutions change.
