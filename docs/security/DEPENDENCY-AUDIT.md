# Dependency audit (2026-11-27)

This is a source and lockfile review of the local `codex/security-remediation` branch. It is not an assessment of the running image, the host, or a deployed revision.

## Scope and method

| Input | Tool | Result |
| --- | --- | --- |
| Go packages reachable from `./...` | `govulncheck -json ./...` v1.10.0, Go 1.26.11 | No vulnerabilities found in the call analysis. This does not prove that every dependency path is safe. |
| `web/package-lock.json`, production dependencies | `npm audit --omit=dev --json`, npm 11.19.0 | 0 reported vulnerabilities. |
| `web/package-lock.json`, all dependencies | `npm audit --json`, npm 11.19.0 | 19 affected packages: 1 critical, 11 high, 7 moderate. These are development dependencies; production reachability was not demonstrated. |
| `skills/api-recon/scripts/package-lock.json`, production dependencies | `npm audit --omit=dev --json`, npm 11.19.0 | 10 high affected packages before the Puppeteer upgrade; 0 after it. |
| Source manifests and lockfiles | Trivy 0.76.2, CycloneDX 1.7 | [Source SBOM](sbom/source-2026-11-27.cdx.json): 472 components, 0 vulnerability records after the Puppeteer update. It covers Go and both npm lockfiles; it is not an image or OS package SBOM. Trivy's default run suppresses development and test dependency vulnerabilities. |

OSV Scanner 2.7.0 independently reported affected packages in the web lockfile. Its standalone `go.mod` result contained no source package inventory, so it was not counted as Go coverage. The Go conclusion above comes from `govulncheck`.

## Api-recon remediation

`api-recon` is a separate, optional Node runtime. Its `runtime_harvest.js` uses `puppeteer-core` to launch a system Chromium and automate an authorized local browser session. The old lockfile resolved Puppeteer 23 and vulnerable transitive packages. The direct dependency and lockfile now resolve Puppeteer 25.19.0. The new package requires Node 22.12 or newer.

Validation: `npm ci --ignore-scripts` in a temporary directory completed; `npm audit --omit=dev` reported zero vulnerabilities; the actual harvester ran with local Chrome against a loopback HTTP fixture, navigated and captured an `/api/check` request. This is a smoke test, not a complete compatibility test with a real target or the deployed container. Re-run the harvester with an approved test target before deployment.

## Remaining work

- Triage the web development dependency advisories by build-time reachability and update them with frontend build and UI regression checks. They are not counted as production runtime findings solely from their severity labels.
- Run `gosec` and `staticcheck` on the pinned Go toolchain, and review their findings against code paths.
- Build the intended image and scan that exact image for OS and language packages; generate an image SBOM and record the image digest. The source SBOM does not cover the image.
- Re-run all dependency checks at release time. Advisory databases and registry resolutions change.
