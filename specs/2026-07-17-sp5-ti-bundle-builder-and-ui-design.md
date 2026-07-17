# SP5 — TI bundle builder script + connector-tab bundle status (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Threat Intel Pipeline (SP5) — closes the two remaining open items from the layered-fetch work (`c95d2f5`).

## Problem
`connector.BundleSource.Fetch()` can *consume* a signed `ti-bundle.json`, but nothing produces one — the air-gapped delivery path is a dead end without operator tooling. Separately, `ConnectorStatus.BundleEnabled`/`BundleVersion` are already populated by the scheduler but never rendered in the Threat Intel settings tab (`wwwroot/index.html`).

## Decision

### 1. Bundle builder script — reuse, don't reinvent
`Bundle`'s own doc comment already states the intended workflow: "an operator builds it on an internet-connected box, signs it with the release key, and hand-carries it in." The build step should be a thin CLI over machinery that already exists from today's SP5 work:
- `connector.NewMISPClient` / `NewOpenCTIClient` already implement `Source.Fetch()` — the builder just instantiates whichever are configured (same env vars as the live scheduler: `MISP_URL`/`MISP_API_KEY`, `OPENCTI_URL`/`OPENCTI_API_KEY`, or CLI flags for a one-off run from an operator's machine).
- `mergeActors` (scheduler.go) already unions actor techniques across sources — export it (`MergeActors`) so the CLI can reuse it instead of duplicating merge logic.
- **Signing needs zero new code.** `scripts/signer.go sign <key> <file>` already signs *any* file with the same RSA-4096/SHA-256/PKCS1v15 scheme `integrity.VerifyScenarioFile` checks — it doesn't know or care that the file used to be a scenario YAML. The builder just has to produce `ti-bundle.json` in the right shape; the existing signer takes it from there.

New file: `orchestrator/scripts/ti-bundle-builder/main.go` (`package main`, its own subpackage — `signer.go` already owns `package main` directly under `scripts/`, so a second flat file there would collide on `func main`). Flags: `-misp-url`, `-misp-key`, `-opencti-url`, `-opencti-key`, `-sectors` (comma-separated), `-regions` (comma-separated, MISP only), `-version` (defaults to a UTC date stamp), `-out` (defaults to `ti-bundle.json`). Requires at least one source configured; fetch failures from an individual source are logged and skipped (mirrors the scheduler's per-source isolation), but zero total actors is a hard error — never write an empty bundle, that would silently blank out a client's air-gapped intel on next hand-carry.

Operator workflow (documented in the script's own `-h` output, not a new doc page):
```
go run ./scripts/ti-bundle-builder -misp-url=... -misp-key=... -version=2026.07.17
go run scripts/signer.go sign private_key.pem ti-bundle.json
# hand-carry ti-bundle.json + ti-bundle.json.sig into TI_BUNDLE_DIR on the client box
```

### 2. Connector-tab bundle status — pure UI
`GET /api/connector/status` already returns `bundleEnabled`/`bundleVersion` (`ConnectorStatus` struct, unchanged since `c95d2f5`) — no Go API change needed. Add a "Bundle" row next to the existing MISP/OpenCTI rows in `#connector-status-card` (`wwwroot/index.html` ~L1757), and populate it in `loadConnectorStatus()` (~L10953): `✓ Enabled (v<version>)` / `✗ Not configured`, same visual pattern as the MISP/OpenCTI rows.

## Testing
- `ti-bundle-builder_test.go` — can't hit real MISP/OpenCTI, so test the pieces that don't need one: `MergeActors` already has coverage (`scheduler_test.go`); add a test for the CLI's "zero actors is a hard error" guard and for JSON output shape (build a `Bundle` from fake `Source`s via a small `buildBundle(sources []connector.Source, version string) (connector.Bundle, error)` helper the `main()` wraps, so it's testable without a live network call).
- Manual verification: run the builder against nothing configured → expect the "no sources" error; run `signer.go sign` against the output → expect a valid `.sig`; point `TI_BUNDLE_DIR` at it and confirm `BundleSource.Fetch()` (already tested) accepts it.
- UI: no automated test (no JS test harness in this repo for `wwwroot`); manual browser check that the Bundle row renders after dropping a signed bundle in `TI_BUNDLE_DIR` and restarting.

## Out of scope
Where the bundle's actor data ultimately comes from long-term (live pull vs. curated ATT&CK snapshot) is already answered by reusing the existing MISP/OpenCTI sources — no separate curation pipeline needed for this slice. UI form fields for triggering a bundle build from the dashboard itself — this stays a build-host/operator CLI step, not a runtime feature, consistent with how scenario signing works today.
