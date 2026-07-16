# SP5 — Layered Threat-Intel Fetch (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Threat Intel Pipeline (SP5) — unblocks the `blocked` module.

## Problem
The threat-intel connector (`internal/connector`) is **live-only**: it polls MISP + OpenCTI over HTTP, normalises `ThreatActor` profiles, and generates `scenarios/intel/*.yaml`. Audspect deployments are on-prem / air-gapped by norm, so a design that *requires* internet strands most clients. SP5 was blocked on the fetch model.

## Decision
**Layered fetch** (approved): a **signed air-gapped bundle** is the floor; **live MISP/OpenCTI** overlay when a client has egress. Bundle-only when no live sources are configured → pure air-gap.

## Architecture
Additive; mirrors the proven OpenAEV `ContentProvider` pattern (REST + Bundle → one pipeline).

- **`Source` interface** (`connector/source.go`): `Fetch() ([]ThreatActor, error)` + `Name() string`. `MISPClient` and `OpenCTIClient` already have `Fetch()` → add a one-line `Name()`.
- **`BundleSource`** (`connector/bundle.go`): reads a signed `ti-bundle.json` from a hand-carried dir, verifies it, parses to `[]ThreatActor`.
- **`Scheduler` refactor**: replace the hardcoded `misp`/`opencti` fields with `sources []Source`; `sync()` iterates. `mergeActors()` already unions techniques by actor name → bundle (floor) + live (overlay) compose for free. `Generator` and YAML output are untouched.

### Bundle format & trust
```json
{ "version": "2026-07-17", "generated_at": "...", "actors": [ { ThreatActor… } ] }
```
- Operator builds `ti-bundle.json` on an internet box and signs it with the **existing RSA-4096 release key** (same `.sig` convention as scenario signing).
- `BundleSource` verifies via **`integrity.VerifyScenarioFile(path)`** — no new crypto. Tampered/unsigned → rejected in signed builds; skipped in dev builds (placeholder key), consistent with `Integrity & Tamper Detection`.
- Verifier is **injected** (`verify func(path) error`) so unit tests don't need the private key; production passes `integrity.VerifyScenarioFile`.
- Dropped in `/intel-bundles` (read-only mount, like `art-payloads`).

### Garble note
`ThreatActor` + `TechniqueRef` get explicit **json tags** — without them the garble build renames fields and bundle JSON keys break (same reflection failure as ADR-004).

### Layering precedence
Union of techniques (existing `mergeActors`). On scalar conflicts (description/confidence) live overlays bundle (fresher). Live sources stay optional.

## Config / API / UI
- `TI_BUNDLE_DIR` env (+ compose `./intel-bundles:/intel-bundles:ro`).
- `ConnectorStatus` gains `bundleEnabled` / `bundleVersion`; existing connector tab renders them (no new UI plumbing).

## Testing (TDD)
- `BundleSource`: valid parse, injected-verify failure → rejected, missing file → graceful, malformed JSON → error.
- `Scheduler`: multi-source merge via a fake `Source`; empty sources → idle.

## Out of scope
Bundle-builder tooling (operator-side script) and new scenario-generation logic — the existing `Generator` is reused as-is.

## Capture (by-product)
Threat Intel feature note → `in-progress`; new ADR "TI layered fetch (bundle + live overlay)"; daily note.
