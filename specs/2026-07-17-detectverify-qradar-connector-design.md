# Detection Validation — QRadar connector (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Detection Validation (SP1 connectors) — third provider after Sentinel/Defender XDR, Splunk.

## Problem
QRadar reuses the generic `base_url`/`api_token` storage added for Splunk (no new columns), but its query API is fundamentally different: Sentinel/Splunk are synchronous (submit query, get rows back in one call). QRadar's Ariel API is **asynchronous** — submit an AQL search, poll until `COMPLETED`, then fetch results.

## Decision
`newQRadarConnector`, registered under provider key `"qradar"`, mirroring the `Connector` interface:
1. `POST /api/ariel/searches` with an AQL `query_expression` scoped to host + time window over the `events` table.
2. Poll `GET /api/ariel/searches/{id}` until `status` is `COMPLETED` or `ERROR`/`CANCELED`, sleeping `pollInterval` between checks (injectable, defaults 2s, tests override to ~1ms). Hard cap of `maxPolls` (30) to avoid an infinite loop on a stuck search.
3. `GET /api/ariel/searches/{id}/results` → parse `events[]` into `normalizedAlert`, then the shared `matchAlerts`.

Auth: `SEC: <api_token>` header (QRadar's convention — not `Authorization: Bearer`) + `Version: 20.0` + `Accept: application/json`. `cfg.BaseURL` is the console base URL; `cfg.APIToken` is the SEC token.

## Architecture
- `qradar.go` — `qradarConnector{baseURL, secToken, httpClient, pollInterval, maxPolls}`; `Verify` (submitSearch → pollUntilDone → fetchResults → parseQRadarEvents → matchAlerts); `TestConnection` (`GET /api/system/about`).
- `connector.go` — `NewConnector` `case "qradar"`.
- API `detectverify_handlers.go` — add `"qradar"` to `validProviders`.
- No DB changes — reuses `base_url`/`api_token` from the Splunk slice.

### QRadar field mapping (default `events` table)
`starttime` (epoch ms) → Timestamp; `QIDNAME(qid)` (aliased `rulename`) → RuleName; `magnitude` → Severity (as string); `sourceip`/`destinationip` scope the WHERE clause; `mitre_technique` (custom property, present only when QRadar Use Case Manager or an equivalent app tags it) → Techniques, absent → medium confidence via the existing `matchAlerts` fallback, same as Sentinel/Splunk when no technique tag exists. InvestigationURL → `<baseURL>/console/qradar/jsp/QRadar.jsp` (QRadar has no per-search deep link without an offense ID, so this points at the console root — an acceptable placeholder, consistent with "best effort" investigation links already used elsewhere).

## Testing (TDD)
- `qradar_test.go` — httptest server: POST search → `{"search_id":"s1","status":"WAIT"}`; first status poll → `WAIT`, second → `COMPLETED`; results → 2 rows (one `mitre_technique`-tagged, one not). Assert Detected + high confidence + 2 matched alerts. Empty results → NotDetected. `ERROR` status → connector returns an error, not a fabricated NotDetected. HTTP 4xx on submit → error.
- `connector_test.go` — `NewConnector("qradar")` now succeeds.

## Out of scope
UI form fields (already deferred from the Splunk slice, same story). CrowdStrike/Trellix (next slices, reuse `base_url`/`api_token` + `client_id`/`client_secret`).

## Capture
Detection Validation note (tick QRadar); daily note; no new ADR.
