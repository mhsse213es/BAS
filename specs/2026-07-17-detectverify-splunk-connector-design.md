# Detection Validation — Splunk connector + generic credential storage (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Detection Validation (SP1 connectors) — continues the Sentinel/Defender XDR first slice.

## Problem
`detectverify` verifies whether a run's techniques were detected, via per-vendor `Connector`s dispatched by `NewConnector(cfg.Provider)`. Only `microsoft_sentinel` + `microsoft_defender` exist. The next-most-valuable providers (Splunk, QRadar, CrowdStrike, Trellix) are unbuilt. Two blockers:
1. The `Connector` framework is ready, but `detection_connectors` is **Azure-shaped** (tenant/client/secret/workspace) — non-Azure providers have nowhere to store a base URL + token.

## Decision
1. **Generic credential storage** — add `base_url` + `api_token` columns to `detection_connectors` (additive; `ALTER … ADD COLUMN IF NOT EXISTS` for existing DBs). Serves Splunk/QRadar (base+token) and CrowdStrike/Trellix (base + reuse client_id/secret). `Config` gains `BaseURL`, `APIToken`.
2. **Splunk connector** — `newSplunkConnector`, registered under provider key `"splunk"`, mirroring `sentinelConnector`: build an SPL search scoped to host+window over the ES `notable` index, POST to `<base>/services/search/jobs/export?output_mode=json` with `Authorization: Bearer <token>`, parse the newline-delimited JSON `result` rows into `normalizedAlert`, then the shared `matchAlerts`.

## Architecture
- `splunk.go` — `splunkConnector{exportURL, uiBase, token, httpClient}`; `Verify` + `TestConnection`; `buildSplunkSearch(req)`, `parseSplunkResults(data, uiBase)`. TLS `InsecureSkipVerify` (self-signed mgmt certs common on-prem, same as MISP).
- `connector.go` — `Config.BaseURL`/`APIToken`; `NewConnector` `case "splunk"`.
- DB — new columns in CREATE + ALTERs.
- API `detectverify_handlers.go` — load/store `base_url`/`api_token` in list/create/update and the verify-path `SELECT` that builds `Config` (mandatory, else empty creds).

### Splunk field mapping (ES `notable` defaults)
`_time` → Timestamp (epoch); `rule_title` \|\| `search_name` \|\| `source` → RuleName; `severity` → Severity; `event_id` \|\| `_cd` → AlertID; `annotations.mitre_attack` → Techniques (string or list). InvestigationURL → `<uiBase>/en-US/app/SplunkEnterpriseSecuritySuite/incident_review`.

## Testing (TDD)
- `splunk_test.go` — httptest export server returns 2 canned rows (one technique-tagged, one not); assert Detected + high confidence + matched alerts + latency; empty result → NotDetected; HTTP 4xx → error.
- `connector_test.go` — `NewConnector("splunk")` now succeeds.

## Out of scope
UI form fields for base_url/api_token (follow-up, like other connector UI); QRadar/CrowdStrike/Trellix connectors (reuse this storage in later slices). Splunk `notable`-index assumption is the same schema-coupling level as the existing Sentinel `SecurityAlert` assumption.

## Capture
Detection Validation note (tick Splunk); update Open Issues; daily note; no new ADR (follows ADR-established framework).
