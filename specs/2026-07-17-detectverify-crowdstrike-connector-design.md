# Detection Validation — CrowdStrike connector (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Detection Validation (SP1 connectors) — fourth provider after Sentinel/Defender XDR, Splunk, QRadar.

## Problem
CrowdStrike Falcon needs no new credential columns — it's OAuth2 client-credentials like Sentinel/Defender (`client_id`/`client_secret`), plus `base_url` for the regional API host (`api.crowdstrike.com` / `api.us-gov-crowdstrike.mil` / `api.eu-1.crowdstrike.com`), already added for Splunk/QRadar. Its query shape is a third pattern: **two-step ID-then-detail** — list matching alert IDs via a filter query, then fetch full alert objects for those IDs (Sentinel/Splunk return full rows in one call; QRadar polls a single search to completion).

## Decision
`newCrowdStrikeConnector`, registered under provider key `"crowdstrike"`:
1. **Auth** — `crowdstrikeTokenSource`, a client-credentials OAuth2 fetcher against `<base_url>/oauth2/token`, structurally identical to `entraTokenSource` (same cache-until-60s-left rule) but without an Entra-style `scope` parameter — CrowdStrike's token grants access to whatever scopes the API client was provisioned with.
2. **Query** — `GET /alerts/queries/alerts/v2?filter=<FQL>` scoped to `device.hostname` and `created_timestamp` window, returns `{resources: [id, ...]}`.
3. **Detail** — `POST /alerts/entities/alerts/v2` with `{"composite_ids": [...]}`, returns full alert objects including a `behaviors[]` array where each behavior already carries `technique_id` (an ATT&CK ID like `T1059.001`) — CrowdStrike tags this natively, so (unlike Sentinel/Splunk/QRadar) high-confidence matches don't depend on an optional custom field.
4. Parse into `normalizedAlert` (technique IDs pooled from every behavior on the alert), then the shared `matchAlerts`.

## Architecture
- `crowdstrike_auth.go` — `crowdstrikeTokenSource{clientID, clientSecret, tokenURL, httpClient, mu, cached, expiresAt}`; `newCrowdStrikeTokenSource(baseURL, clientID, clientSecret)`; `Token(ctx)`.
- `crowdstrike.go` — `crowdstrikeConnector{queryURL, detailURL, tokens, httpClient}`; `Verify` (buildFQLFilter → queryAlertIDs → fetchAlertDetails → parseCrowdStrikeAlerts → matchAlerts); `TestConnection` (`GET /alerts/queries/alerts/v2?limit=1`).
- `connector.go` — `NewConnector` `case "crowdstrike"`.
- API `detectverify_handlers.go` — add `"crowdstrike"` to `validProviders`.
- No DB changes.

### CrowdStrike field mapping (Alerts v2 entity)
`composite_id` → AlertID; `name` (fallback `display_name`) → RuleName; `created_timestamp` (RFC3339) → Timestamp; `severity` (int 1–100, stringified) → Severity; `behaviors[].technique_id` (deduped) → Techniques. InvestigationURL → `<base_url-mapped console>/activity-dashboard/detections/<composite_id>` — since the console host differs from the API host per region, this slice uses the API `base_url` itself as a best-effort link base (documented limitation, follow-up ticket like the QRadar placeholder).

## Testing (TDD)
- `crowdstrike_auth_test.go` — mirrors `entra_auth_test.go`: token fetch + 60s-cache-reuse.
- `crowdstrike_test.go` — httptest server: query endpoint returns `{"resources":["a1","a2"]}`; detail endpoint returns 2 alerts (one with a `T1059.001`-tagged behavior, one without). Assert Detected + high confidence + 2 matched alerts. Empty `resources` → NotDetected (short-circuits before calling detail). HTTP 4xx on query → error.
- `connector_test.go` — `NewConnector("crowdstrike")` now succeeds.

## Out of scope
UI form fields (same deferred story as Splunk/QRadar). Trellix (next slice, reuses this same client-credentials + base_url shape).

## Capture
Detection Validation note (tick CrowdStrike); daily note; no new ADR.
