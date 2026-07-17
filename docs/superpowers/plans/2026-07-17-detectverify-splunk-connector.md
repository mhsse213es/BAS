# Detection Validation — Splunk connector Implementation Plan

> TDD, task-by-task.

**Goal:** Add a Splunk `detectverify` connector end-to-end (generic credential storage + connector + API wiring), following the Sentinel pattern.

**Tech Stack:** Go, `internal/detectverify`, `internal/db`, `internal/api`, Splunk REST export API.

---

### Task 1: Generic credential columns

**Files:** `internal/db/postgres.go`, `internal/detectverify/connector.go`.

- [ ] `postgres.go`: add to the `detection_connectors` CREATE — `base_url text NOT NULL DEFAULT ''`, `api_token text NOT NULL DEFAULT ''`. Append idempotent `ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS base_url text NOT NULL DEFAULT '';` and same for `api_token`.
- [ ] `connector.go` `Config`: add `BaseURL string` and `APIToken string`.
- [ ] `go build ./internal/...`.

### Task 2: Splunk connector (TDD)

**Files:** Create `internal/detectverify/splunk.go`, `splunk_test.go`; Modify `connector.go`.

- [ ] Write `splunk_test.go`: httptest server serving 2 newline-delimited JSON rows (one with `annotations.mitre_attack` = the requested technique, one without); build connector with `exportURL` pointed at the server; assert `Verdict==Detected`, `Confidence==high`, 2 matched alerts. Add empty-results → `NotDetected` and HTTP 500 → error cases.
- [ ] `splunk.go`: `splunkConnector{exportURL, uiBase, token, httpClient}`, `newSplunkConnector(cfg)`, `Verify` (buildSplunkSearch → search → parseSplunkResults → matchAlerts), `TestConnection` (`| makeresults` search), `buildSplunkSearch(req)`, `parseSplunkResults(data, uiBase)`. Reuse `normalizedAlert`, `matchAlerts`, `escapeKQLString`-style escaping (add `escapeSplunk`).
- [ ] `connector.go` `NewConnector`: add `case "splunk": return newSplunkConnector(cfg), nil`.
- [ ] `go test ./internal/detectverify/...`.

### Task 3: API wiring

**Files:** `internal/api/detectverify_handlers.go`.

- [ ] Add `baseUrl`/`apiToken` to the list, create, update request/response structs and their SQL (INSERT columns, UPDATE set-list, list SELECT).
- [ ] **Critical:** the verify-path `SELECT` (~L187) that builds `detectverify.Config` must add `base_url, api_token` and scan into `cfg.BaseURL, cfg.APIToken` — else the Splunk connector runs with empty creds.
- [ ] Mirror the `client_secret` "***" preserve-on-update trick for `api_token` (don't echo/overwrite the token with a mask).
- [ ] `go build ./...`; `go vet`; `go test ./internal/detectverify/...`.

### Task 4: Capture + commit

- [ ] Vault: Detection Validation note — tick Splunk in Open Issues, bump last_updated; daily note.
- [ ] `gofmt` touched files; commit code + spec + plan; push.
