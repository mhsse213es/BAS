# Detection Validation — QRadar connector Implementation Plan

> TDD, task-by-task.

**Goal:** Add a QRadar `detectverify` connector (async Ariel search: submit → poll → fetch), reusing the `base_url`/`api_token` storage added for Splunk.

**Tech Stack:** Go, `internal/detectverify`, `internal/api`, QRadar Ariel REST API.

---

### Task 1: QRadar connector (TDD)

**Files:** Create `internal/detectverify/qradar.go`, `qradar_test.go`; Modify `connector.go`.

- [ ] Write `qradar_test.go`: httptest server routing on method+path — `POST /api/ariel/searches` returns `{"search_id":"s1","status":"WAIT"}`; `GET /api/ariel/searches/s1` returns `WAIT` on first call, `COMPLETED` on second (track call count); `GET /api/ariel/searches/s1/results` returns 2 events (one with `mitre_technique`, one without). Build connector with `baseURL` pointed at the server, `pollInterval` ~1ms. Assert `Verdict==Detected`, `Confidence==high`, 2 matched alerts. Add empty-results → `NotDetected`, search `status=="ERROR"` → error, and HTTP 4xx on submit → error cases.
- [ ] `qradar.go`: `qradarConnector{baseURL, secToken, httpClient, pollInterval, maxPolls}`, `newQRadarConnector(cfg)`, `Verify` (submitSearch → pollUntilDone → fetchResults → parseQRadarEvents → matchAlerts), `TestConnection` (`GET /api/system/about`), `buildQRadarAQL(req)`. Reuse `normalizedAlert`, `matchAlerts`, add `escapeAQL`.
- [ ] `connector.go` `NewConnector`: add `case "qradar": return newQRadarConnector(cfg), nil`.
- [ ] `go test ./internal/detectverify/...`.

### Task 2: API wiring

**Files:** `internal/api/detectverify_handlers.go`.

- [ ] Add `"qradar"` to `validProviders` in `CreateDetectionConnector` (and the error message).
- [ ] `go build ./...`; `go vet`; `go test ./internal/detectverify/...`.

### Task 3: Capture + commit

- [ ] Vault: Detection Validation note — tick QRadar; daily note.
- [ ] `gofmt` touched files; commit code + spec + plan; push.
