# Detection Validation — CrowdStrike connector Implementation Plan

> TDD, task-by-task.

**Goal:** Add a CrowdStrike Falcon `detectverify` connector (OAuth2 client-credentials + two-step query-then-detail Alerts v2 API), reusing `client_id`/`client_secret`/`base_url` already in `Config`.

**Tech Stack:** Go, `internal/detectverify`, `internal/api`, CrowdStrike Falcon Alerts v2 API.

---

### Task 1: CrowdStrike auth (TDD)

**Files:** Create `internal/detectverify/crowdstrike_auth.go`, `crowdstrike_auth_test.go`.

- [ ] Write `crowdstrike_auth_test.go`: httptest token server returns `{"access_token":"tok","expires_in":1800}`; assert `Token()` returns `"tok"`; assert a second call within the cache window doesn't hit the server again (reuse the `entra_auth_test.go` pattern — a request counter).
- [ ] `crowdstrike_auth.go`: `crowdstrikeTokenSource{clientID, clientSecret, tokenURL, httpClient, mu, cached, expiresAt}`, `newCrowdStrikeTokenSource(baseURL, clientID, clientSecret)`, `Token(ctx)` — client-credentials POST to `tokenURL`, cache until 60s before expiry (mirror `entra_auth.go` exactly, no `scope` field).
- [ ] `go test ./internal/detectverify/... -run CrowdStrikeToken`.

### Task 2: CrowdStrike connector (TDD)

**Files:** Create `internal/detectverify/crowdstrike.go`, `crowdstrike_test.go`; Modify `connector.go`.

- [ ] Write `crowdstrike_test.go`: httptest server routing on path — `GET /alerts/queries/alerts/v2` returns `{"resources":["a1","a2"]}`; `POST /alerts/entities/alerts/v2` returns 2 alert objects (one with `behaviors:[{"technique_id":"T1059.001"}]`, one with empty `behaviors`). Assert `Verdict==Detected`, `Confidence==high`, 2 matched alerts. Add empty-`resources` → `NotDetected` (and assert the detail endpoint was never called) and HTTP 500 on query → error cases.
- [ ] `crowdstrike.go`: `crowdstrikeConnector{queryURL, detailURL, tokens, httpClient}`, `newCrowdStrikeConnector(cfg)`, `Verify` (buildFQLFilter → queryAlertIDs → fetchAlertDetails → parseCrowdStrikeAlerts → matchAlerts), `TestConnection` (`GET .../alerts/v2?limit=1`), `buildFQLFilter(req)`, `escapeFQL`.
- [ ] `connector.go` `NewConnector`: add `case "crowdstrike": return newCrowdStrikeConnector(cfg), nil`.
- [ ] `go test ./internal/detectverify/...`.

### Task 3: API wiring

**Files:** `internal/api/detectverify_handlers.go`.

- [ ] Add `"crowdstrike"` to `validProviders` (and the error message).
- [ ] `go build ./...`; `go vet`; `go test ./internal/detectverify/...`.

### Task 4: Capture + commit

- [ ] Vault: Detection Validation note — tick CrowdStrike; daily note.
- [ ] `gofmt` touched files; commit code + spec + plan; push.
