# SP5 — TI bundle builder script + connector-tab bundle status Implementation Plan

> TDD, task-by-task.

**Goal:** Close the two remaining SP5 open items — an operator CLI to build+sign `ti-bundle.json`, and a Bundle row in the Threat Intel settings tab.

**Tech Stack:** Go (`orchestrator/scripts`, `internal/connector`), vanilla JS/HTML (`wwwroot/index.html`).

---

### Task 1: Export `mergeActors` for reuse

**Files:** `orchestrator/internal/connector/scheduler.go`.

- [ ] Rename `mergeActors` → `MergeActors` (exported) and its one call site in `sync()`.
- [ ] `go build ./internal/connector/...`.

### Task 2: Bundle builder core (TDD)

**Files:** Create `orchestrator/internal/connector/build_bundle.go`, `build_bundle_test.go`.

- [ ] Write `build_bundle_test.go`: a `fakeSource` (reuse the one already in `scheduler_test.go` if same package, else a local copy) with actors; assert `BuildBundle([]Source{...}, "v1")` returns a `Bundle` with `Version=="v1"`, `GeneratedAt` non-zero, and merged actors (reuse `MergeActors` semantics — two sources with an overlapping actor name union their techniques). Assert `BuildBundle(nil, "v1")` and `BuildBundle([]Source{emptySource}, "v1")` both return an error ("no actors" — never produce an empty bundle silently).
- [ ] `build_bundle.go`: `func BuildBundle(sources []Source, version string) (Bundle, error)` — iterate sources, `Fetch()` each (log-and-skip a source error to `log.Printf`, don't abort), collect actors, error if the total is zero, else `MergeActors` and return `Bundle{Version: version, GeneratedAt: time.Now().UTC(), Actors: merged}`.
- [ ] `go test ./internal/connector/...`.

### Task 3: CLI wrapper

**Files:** Create `orchestrator/scripts/ti-bundle-builder.go`.

- [ ] `package main` — flags `-misp-url`, `-misp-key`, `-opencti-url`, `-opencti-key`, `-sectors` (comma-split), `-regions` (comma-split), `-version` (default `time.Now().UTC().Format("2006.01.02")`), `-out` (default `ti-bundle.json`). Build `[]connector.Source` from whichever pair of flags is non-empty; error out ("no threat-intel source configured — set -misp-url/-misp-key or -opencti-url/-opencti-key") if neither is set. Call `connector.BuildBundle`, `json.MarshalIndent`, `os.WriteFile(out, data, 0644)`, print the actor/technique count and a reminder to run `signer.go sign`.
- [ ] Manual check: `go run scripts/ti-bundle-builder.go` (no flags) → confirm the "no source configured" error, no file written.
- [ ] `go build ./...` (confirms the new `package main` file compiles standalone; `go vet ./...`).

### Task 4: Connector-tab bundle status (UI)

**Files:** `orchestrator/wwwroot/index.html`.

- [ ] Add a "Bundle" row to `#connector-status-card` (~L1757), same markup pattern as the MISP/OpenCTI rows: `<span class="conn-cfg-label">Bundle</span><span id="cs-bundle" class="conn-cfg-val">—</span>`.
- [ ] In `loadConnectorStatus()` (~L10953), add: `document.getElementById('cs-bundle').textContent = s.bundleEnabled ? ('✓ Enabled (v' + (s.bundleVersion || '?') + ')') : '✗ Not configured';`
- [ ] Manual browser check: load the Settings → Threat Intel tab, confirm the Bundle row renders (✗ Not configured when `TI_BUNDLE_DIR` is empty, as it will be in dev).

### Task 5: Capture + commit

- [ ] Vault: Threat Intel Pipeline note — tick both open items; daily note.
- [ ] `gofmt` touched Go files; commit code + spec + plan; push.
