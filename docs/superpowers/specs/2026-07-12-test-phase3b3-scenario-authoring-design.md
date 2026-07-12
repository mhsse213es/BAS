# Phase 3b.3 — Scenario Authoring: Test Design

**Status:** approved for planning
**Depends on:** Phase 3b.1 (Run Dispatch, done), Phase 3b.2 (Result Ingestion, done)
**Scope of Phase 3b overall:** Scenario & Run Lifecycle. This is the final sub-phase.

## Goal

Lock down correctness of scenario **authoring and persistence**: CRUD, YAML validation,
upload/import, clone behavior, delete semantics, engine file persistence, ID/path safety,
serialization round-trips, and malformed-input handling. Unlike 3b.1/3b.2, this phase is not
about security or run-state machines — it's about "does the file on disk match what the UI
sent, and does the engine's in-memory map stay consistent with disk."

## In scope

**Primary — 7 `internal/api` authoring handlers**, tested integration-style (`httptest`,
real `*Handler`, real file-backed `scenario.Engine` over `t.TempDir()`, real Postgres pool
from `sharedDB` — the pool is required because `auditLog` fires an async `INSERT` goroutine
on a real `h.db`; per 3b.2 precedent we never assert on audit rows, we just avoid a nil-pool
panic):

- `ListScenarios` (handlers.go:794)
- `GetScenario` (handlers.go:799)
- `CreateScenario` (handlers.go:1271)
- `UpdateScenario` (handlers.go:1292)
- `CloneScenario` (handlers.go:1320)
- `UploadScenario` (handlers.go:1365)
- `DeleteScenario` (handlers.go:1391)

**Secondary — targeted `internal/scenario` engine gaps** not already covered by the existing
`engine_test.go` (`TestSaveAndDelete`, `TestValidate`):

- `idPattern` path-traversal / slug-safety rejection (`Validate`)
- YAML round-trip fidelity of loss-prone fields via `Save` → reload
- Source classification on `Load` (`sourceForPath`: custom/intel/builtin) including the
  unsigned-builtin refusal path (`integrity.VerifyScenarioFile` failure → skipped, not loaded)
- `Delete`'s disk re-scan-by-ID behavior (already partly covered by `TestSaveAndDelete`;
  extend to the intel case and to confirming the file is gone, not just the map entry)

## Out of scope

- Async `auditLog` goroutine correctness (never polled/asserted — same rule as 3b.2's async
  fan-outs).
- Router-level RBAC / role middleware (Analyst+Admin gating happens in the router, not the
  handler; not exercised here).
- Re-testing the existing `Validate()` matrix in `engine_test.go` — reused as-is via the
  handlers that call it, not re-enumerated.
- `Load()`'s directory-walk error handling for unreadable files/dirs (OS-fault branch,
  consistent with the "don't chase DB/IO-fault branches" rule from earlier phases).

## Test matrices

### 1. `ListScenarios`

| Case | Setup | Assertion |
|---|---|---|
| Empty engine | no scenarios loaded | `200`, `[]` |
| Deterministic ordering | seed custom scenarios with IDs `zzz`, `aaa`, `mmm` | response array is ascending by `id` (matches `engine.List()`'s `sort.Slice` on ID) |
| Source classification | one builtin-dir file, one `custom/` file, one `intel/` file, loaded via `engine.Load()` | each entry's `source` field is `"builtin"`, `"custom"`, `"intel"` respectively |
| Key metadata present | seeded scenario with name/description/tags/mitrePhases | those fields present and correct in the JSON list (catches accidental field omission in `respond`) |

### 2. `GetScenario`

| Case | Assertion |
|---|---|
| Found | `200`, full scenario JSON |
| Not found | `404` |

### 3. `CreateScenario`

| Case | Body | Assertion |
|---|---|---|
| Valid | well-formed scenario JSON, novel ID | `201`, `source="custom"` in response, file exists at `custom/<id>.yaml` |
| Duplicate ID | ID already loaded (any source) | `409`, no file written/overwritten |
| Malformed JSON | truncated/invalid JSON body | `400` |
| Fails `Validate()` | bad ID pattern, empty name, or no execution mode | `422`, no file written |

### 4. `UpdateScenario`

| Case | Assertion |
|---|---|
| Not found | `404` |
| `source != "custom"` (intel-sourced target, the sole guard-test vehicle — see the note under DeleteScenario) | `400`, original file on disk byte-unchanged, in-memory scenario unchanged |
| URL ID authoritative | body carries a different `id` than the URL; saved/returned scenario uses the URL ID |
| Valid update | `200`, file on disk reflects new content, `Get(id)` returns updated data |
| Fails `Validate()` after edit | `422`, original file/memory unchanged (Save validates before writing) |

### 5. `CloneScenario`

Clone is tested against its **documented public contract only** — see Finding below for the
shallow-copy aliasing hazard that is deliberately *not* asserted as required behavior.

| Case | Assertion |
|---|---|
| Clone an intel-sourced scenario, no body (intel is the vehicle — same reasoning as the source-guard note under DeleteScenario; cloning a custom scenario is also covered as a baseline case) | `201`; new ID is `"<id>-copy"`; `name` is `"<original name> (copy)"`; `source="custom"`; `Source`/`IntelSource*` all stripped/zeroed (`IntelGeneratedAt.IsZero()`); original scenario (`Get(id)`) unchanged; new file exists at `custom/<newId>.yaml` |
| Clone a custom scenario, no body | same assertions as above, minus the intel-field stripping (there were none to strip) — confirms clone works for the common case too |
| Clone with explicit `newId`/`name` in body | response uses supplied values instead of defaults |
| Clone ID collision | `newId` already exists (or default `<id>-copy` already exists) | `409`, no file written |
| Clone of nonexistent source | `404` |
| Independence of the *documented* fields | mutate a scalar field (e.g. `Name`) on the clone post-response via a follow-up `UpdateScenario`; confirm original is unaffected (this exercises the real API path, not direct struct mutation) |

**Finding (documented, not asserted as contract):** `CloneScenario` does `clone := *src`
(handlers.go:1333), a shallow copy. Slice-typed fields (`Steps`, `Tags`, `MITREPhases`,
`SupportedOS`, `CalderaAbilities`, `ARTTechniques`) share backing arrays with the source
until the clone is independently re-saved with new slice values. This is latent — nothing in
the current handler mutates those slices in place — but it means a future code path that did
an in-place slice mutation (e.g. `append` within capacity, or `clone.Tags[0] = ...`) could
corrupt the source scenario in memory. Per user decision, this is recorded as a finding in
the phase summary, not encoded as expected behavior in a test (we will not assert "mutating
`clone.Tags` mutates `original.Tags`" — that would make the hazard a spec requirement instead
of a bug to fix later).

### 6. `UploadScenario`

The 1 MiB `io.LimitReader` cap and the fact that `ParseYAML` folds both YAML-syntax errors
and `Validate()` errors into the same `"invalid YAML: " + err.Error()` / `422` response (they
are **not** distinguished at the HTTP layer — handlers.go:1371-1374) are both load-bearing
facts for this matrix.

| Case | Body | Assertion |
|---|---|---|
| Valid YAML | well-formed scenario YAML | `201`, file written to `custom/<id>.yaml`, `source="custom"` |
| Syntactically invalid YAML | unparseable YAML (bad indentation/tab) | `422`, message contains `"invalid YAML"`, no file written |
| Valid YAML, fails schema validation | parses but bad ID / no name / no execution mode | `422`, same error-prefix shape as the syntax-error case (documents that callers cannot distinguish parse vs. validation failure from status/message shape alone) |
| Empty body | zero-length upload | `422` (empty YAML unmarshals to a zero-value `Scenario`, which fails `Validate()` on empty ID/name) |
| Missing required fields only | YAML with `id`/`name` but no steps/local_check/ART/Caldera mode | `422`, error mentions "no execution mode" |
| Duplicate ID | valid YAML, ID already loaded | `409`, no file written/overwritten |
| Oversized body | body > 1 MiB | request is truncated by `io.LimitReader` before parsing; assert the truncated bytes fail YAML parsing → `422` (documents actual behavior: there is no explicit "too large" error, just a truncated-then-rejected parse) |

### 7. `DeleteScenario`

| Case | Assertion |
|---|---|
| Not found | `404` |
| `source != "custom"` (intel) | `400`, `engine.Get(id)` still returns it, file still on disk — confirms the API-layer guard is stricter than `engine.Delete` (which permits deleting intel; only the API restricts intel deletion to a different route per the handler comment) |
| Valid delete of custom scenario | `204`; `engine.Get(id)` → not found; file removed from `custom/`; a subsequent `ListScenarios` no longer includes it |

Note: the guard is a single `if existing.Source != "custom"` branch shared by every
non-custom source. `intel` is the sole vehicle for exercising it (see the source-guard note
below) — a second case with `source="builtin"` would hit the identical branch and isn't
worth the cost of constructing a genuinely-signed builtin fixture (the real RSA private key
that pairs with the compiled-in `ScenarioPublicKeyPEM` is not available to tests or CI; it's
an operator-held signing key used only by `scripts/signer.go` at release-build time).

### 8. Engine-level additions (`internal/scenario/engine_test.go`)

| Test | Assertion |
|---|---|
| `TestValidate_IDPathTraversal` | IDs like `"../evil"`, `"a/b"`, `"CON"`-with-uppercase, `""`, and a 65-char string all fail `idPattern`; a valid 2-63-char lowercase-alnum-hyphen ID passes |
| `TestSave_RoundTripFidelity` | Save a scenario populated with `LivePolicy` (all fields non-zero), a `Step` with `RequiresPriv` in each of the three YAML forms (scalar `admin`, `{minimum: user}`, `{minimum: user, preferred: admin}`), `SupportedOS`, `Executable: true`, `Tags`, `MITREPhases`. Reload via a fresh `Engine.Load()`. Assert every field is value-equal after reload — noting `PrivSpec` has no custom YAML marshaler, so a scalar `admin` on the way in comes back out as the equivalent `{minimum: admin}` mapping on disk; assert on the parsed **value** (`Effective() == "admin"`), not on disk byte-format |
| `TestLoad_SourceClassification` | three files under builtin-root, `custom/`, `intel/` respectively; `Load()` classifies each correctly via `sourceForPath` |
| `TestLoad_UnsignedBuiltinRefused` | a scenario file placed directly under the engine root (builtin path) with no valid signature; `Load()` logs and skips it — `Get(id)` returns `false`, `Count()` excludes it |
| `TestDelete_IntelRescan` | intel-sourced scenario (loaded from `intel/<id>.yaml`); `engine.Delete(id)` succeeds (engine-level delete permits intel — only the API layer restricts this), file removed from disk, map entry gone |

## File structure

- **Create:** `orchestrator/internal/api/scenario_authoring_test.go` — `ListScenarios`,
  `GetScenario`, `CreateScenario`, `UpdateScenario`, `UploadScenario` tests; shared helpers
  `newFileEngine(t) *scenario.Engine` (temp-dir engine, `Load()`'d once empty) and
  `seedCustomScenario(t, engine, sc *scenario.Scenario)` (direct `engine.Save` for setup,
  bypassing HTTP where the test isn't about the Create/Upload path itself).
- **Create:** `orchestrator/internal/api/scenario_clone_test.go` — `CloneScenario` matrix,
  including the documented finding as a code comment (not an assertion).
- **Create:** `orchestrator/internal/api/scenario_source_guard_test.go` — dedicated
  source-guard matrix shared by `UpdateScenario`/`DeleteScenario`, using
  `seedIntelScenario(t, dir, sc)` (writes a YAML file directly under `<dir>/intel/` before
  `Load()`) as the sole non-custom vehicle (see note above — no builtin fixture, since that
  would require the offline release-signing private key). Every rejection case re-reads the
  file from disk after the HTTP call and asserts byte-for-byte equality with its pre-call
  content, plus confirms `engine.Get(id)` in memory is unchanged.
- **Modify:** `orchestrator/internal/scenario/engine_test.go` — append the 5 engine-level
  tests from the table above.

## Helpers reused from existing test files (no duplication)

- `withURLParam(r, key, val) *http.Request` — already defined in `event_handlers_test.go`,
  package-visible; reused for `{id}` route params on Get/Update/Clone/Delete.
- `sharedDB.RunWithPool` — existing harness entry point.
- `New(pool, ws.NewHub(), engine, "")` — existing `Handler` constructor; the WS hub and the
  agent-secret argument are irrelevant to these handlers (no WS traffic, no MAC) but are
  required positionally.

## Definition of done

- All 7 handlers plus the 5 engine tests pass, `-count=10` targeted stress run clean.
- Coverage review confirms every branch in the 7 handlers is hit except the async `auditLog`
  goroutine body (out of scope by design) and the `os`-level I/O failure paths in `Save`/
  `Delete`/`Load` (out of scope, consistent with prior phases).
- The `CloneScenario` shallow-copy aliasing hazard is written up as a finding in the phase
  summary and in a source comment near the test, not encoded as a passing assertion.
- Memory (`project_test_generation_phase0.md`, `MEMORY.md`) updated marking 3b.3 done and
  Phase 3b (Scenario & Run Lifecycle) complete.
