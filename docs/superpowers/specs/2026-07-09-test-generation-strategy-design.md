# Test Generation Strategy — Design

**Status:** Approved (2026-07-09). Phase 0 implementing now; Phases 1-5 each get their own
spec+plan cycle when picked up.

## Problem

`orchestrator` has 43,197 lines of source and 4,349 lines of test (~10%). Ten packages have
**zero** tests, including security- and correctness-critical ones: `verification`,
`relationships`, `siem`, `ticketing`, `connector`, `exercise`, `integrity`, `ws`, `license`,
`static`. `api` (12,247 LOC — routing, RBAC, handlers) is the single largest package and is
2.5% tested. No DB-integration test infrastructure exists anywhere; every existing test is a
pure-function test with no live database. No CI pipeline exists.

## Goal

**Regression safety, not a test-count target.** Success is measured by defect detection and
confidence in the highest-risk code paths, not by a number. Volume follows naturally from
applying the right technique to each package: generated matrices (RBAC × endpoint × method,
scoring permutations, malformed-payload fuzzing) legitimately produce thousands of concrete
cases where the underlying logic has that much combinatorial surface — but padding low-risk
packages to hit a count is explicitly out of scope.

## Scope Boundary

This spec covers **Phase 0 only**: the shared test infrastructure every later phase depends
on. Phases 1-5 (package-by-package rollout) are outlined here for sequencing and coverage
targets, but each gets its own brainstorming → spec → plan cycle before implementation,
per the project's standing decomposition convention (see `project_platform_roadmap_2026h2`
for the precedent — large initiatives are sequenced, not speced all at once).

## Architecture — Phase 0: Test Infrastructure Foundation

### `internal/testutil` — Postgres harness

```go
type TestDB struct {
    Pool      *pgxpool.Pool
    Container testcontainers.Container
    Cleanup   func()
}

func NewTestDB(t *testing.T) *TestDB
func (db *TestDB) RunInTx(t *testing.T, fn func(pgx.Tx))
func (db *TestDB) RunWithPool(t *testing.T, fn func(*pgxpool.Pool))
```

- `NewTestDB` starts a `postgres:16-alpine` container (matches production —
  `packaging/compose/docker-compose.yml`), runs `db.EnsureSchema` + `db.EnsureContentSchema`
  against it, returns a ready harness. Registers `t.Cleanup` to terminate the container.
- **One container per package** (`TestMain`), not per-test — keeps the suite fast.
- **`RunInTx`** wraps the test body in a transaction that's rolled back after — the default
  isolation mode for most repository tests.
- **`RunWithPool`** is the escape hatch for code that manages its own transactions
  internally and can't accept an injected `pgx.Tx` — falls back to `TRUNCATE`-between-tests
  isolation, used only where `RunInTx` doesn't fit.
- No build tag gating integration tests behind `-tags=integration`. Docker is confirmed
  available on the Windows build host and will be available in CI (GitHub-hosted
  `ubuntu-latest` runners ship Docker preinstalled). If the suite's wall-clock time later
  becomes a problem, splitting via build tags is a cheap follow-up — not solved
  speculatively now.

### Fixtures — builders, not files

```go
testutil.NewExercise().WithTechnique(t1110).WithAgent(a1).WithStatus("Running").Build(t, pool)
```

Composable Go builder functions with sensible defaults, overridden via chained `With*`
calls. No golden YAML/JSON fixture files for entity setup — those go stale silently and
don't show up in code review diffs the way builder call-sites do.

### Determinism helpers

```go
testutil.Clock(t, fixed time.Time) func() time.Time   // frozen, advanceable via clock.Advance(d)
testutil.UUIDGenerator(t, seed int64) func() string    // sequential/seeded, not uuid.New()
testutil.RandSource(t, seed int64) *rand.Rand
```

These are only usable where production code accepts an injected time/uuid/rand source
rather than calling `time.Now()` / a global UUID func directly. Where a package under test
doesn't yet have that seam, adding one is a small, explicitly-called-out step in that
package's own phase — never a silent drive-by refactor bundled into an unrelated test PR.

### Mocks — `internal/testutil/mocks`

Centralized mocks for external systems, built against real interfaces:
`MockSIEM`, `MockTicketing`, `MockConnector`, `MockAgent`, `MockNotifier`, `MockStorage`.

**Confirmed by inspection:** `siem`, `ticketing`, and `connector` currently expose concrete
structs with no interface — there is nothing to mock yet. Phase 0 scaffolds the `mocks`
package directory with a doc comment only. Extracting the minimal interface each concrete
type needs (e.g. `siem.Provider`) and writing the real mock happens in **Phase 4**, as part
of that package's own spec, not bundled into Phase 0.

### Extension points (structure only)

`testutil/bench.go`, `testutil/fuzz.go`, `testutil/property.go`, `testutil/concurrency.go` —
doc-comment stubs naming their future purpose (Phase 5 cross-cutting work), no speculative
implementation. This is the one part of Phase 0 with a real risk of turning into premature
scaffolding; kept deliberately to empty stubs to avoid that.

### Golden regression tests

New `testdata/golden/` convention per package (e.g. `internal/reporting/testdata/golden/`)
for customer-facing output: JSON API responses, score calculations, report HTML, CSV/XLSX
exports, evidence serialization. A `-update` flag idiom regenerates golden files
(`go test ./... -run TestGolden -update`). JSON compared structurally (parse + deep-equal,
tolerant of key ordering); text formats compared literally. When these outputs change,
the PR diff shows exactly what changed for a reviewer — catching accidental regressions
that isolated unit tests miss.

### Coverage

Three outputs per run, all local artifacts (no third-party SaaS — this is an
on-prem/air-gapped-conscious product):
- `coverage.out` — raw profile
- `coverage.html` — `go tool cover -html`
- Package-level summary table (`go tool cover -func`, reformatted), e.g.:
  ```
  api ............. 92%
  verification .... 98%
  relationships ... 97%
  exercise ........ 91%
  ```
  Package-level visibility is more actionable than a single global percentage.

### CI — `.github/workflows/test.yml`

```
checkout → setup-go 1.26 → gofmt -l (fail if non-empty) → go vet ./... →
staticcheck ./... → go build ./... (CGO_ENABLED=0) →
go test ./... -race -coverprofile=coverage.out →
coverage summary + HTML artifact upload
```

Runs on push + PR to `main`. `staticcheck` (`honnef.co/go/tools`) is a new dev dependency.
Docker is preinstalled on `ubuntu-latest`; no services block needed for testcontainers.

## Phased Rollout (sequencing reference — each phase specs separately when started)

| Phase | Packages | Target Coverage | Technique | Why this order |
|---|---|---|---|---|
| 1 | `verification`, `relationships` | 95-98% | State machines, lifecycle transitions, unique-constraint conflicts, confidence calculations, concurrent updates | Small, clean state machines — proves the `testutil` harness before tackling `api`'s size |
| 2 | `exercise` | 90%+ | Workflow orchestration, execution state, cancellation, retries, concurrency, transactional behavior | Introduces concurrency patterns Phase 3/4 will reuse |
| 3 | `api` | 90%+ | RBAC matrix (roles × endpoints × methods), auth, request validation, handler behavior, middleware, error paths | Repositories already validated by Phases 1-2, so `api` tests focus on HTTP/RBAC behavior, not re-deriving DB correctness |
| 4 | `integrity`, `scoring` (in `models`/`reporting`), `siem`, `connector`, `ticketing` | 85-95% (integrity/scoring 95%+) | Per-package: integrity = cryptographic/tamper tests; scoring = property + table-driven math; siem = parser/normalization; connector/ticketing = interface extraction + mocked external calls + retry/timeout | Each needs a distinct technique; integrity/scoring get the highest bar since they're correctness-critical outputs |
| 5 | Cross-cutting | — | Fuzz testing (UUIDs, JSON/YAML payloads, SQL filter strings, search queries), race testing, property-based testing, concurrency/stress, migration compatibility, benchmarks, golden-file coverage expansion | Needs the patterns from Phases 1-4 already in place to build on |

Coverage targets are directional, not hard CI gates in Phase 0 — a per-package gate can be
added once a package's phase lands and its real achievable ceiling is known.

## Out of Scope (this spec)

- Any actual package-level tests (Phases 1-5) — each is its own future spec+plan.
- Third-party coverage SaaS (Codecov etc.) — local artifacts only, consistent with the
  product's on-prem/air-gapped posture.
- Asset-criticality, SP3 connectors, or other roadmap items — unrelated initiative, see
  `project_platform_roadmap_2026h2`.
