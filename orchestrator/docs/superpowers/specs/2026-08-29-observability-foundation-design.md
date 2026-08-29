# Observability Foundation — Design

**Status:** Platform Roadmap 2026H2, Phase 8 (Production Readiness) —
[[project_platform_roadmap_2026h2]]. Backup/restore + disaster recovery are
already done ([[project_backup_recovery]]); this is the monitoring/
observability piece of Phase 8's remaining scope. Perf/load/pen testing,
upgrade validation, and release documentation are separate, not-yet-started
items in the same phase, each needing its own brainstorm cycle when picked
up.

## Goal

Give the platform real observability infrastructure — structured logging
for new code, a genuine liveness/readiness split, and a `/metrics`
endpoint — without requiring a live dev server for the design or most of
the implementation (testcontainers-backed tests only, matching this
session's established pattern). Explicitly a foundation: dashboards,
collectors, and alerting are someone else's job to point at what this
ships, not this sub-project's job to build.

## Scope

**In scope:**
- `log/slog` as the structured-logging convention for all *new* logging.
- `GET /ready` — a real readiness check (Postgres connectivity), additive
  alongside the existing `GET /health` (unchanged).
- `GET /metrics` — Prometheus text-exposition format via
  `prometheus/client_golang`, a small initial metric set, optional
  bearer-token gating.
- A request-logging middleware that feeds both structured logs and the
  HTTP metrics from one instrumentation point.

**Explicitly out of scope**, decided during brainstorming:
- **No retrofit of the existing 373 `log.Printf`/`log.Println`/`log.Fatal`
  call sites.** They keep working exactly as they do today. Migrating them
  is a separate, purely mechanical future task, not part of building the
  foundation. Old and new logging styles coexisting is an accepted,
  deliberate trade-off — forcing a mass migration now would be pure
  regression risk with no functional payoff.
- **No request ID / correlation ID system.** Nothing in this codebase
  currently generates or propagates one; adding it would be a new
  cross-cutting concern beyond "log requests, expose metrics."
- **No `slog` wrapper.** Call sites use `slog.Logger`/`slog.Default()`
  directly; the structured-fields convention (`component`, `error`, an
  existing correlation ID where the code path already has one) is applied
  at each call site, not enforced by an abstraction layer.
- **No automated secret/PII redaction.** "No secrets/tokens/passwords in
  logs" is a code-review discipline for new call sites, matching how the
  existing `[security]` log lines already avoid printing secrets — not a
  scrubber, which is materially larger scope than asked for.
- **No Grafana dashboards, no Prometheus server deployment, no Kubernetes
  monitoring, no alerting rules.** `/metrics` is a passive endpoint;
  nothing scrapes it unless something is pointed at it later, and that's
  explicitly a future, separate decision.
- **No production load/performance testing, no upgrade validation.**
  Different Phase 8 items, incompatible with this session's no-live-server
  constraint, picked up separately if/when a server is available.

## Structured logging

`main.go` sets a JSON `slog` handler as the process default at startup:

```go
slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
```

Every new `slog.Info`/`slog.Error`/etc. call anywhere in new code
automatically gets consistent JSON output as a result — no per-call-site
handler wiring needed. Convention (not enforced by tooling, established by
example at the call sites this sub-project adds): `component` (e.g.
`"http"`, `"sla"`, `"jobs"`), `error` via `slog.Any("error", err)`, and an
existing correlation ID (e.g. `run_id`) only when the code path already
carries one — never invented for this purpose.

## Health vs. readiness

`GET /health` (`routes.go:122`) is **unchanged** — still an unconditional
`200 {"status":"ok"}`. Docker's `HEALTHCHECK` (`cmd/server/main.go`'s
`runHealthcheck`) and `LicenseGate`'s allowlist both already depend on that
exact unconditional behavior; changing its semantics risks a transient DB
blip flapping a container that's otherwise fine.

New `GET /ready`, top-level (not under `/api/`, so it — like `/health` —
naturally bypasses `LicenseGate`'s prefix-based gating without needing an
explicit allowlist change; `LicenseGate` only gates `/api/`, `/ws/`,
`/scim/`, `/x/`, `/login/` prefixes and passes everything else through
regardless of license state):

```json
// 200, DB reachable
{"status": "ready", "checks": {"database": "ok"}}
// 503, DB unreachable
{"status": "not_ready", "checks": {"database": "<error text>"}}
```

Implementation: `h.db.Ping(ctx)` with a short timeout (2s) — pgxpool
already exposes this. This is the liveness/readiness split: `/health`
answers "is the process alive" (true if it can respond at all); `/ready`
answers "can this instance actually serve traffic right now."

## `/metrics`

New top-level `GET /metrics`, using `promhttp.Handler()` directly (not a
hand-rolled exposition format) from a new direct dependency,
`prometheus/client_golang` — confirmed absent from `go.mod`/`go.sum`
today, even transitively.

Initial metric set, deliberately small, every label bounded-cardinality
(`method`, `route` — chi's matched pattern like
`/api/sla/policies/{severity}`, never the raw URL or an ID — `status`,
`component`, `type`, `severity`):

| Metric | Type | Labels | Source |
|---|---|---|---|
| `http_requests_total` | counter | `method`, `route`, `status` | request-logging middleware |
| `http_request_duration_seconds` | histogram | `method`, `route` | request-logging middleware |
| `jobs_active` | gauge | `type` | `internal/jobs.Dispatcher` |
| `job_execution_duration_seconds` | histogram | `type` | `internal/jobs.Dispatcher` |
| `sla_breach_evaluations_total` | counter | — | `TickSLABreaches` |
| `sla_breaches_total` | counter | `severity` | `TickSLABreaches` |
| `db_ready` | gauge (0/1) | — | same check `/ready` performs |

`promhttp.Handler()` uses the default Prometheus registry, which
auto-registers the standard Go runtime collectors (`go_*` memory/GC/
goroutine metrics, `process_*` CPU/fd/uptime metrics) alongside whatever
this sub-project registers — the actual `/metrics` output will list more
than the 7 custom metrics above. That's expected default behavior, not an
inconsistency with this table.

**Access**: an optional static bearer token, not JWT — a scrape job can't
easily hold/refresh a session token. New config field `metrics_token`
(mirrors this codebase's existing pattern for optional hardening: unset =
endpoint stays open, same opt-in-by-default-off posture as
`BAS_DB_BREAKGLASS_PASSWORD` and API rate limiting; set = every request to
`/metrics` needs `Authorization: Bearer <token>` or gets `401`). Auth
resolution is a simple token-equality check, not the SCIM
`token_hash`/tenant-lookup machinery — there's no per-tenant dimension
here, just one instance-wide optional secret.

## Request-logging middleware

New `internal/api/observability.go`, `RequestLoggingMiddleware`, wired into
`Mount()` alongside the existing `RateLimitMiddleware`, applied to all
routes. One instrumentation point feeding both Section "Structured
logging" and the `http_requests_total`/`http_request_duration_seconds`
metrics: after each request completes, emits one `slog.Info` (`method`,
`route`, `status`, `duration_ms`, `component="http"`) and records the same
`method`/`route`/`status`/duration into the two HTTP metrics.

## Testing

TDD, testcontainers-backed where DB-dependent, matching this session's
established pattern — everything here verifies without a live dev server:

- `/ready`: DB reachable → `200`; DB unreachable (pool closed, or a
  stopped testcontainer) → `503` with the error surfaced in
  `checks.database`.
- `/health`: unchanged regression test — still unconditional `200`, guards
  against this sub-project accidentally touching it.
- `/metrics`: response contains the expected metric names in Prometheus
  text format; `metrics_token` unset → open; set → `401` without the
  bearer token, `200` with the correct one.
- Request-logging middleware: unit test capturing `slog` output (a test
  `slog.Handler`) asserting `method`/`route`/`status`/`duration_ms`/
  `component` are present and `route` is the chi pattern, not the raw path.
- Job/SLA metrics: extend a couple of existing `TickSLABreaches`/job-
  dispatch tests to also assert the corresponding counter incremented —
  reusing existing test scenarios rather than writing new ones purely for
  metrics.

## Migration

No DB schema change. One new optional `Config.MetricsToken` field
(`json:"metrics_token,omitempty"`), same additive pattern as every other
optional config field in `config.Config`.
