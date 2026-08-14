# License Grace Period & Hard Lockout — Design Spec

**Status:** Approved for implementation
**Date:** 2026-08-14

## Problem

Audspect BAS licenses are RSA-4096-signed files (`internal/license/license.go`) checked once, at process startup, via `license.Check()`. Today:

- An expired license (beyond a hardcoded 24-hour timezone-drift fudge) makes the orchestrator `log.Fatalf` and crash-loop at startup — there is no grace period at all.
- A **running** process never re-checks the license. If it's already up when the license expires, it keeps operating with full functionality indefinitely, until the next restart.
- There is no distinction between "just expired" and "expired for months" — both crash-loop identically.
- There's a `GET /api/license` endpoint and a Settings → License status card in the UI, but no banner, no modal, and no enforcement tied to license state beyond the startup crash.

## Goal

Replace this with a deterministic three-state model — `LICENSE_VALID` → `LICENSE_EXPIRED_GRACE` (5 days) → `LICENSE_LOCKED` — enforced server-side (HTTP middleware, WebSocket gate, scenario-execution gate) so the lockout can't be bypassed by avoiding the frontend, plus a frontend banner/modal during grace and a dedicated lockout screen once locked.

## Non-Goals

- No change to license file format, RSA signing, or the payload string that's signed — every already-issued `.lic` file continues to work unmodified.
- No per-customer/per-tier configurable grace period — `GracePeriodDays = 5` is a fixed constant.
- No gating of background analytics/sync schedulers (verify-sync, search index, OpenAEV sync, threat-intel connector polling) — only actual scenario/campaign **execution** and new agent work are blocked. See "Scope: what counts as a BAS operation" below.

## State Machine

### Timestamp derivation

Existing licenses store `expires_at` as a date-only string (`"2026-08-14"`), and the RSA signature covers that exact string (`License.payload()`) — the format cannot change without invalidating every issued license. So:

```
expiresAt = parse(lic.ExpiresAt, "2006-01-02") + 23:59:59 UTC   // end of that calendar day
lockoutAt = expiresAt + (GracePeriodDays * 24h)                  // GracePeriodDays = 5
```

### States

Evaluated purely from `(expiresAt, lockoutAt, now)` — no wall-clock-dependent process state, so a restart mid-grace-period resumes at the correct day, not day 1:

```
now < expiresAt              → LICENSE_VALID
expiresAt <= now < lockoutAt → LICENSE_EXPIRED_GRACE   (DaysRemaining = ceil((lockoutAt - now) / 24h))
now >= lockoutAt             → LICENSE_LOCKED
```

## Components

### 1. `internal/license` package additions (`license.go`, new `state.go`)

```go
type State string

const (
	StateValid  State = "valid"
	StateGrace  State = "grace"
	StateLocked State = "locked"
)

const GracePeriodDays = 5

type Info struct {
	State         State     `json:"state"`
	Customer      string    `json:"customer,omitempty"`
	ExpiresAt     time.Time `json:"expiresAt"`
	LockoutAt     time.Time `json:"lockoutAt"`
	DaysRemaining int       `json:"daysRemaining"` // 0 unless State == StateGrace
}

// Evaluate is pure — no I/O, no globals. now is injected for testability.
func Evaluate(lic *License, now time.Time) (Info, error)
```

`Evaluate` parses `lic.ExpiresAt` with the existing `"2006-01-02"` layout (reuses the same parse call already in `Check()`/`Status()`), computes `expiresAt`/`lockoutAt` per the formula above, and returns the `Info`. Returns an error only if `lic.ExpiresAt` fails to parse (same error path `Check()` already has).

`Status(expiresAt string) string` (existing, used by `GetLicenseInfo`) is reimplemented in terms of `Evaluate` so the Settings → License card and the new grace/lockout machinery can never disagree: `valid`→"valid", `grace`→"expiring_soon" is **replaced** — the card should show the real state now (see Component 4).

**Required change to existing `Check()` (`license.go:76-85`):** today `Check()` itself fatals when the license is expired beyond a hardcoded 24-hour fudge (`if time.Now().UTC().After(expiry.UTC().Add(24 * time.Hour)) { return fmt.Errorf("license: expired...") }`). This must be **removed** — as written, it would kill the process ~24 hours into Grace state, before the 5-day window is anywhere near up, directly contradicting "Grace and Locked both start normally." `Check()`'s remaining job is narrowed to what its name says: signature verification and file/date well-formedness (keep the `time.Parse` call and its error branch — a malformed date is still a legitimately fatal bad-license-file condition; only the *expired* branch goes). All expiry/grace/lockout evaluation moves entirely to `Evaluate()` and the runtime monitor (Components 2-3) — `Check()` no longer knows or cares what day it is relative to expiry.

### 2. Runtime monitor (`internal/license/monitor.go`, new)

```go
// SetInitial seeds the state atomic.Value read by Current, synchronously,
// before StartMonitor's ticker begins. Call once, at startup, right after
// the first Evaluate — guarantees Current() never reads a zero-valued Info.
func SetInitial(info Info)

// StartMonitor begins a background ticker that re-parses and re-evaluates
// the license at licPath every interval, overwriting the value SetInitial
// seeded. onLock is called at most once per transition into StateLocked
// (nil-safe — pass nil to skip).
func StartMonitor(ctx context.Context, licPath string, interval time.Duration, onLock func())

// Current returns the most recently stored evaluation (from SetInitial
// until the first tick, from the ticker thereafter).
func Current() Info
```

Implementation: `atomic.Value` holding `Info`, written by `SetInitial` once and then by the ticker goroutine on each tick, read by every consumer below. Ticker interval: 5 minutes (a license only ever transitions once every up-to-24-hours; 5 minutes bounds the worst-case detection lag to something well inside a single day without meaningful overhead). The `onLock` callback fires by comparing the previous stored `State` to the newly computed one inside the ticker loop — fires only on `!= StateLocked → == StateLocked`, never on every tick while already locked.

### 3. `cmd/server/main.go` wiring

Immediately after the existing startup block (`main.go:78-81` — still present and still fatal, but now only for a missing/tampered/malformed license, per the `Check()` change in Component 1):

```go
// ── License Check ─────────────────────────────────────────────────────
if err := license.Check(cfg.LicensePath); err != nil {
	log.Fatalf("[FATAL] %v", err)
}

// ── License State Monitor ───────────────────────────────────────────────
lic, err := license.Get(cfg.LicensePath)
if err != nil {
	log.Fatalf("[FATAL] %v", err) // Check() just verified this file parses; only reachable on a race with file deletion
}
initialInfo, err := license.Evaluate(lic, time.Now())
if err != nil {
	log.Fatalf("[FATAL] %v", err)
}
license.SetInitial(initialInfo) // seeds the atomic.Value Current() reads
if initialInfo.State == license.StateLocked {
	log.Printf("[license] LOCKED — grace period expired on %s. Serving lockout-only mode.", initialInfo.LockoutAt.Format(time.RFC3339))
} else if initialInfo.State == license.StateGrace {
	log.Printf("[license] WARNING: in grace period — %d day(s) remaining before lockout on %s", initialInfo.DaysRemaining, initialInfo.LockoutAt.Format(time.RFC3339))
}
monitorCtx, monitorCancel := context.WithCancel(context.Background())
defer monitorCancel()
license.StartMonitor(monitorCtx, cfg.LicensePath, 5*time.Minute, func() {
	hub.CloseAllAgentConnections() // hub constructed earlier in main.go — verify ordering, move this wiring below hub's construction if StartMonitor is called before hub exists
})
```

Note for the plan: `hub` (the `*ws.Hub`) must already be constructed before this call — if `main.go`'s current ordering constructs `hub` later, `StartMonitor` moves down to after that point, or the `onLock` callback is registered via a setter (`hub.SetOnLockCallback`) called once `hub` exists. The plan should check `main.go`'s actual construction order and pick whichever requires the smaller diff.

If `license.Check()` at the top already exits fatally on missing/tampered/unparseable files, `license.Get`+`Evaluate` immediately after can only fail via a race (file deleted between the two calls) — treated as fatal, consistent with existing behavior.

### 4. HTTP enforcement (`internal/api`)

**New middleware, `internal/api/license_gate.go`:**

```go
// LicenseGate blocks all requests once the license is StateLocked, except
// the small allowlist needed to serve the lockout UI itself.
func LicenseGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if license.Current().State != license.StateLocked {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" || r.URL.Path == "/api/license/status" {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") &&
			!strings.HasPrefix(r.URL.Path, "/ws/") &&
			!strings.HasPrefix(r.URL.Path, "/scim/") &&
			!strings.HasPrefix(r.URL.Path, "/x/") &&
			!strings.HasPrefix(r.URL.Path, "/login/") {
			next.ServeHTTP(w, r) // static SPA shell — must still load so it can render the lockout screen
			return
		}
		jsonError(w, "license_locked", http.StatusPaymentRequired)
	})
}
```

Mounted in `routes.go` right after `r.Use(middleware.StripSlashes)` (`routes.go:25`), before every route group — applies uniformly to public routes (including `POST /api/auth/login`, which is now rejected outright when locked, per design decision), the JWT-authenticated group, SCIM, ITSM webhook, and both WebSocket upgrade handlers.

**New public endpoint**, added to the "Public endpoints (no auth)" block (`routes.go:36-41`):

```go
r.Get("/api/license/status", h.GetLicenseStatus)
```

```go
// GetLicenseStatus is public (no auth) — the frontend polls it before
// login to decide whether to render the normal app shell or the
// permanent lockout screen. Deliberately excludes customer/features
// (those stay behind auth in GetLicenseInfo) — only state + dates.
func (h *Handler) GetLicenseStatus(w http.ResponseWriter, r *http.Request) {
	info := license.Current()
	respond(w, map[string]any{
		"state":         string(info.State),
		"expiresAt":     info.ExpiresAt.Format("2006-01-02"),
		"lockoutAt":     info.LockoutAt.Format("2006-01-02"),
		"daysRemaining": info.DaysRemaining,
	})
}
```

**Existing `GetLicenseInfo`** (`handlers.go:458-474`, behind auth) — its `"status"` field switches from `license.Status(lic.ExpiresAt)` (today: `valid`/`expiring_soon`/`expired`) to `string(license.Current().State)` (`valid`/`grace`/`locked`), and gains `"daysRemaining"` and `"lockoutAt"` fields so the Settings → License card can show the same grace countdown as the banner.

### 5. WebSocket enforcement (`routes.go:60-87`, `internal/ws`)

Both `/ws/agent` and `/ws/browser` handlers gain a `license.Current().State == license.StateLocked` check before their existing auth checks, returning `401` (reusing the existing `http.Error(w, "unauthorized", ...)` pattern already on both handlers) — new connections can't be established while locked. (These two handlers sit above the `LicenseGate` middleware's mount point in the public-routes block per the current route ordering — the plan should confirm whether `LicenseGate` alone already covers them via the `/ws/` prefix check, or whether this explicit check is redundant-but-harmless defense in depth; either is acceptable, prefer one over duplicating logic.)

**`ws.Hub` new method:**

```go
// CloseAllAgentConnections force-closes every currently-connected agent
// WebSocket session. Called once, by the license monitor's onLock
// callback, on the transition into StateLocked.
func (h *Hub) CloseAllAgentConnections()
```

Iterates the hub's existing agent-connection registry (mirroring however the hub already iterates connections for broadcast, if such a method exists — the plan should locate and reuse that iteration pattern rather than inventing a new one) and closes each with a WebSocket close frame, not just dropping the TCP connection, so agents get a clean disconnect they can log.

### 6. Scenario execution gate (`internal/api/handlers.go:1238`, `dispatchRun`)

```go
func (h *Handler) dispatchRun(ctx context.Context, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID string, skipReason string, err error) {
	if license.Current().State == license.StateLocked {
		return "", "license_locked", nil
	}
	// ... existing body unchanged
}
```

Returning `skipReason: "license_locked"` (not `err`) matches the existing skip-reason convention already used for the agent-busy case (per prior session context: `dispatchRun`'s "agent busy" skip) — callers already know how to surface a skip reason without treating it as a hard error. This single gate covers manual runs, scheduled assessments, campaigns, `vexsweep`, and `emsweep`, since all funnel through this function.

### 7. Frontend (`orchestrator/wwwroot/index.html`)

**Boot-time gate:** near the top of the app's initialization JS (wherever the SPA currently decides "show login form" vs "restore session" — the plan should locate this exact entry point), add an unauthenticated `fetch('/api/license/status')` call *before* that decision. If `state === 'locked'`, render a dedicated full-screen view (new function, e.g. `renderLicenseLockedScreen(info)`) instead of the login form or the app shell, using your exact copy:

> 🔒 BAS LICENSE EXPIRED
> This Audspect BAS installation is currently unavailable because its license and grace period have expired.
> Please contact your licensing administrator to renew the license.

Plus expiry/lockout dates and a "Contact Licensing Support" button (`mailto:support@audspect.com`, matching the existing error-message convention already used in `license.Check()`'s error strings). This view never calls any other API — nothing else works while locked, per the middleware gate.

**Grace banner:** when `state === 'grace'`, inject a persistent, always-visible red/amber banner at the top of the app shell (present on every page, including dashboard and the Settings → License panel) using your exact copy:

> ⚠️ LICENSE EXPIRED — ACTION REQUIRED
> Your Audspect BAS license expired on `{expiresAt}`. You are currently within the 5-day license grace period.
> Grace Period Remaining: `{daysRemaining}` Days
> The BAS platform will become inaccessible after the grace period expires. Please contact your Audspect administrator or licensing representative to renew your license.
> License Expiry: `{expiresAt}` · Access Disabled On: `{lockoutAt}`
> [Contact Licensing Support]

Countdown copy varies by day per your spec ("4 days... remaining" → "1 day... BAS access will be disabled tomorrow").

**Once-per-session modal:** same content as the banner, shown once via a `sessionStorage` flag (`bas_license_grace_modal_shown`) set on first render after login, so it doesn't reappear on every page navigation within the same browser session but does reappear on a fresh login.

**Settings → License card** (`loadLicenseInfo()`, `index.html:16226-16257`): status badge/color logic updates from the current `valid`/`expiring_soon`/`expired` three-way to `valid`/`grace`/`locked`, and gains a grace-countdown line when `state === 'grace'`.

## Scope: what counts as a "BAS operation"

Gated (blocked when `LICENSE_LOCKED`):
- Manual scenario runs, scheduled assessments, campaigns, Full Variant Sweep, EM Full Sweep — all via the `dispatchRun` gate
- New agent WebSocket connections; existing ones force-closed on the lock transition
- All authenticated API access, including login

Not gated (continues running while locked):
- Background analytics/sync schedulers already running in `main.go` (verify-sync, search index, OpenAEV sync) — these update internal state from data already collected, not new BAS execution
- Passive threat-intel connector polling (MISP/OpenCTI/OTX ingestion) — syncing IOCs/actors is not itself a BAS operation; if a connector auto-triggers a scenario run from newly-synced intel, that run attempt still goes through `dispatchRun` and is blocked there

## Testing

- `internal/license/state_test.go` (new): table-driven tests of `Evaluate` across the boundary instants — `now` just before `expiresAt`, exactly at `expiresAt`, mid-grace, just before `lockoutAt`, exactly at `lockoutAt`, well past `lockoutAt`. Table-driven with injected `now` — no wall-clock dependency, no sleeping.
- `internal/license/monitor_test.go` (new): `StartMonitor` with a short interval and a fake clock or a license file swapped mid-test, asserting `Current()` updates and `onLock` fires exactly once on the `Grace → Locked` transition (not on every subsequent tick while already locked).
- `internal/api/license_gate_test.go` (new): table of paths × states → expected status code, covering the allowlist (`/health`, `/api/license/status`, static fallback) and the blocked set (`/api/auth/login`, an authenticated route, `/ws/agent` upgrade attempt) under `StateLocked`, and confirming zero interference under `StateValid`/`StateGrace`.
- `internal/api/handlers_test.go` addition: `dispatchRun` returns `skipReason: "license_locked"` and does not call the injected dispatch function when `license.Current()` is stubbed to `StateLocked` (tests already inject fakes for the dispatch path per existing convention in this file).
- Full `internal/api` suite must still pass (existing tests construct licenses/state indirectly through `Handler` — the plan should check whether any existing test fixture needs `license.SetInitial(validInfo)` seeded so it doesn't spuriously read a zero-valued `Current()` as locked).

## Open items for the plan to resolve with fresh source reads

- Exact current construction order of `hub` vs. the license-check block in `main.go`, to place `StartMonitor`'s wiring correctly (§3).
- Whether `ws.Hub` already has a connection-iteration method to mirror for `CloseAllAgentConnections` (§5).
- The exact SPA boot-sequence function/line in `index.html` where "show login vs. restore session" is decided, to hook the pre-login `/api/license/status` check (§7).
- Whether any existing `internal/api` test fixtures need `license.SetInitial` seeding to avoid a zero-valued `Current()` (§ Testing).
