# License Grace Period & Hard Lockout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the orchestrator's current startup-only, 24-hour-fudge license expiry check with a deterministic three-state model (`LICENSE_VALID` → `LICENSE_EXPIRED_GRACE` (5 days) → `LICENSE_LOCKED`), enforced server-side so it can't be bypassed by avoiding the frontend, plus a grace-period banner/modal and a permanent lockout screen in the UI.

**Architecture:** A new pure `Evaluate()` function in `internal/license` computes state from `(expiresAt, lockoutAt, now)`; a background ticker (`StartMonitor`) re-evaluates every 5 minutes and stores the result in an `atomic.Value`; an HTTP middleware, a WebSocket upgrade check, and a single guard in the existing `dispatchRun` choke point all read that stored state to enforce the lockout. No new DB tables — state is derived entirely from the already-signed `.lic` file plus wall clock.

**Tech Stack:** Go 1.26, chi router, `sync/atomic`, existing `gorilla/websocket` Hub, vanilla JS frontend (`wwwroot/index.html`).

**Spec:** `docs/superpowers/specs/2026-08-14-license-grace-period-design.md`

## Global Constraints

- `GracePeriodDays = 5` — fixed constant, not per-license-configurable.
- Existing `.lic` file format and RSA signature payload (`License.payload()`) must not change — every already-issued license must keep working unmodified.
- `expiresAt` = the license's date-only `ExpiresAt` string interpreted as `23:59:59 UTC` on that calendar day. `lockoutAt` = `expiresAt + 5*24h`.
- `Check()` (`internal/license/license.go`) stays fatal for a missing/tampered/malformed license file, but must **no longer** be fatal for a merely-expired one — all expiry/grace/lockout logic moves to `Evaluate()`/the monitor.
- Login (`POST /api/auth/login`) is rejected outright when `LICENSE_LOCKED` — no session is issued.
- Background analytics/sync schedulers (verify-sync, search index, OpenAEV sync, threat-intel connector polling) are **not** gated — only actual scenario/campaign execution (`dispatchRun`) and new/existing agent WebSocket connections are blocked.

---

## Task 1: License state machine — `Evaluate()`

**Files:**
- Create: `orchestrator/internal/license/state.go`
- Test: `orchestrator/internal/license/state_test.go`

**Interfaces:**
- Produces: `type State string` with consts `StateValid`, `StateGrace`, `StateLocked`; `const GracePeriodDays = 5`; `type Info struct { State State; Customer string; ExpiresAt time.Time; LockoutAt time.Time; DaysRemaining int }`; `func Evaluate(lic *License, now time.Time) (Info, error)`.

- [ ] **Step 1: Write the failing tests**

```go
package license

import (
	"testing"
	"time"
)

func mustLicense(expiresAt string) *License {
	return &License{Customer: "Acme Corp", ExpiresAt: expiresAt}
}

func TestEvaluate_Valid_WellBeforeExpiry(t *testing.T) {
	lic := mustLicense("2026-08-20")
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateValid {
		t.Errorf("state = %q, want %q", info.State, StateValid)
	}
	if info.DaysRemaining != 0 {
		t.Errorf("DaysRemaining = %d, want 0 for a Valid license", info.DaysRemaining)
	}
}

func TestEvaluate_Valid_JustBeforeExpiryInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	// expiresAt for 2026-08-14 is 2026-08-14T23:59:59Z — one second before that is still Valid.
	now := time.Date(2026, 8, 14, 23, 59, 58, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateValid {
		t.Errorf("state = %q, want %q", info.State, StateValid)
	}
}

func TestEvaluate_Grace_ExactlyAtExpiryInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 14, 23, 59, 59, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateGrace {
		t.Errorf("state = %q, want %q (expiresAt is inclusive-lower-bound of grace)", info.State, StateGrace)
	}
}

func TestEvaluate_Grace_MidWindow(t *testing.T) {
	lic := mustLicense("2026-08-14")
	// lockoutAt = 2026-08-14T23:59:59Z + 5*24h = 2026-08-19T23:59:59Z
	now := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateGrace {
		t.Errorf("state = %q, want %q", info.State, StateGrace)
	}
	if info.DaysRemaining < 1 || info.DaysRemaining > 5 {
		t.Errorf("DaysRemaining = %d, want a value in [1,5] mid-grace", info.DaysRemaining)
	}
}

func TestEvaluate_Grace_JustBeforeLockoutInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 19, 23, 59, 58, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateGrace {
		t.Errorf("state = %q, want %q", info.State, StateGrace)
	}
}

func TestEvaluate_Locked_ExactlyAtLockoutInstant(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 19, 23, 59, 59, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateLocked {
		t.Errorf("state = %q, want %q (lockoutAt is inclusive-lower-bound of locked)", info.State, StateLocked)
	}
}

func TestEvaluate_Locked_WellPastLockout(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.State != StateLocked {
		t.Errorf("state = %q, want %q", info.State, StateLocked)
	}
	if info.DaysRemaining != 0 {
		t.Errorf("DaysRemaining = %d, want 0 once Locked", info.DaysRemaining)
	}
}

func TestEvaluate_InvalidExpiryDate(t *testing.T) {
	lic := mustLicense("not-a-date")
	_, err := Evaluate(lic, time.Now())
	if err == nil {
		t.Fatal("expected an error for a malformed ExpiresAt date")
	}
}

func TestEvaluate_ExpiresAtAndLockoutAtFields(t *testing.T) {
	lic := mustLicense("2026-08-14")
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	info, err := Evaluate(lic, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantExpires := time.Date(2026, 8, 14, 23, 59, 59, 0, time.UTC)
	wantLockout := time.Date(2026, 8, 19, 23, 59, 59, 0, time.UTC)
	if !info.ExpiresAt.Equal(wantExpires) {
		t.Errorf("ExpiresAt = %v, want %v", info.ExpiresAt, wantExpires)
	}
	if !info.LockoutAt.Equal(wantLockout) {
		t.Errorf("LockoutAt = %v, want %v", info.LockoutAt, wantLockout)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/license/... -run TestEvaluate -v`
Expected: FAIL — `Evaluate`, `State`, `StateValid`/`StateGrace`/`StateLocked`, `Info`, `GracePeriodDays` are all undefined.

- [ ] **Step 3: Implement `Evaluate`**

```go
package license

import (
	"fmt"
	"time"
)

// State is one of the three license enforcement states.
type State string

const (
	StateValid  State = "valid"
	StateGrace  State = "grace"
	StateLocked State = "locked"
)

// GracePeriodDays is fixed, not per-license-configurable — see
// docs/superpowers/specs/2026-08-14-license-grace-period-design.md.
const GracePeriodDays = 5

// Info is a point-in-time evaluation of a license's enforcement state.
type Info struct {
	State         State
	Customer      string
	ExpiresAt     time.Time
	LockoutAt     time.Time
	DaysRemaining int // 0 unless State == StateGrace
}

// Evaluate computes the enforcement state of lic as of now. now is an
// explicit parameter (not time.Now()) so this stays a pure function —
// callers pass time.Now() in production and fixed instants in tests.
//
// lic.ExpiresAt is a date-only string ("2006-01-02"); the existing signed
// license payload cannot change, so the exact instant is derived as the
// end of that calendar day in UTC (23:59:59), not midnight — this keeps
// a customer's license valid through the entire day printed on it,
// regardless of the timezone they're actually in.
func Evaluate(lic *License, now time.Time) (Info, error) {
	expiryDate, err := time.Parse("2006-01-02", lic.ExpiresAt)
	if err != nil {
		return Info{}, fmt.Errorf("license: invalid expiry date: %w", err)
	}
	expiresAt := time.Date(
		expiryDate.Year(), expiryDate.Month(), expiryDate.Day(),
		23, 59, 59, 0, time.UTC,
	)
	lockoutAt := expiresAt.Add(GracePeriodDays * 24 * time.Hour)

	info := Info{
		Customer:  lic.Customer,
		ExpiresAt: expiresAt,
		LockoutAt: lockoutAt,
	}

	switch {
	case now.Before(expiresAt):
		info.State = StateValid
	case now.Before(lockoutAt):
		info.State = StateGrace
		remaining := lockoutAt.Sub(now)
		info.DaysRemaining = int(remaining/(24*time.Hour)) + 1 // ceil, and never 0 while still in grace
	default:
		info.State = StateLocked
	}
	return info, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/license/... -run TestEvaluate -v`
Expected: PASS — all 9 test functions.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/license/state.go internal/license/state_test.go
git commit -m "feat(license): add deterministic 3-state Evaluate() for grace period"
git push
```

---

## Task 2: Remove `Check()`'s expiry-fatal branch; reimplement `Status()` via `Evaluate`

**Files:**
- Modify: `orchestrator/internal/license/license.go:76-89` (the expiry check inside `Check()`) and `:108-122` (`Status`)
- Test: `orchestrator/internal/license/license_test.go` (new)

**Interfaces:**
- Consumes: `Evaluate`, `Info`, `State`, `StateValid`/`StateGrace`/`StateLocked` from Task 1.
- Produces: `Check(licPath string) error` (unchanged signature, narrowed behavior — no longer fatals on mere expiry) and `Status(expiresAt string) string` (unchanged signature, now backed by `Evaluate`, returns `"valid"`/`"expiring_soon"`/`"expired"` — see note below on why `Status`'s string values stay as-is even though `Evaluate`'s `State` values differ).

**Note on `Status` vs `State`:** `Status()` is a pre-existing, narrower helper (`GetLicenseInfo`'s old caller expected `"valid"`/`"expiring_soon"`/`"expired"`) that Task 9 replaces entirely with `string(license.Current().State)` — so `Status()` becomes dead code after Task 9 lands. Re-implementing it here (rather than deleting it now) keeps this task's diff small and isolated to `Check()`'s bug fix; Task 9 removes the now-unused `Status` function and this test file's `TestStatus_*` cases as part of its own diff.

- [ ] **Step 1: Write the failing tests**

First, re-read the current exact content of `Check()` (`license.go:42-89`) and `Status()` (`license.go:108-122`) before editing — this session's earlier read may be stale by the time this task executes.

```go
package license

import (
	"testing"
	"time"
)

// Check() with PublicKeyPEM still at its dev-mode placeholder always
// returns nil regardless of expiry — this test only exercises the
// production code path indirectly via Evaluate, since Check() itself
// requires a real signed .lic file on disk to test the signature branch
// meaningfully (out of scope here — Check()'s signature verification is
// unchanged by this task). This task's regression coverage is: Status()
// must agree with Evaluate() for the same three boundary cases Task 1
// already covers for Evaluate directly.
func TestStatus_Valid(t *testing.T) {
	if got := Status("2099-01-01"); got != "valid" {
		t.Errorf("Status = %q, want %q", got, "valid")
	}
}

func TestStatus_Expired(t *testing.T) {
	if got := Status("2000-01-01"); got != "expired" {
		t.Errorf("Status = %q, want %q", got, "expired")
	}
}

func TestStatus_ExpiringSoon(t *testing.T) {
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format("2006-01-02")
	if got := Status(soon); got != "expiring_soon" {
		t.Errorf("Status(%q) = %q, want %q", soon, got, "expiring_soon")
	}
}

func TestStatus_UnknownOnBadDate(t *testing.T) {
	if got := Status("garbage"); got != "unknown" {
		t.Errorf("Status = %q, want %q", got, "unknown")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail (or pass vacuously against the OLD implementation)**

Run: `cd orchestrator && go test ./internal/license/... -run TestStatus -v`
Expected: these will actually PASS against the current `Status()` implementation as-is (it already has this exact behavior) — that's fine, this step just locks in the current external contract before the internals change underneath it in Step 3. Confirm they pass now so a later regression is caught.

- [ ] **Step 3: Remove the expiry-fatal branch from `Check()`; reimplement `Status()` via `Evaluate`**

In `Check()`, delete this block (the exact lines — re-locate before editing, this is the content as read earlier this session):

```go
	expiry, err := time.Parse("2006-01-02", lic.ExpiresAt)
	if err != nil {
		return fmt.Errorf("license: invalid expiry date: %w", err)
	}
	// Give 24-hour grace period for timezone drift
	if time.Now().UTC().After(expiry.UTC().Add(24 * time.Hour)) {
		return fmt.Errorf("license: expired on %s (customer: %s) — contact support@audspect.com",
			lic.ExpiresAt, lic.Customer)
	}
```

Replace it with just the date well-formedness check (drop the expiry-fatal branch entirely — expiry is no longer `Check()`'s concern):

```go
	if _, err := time.Parse("2006-01-02", lic.ExpiresAt); err != nil {
		return fmt.Errorf("license: invalid expiry date: %w", err)
	}
```

Replace the body of `Status`:

```go
// Status returns "valid", "expiring_soon" (< 30 days), "expired", or
// "unknown" for a malformed date. Retained for the existing narrower
// three-way contract some callers still expect; Task 9 replaces its one
// caller (GetLicenseInfo) with the richer license.Current().State and
// removes this function.
func Status(expiresAt string) string {
	lic := &License{ExpiresAt: expiresAt}
	info, err := Evaluate(lic, time.Now().UTC())
	if err != nil {
		return "unknown"
	}
	switch info.State {
	case StateValid:
		if info.ExpiresAt.Sub(time.Now().UTC()) < 30*24*time.Hour {
			return "expiring_soon"
		}
		return "valid"
	default: // StateGrace or StateLocked — both were "expired" under the old 3-way contract
		return "expired"
	}
}
```

- [ ] **Step 4: Run tests to verify they still pass**

Run: `cd orchestrator && go test ./internal/license/... -v`
Expected: PASS — all of Task 1's and this task's tests.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/license/license.go internal/license/license_test.go
git commit -m "fix(license): Check() no longer fatals on mere expiry — grace/lockout is Evaluate()'s job now"
git push
```

---

## Task 3: Runtime monitor — `SetInitial` / `StartMonitor` / `Current`

**Files:**
- Create: `orchestrator/internal/license/monitor.go`
- Test: `orchestrator/internal/license/monitor_test.go`

**Interfaces:**
- Consumes: `Evaluate`, `Info`, `State`, `Get` (existing, `license.go:93-106`) from Tasks 1-2.
- Produces: `func SetInitial(info Info)`, `func Current() Info`, `func StartMonitor(ctx context.Context, licPath string, interval time.Duration, onLock func())`.

- [ ] **Step 1: Write the failing tests**

```go
package license

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCurrent_BeforeAnyCallReturnsZeroValue(t *testing.T) {
	// Guards the documented contract: an unseeded Current() returns a
	// zero-value Info whose State is "" — not StateLocked — so callers
	// that forget to seed never accidentally fail open into a lockout.
	// (Package-level state is intentionally not reset between tests in
	// this file — this test must run first or use a fresh subprocess in
	// CI if test ordering ever becomes a problem; documented here rather
	// than engineered around, since Go test files run in one process and
	// this package has no exported reset — acceptable for a monitor that
	// is only ever seeded once per process in production.)
	t.Skip("informational: see comment — package-global state makes this ordering-fragile, exercised instead via SetInitial below")
}

func TestSetInitial_ThenCurrent(t *testing.T) {
	want := Info{State: StateGrace, DaysRemaining: 3}
	SetInitial(want)
	got := Current()
	if got.State != want.State || got.DaysRemaining != want.DaysRemaining {
		t.Errorf("Current() = %+v, want %+v", got, want)
	}
}

func TestStartMonitor_PicksUpStateChangeOnTick(t *testing.T) {
	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")
	writeLic := func(expiresAt string) {
		data, _ := json.Marshal(License{Customer: "Acme", ExpiresAt: expiresAt})
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}
	}

	// Start valid, well in the future.
	writeLic(time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02"))
	SetInitial(Info{State: StateValid})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

	// Flip the file to an already-locked license (deep in the past).
	writeLic(time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if Current().State == StateLocked {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Current().State never became StateLocked after license file changed; last seen: %+v", Current())
}

func TestStartMonitor_OnLockFiresExactlyOnceOnTransition(t *testing.T) {
	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")
	data, _ := json.Marshal(License{Customer: "Acme", ExpiresAt: time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02")})
	if err := os.WriteFile(licPath, data, 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	SetInitial(Info{State: StateGrace}) // start NOT locked, so the first tick is the transition

	var calls int
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, func() { calls++ })

	time.Sleep(200 * time.Millisecond) // several ticks — onLock must still fire only once
	if calls != 1 {
		t.Errorf("onLock called %d times, want exactly 1", calls)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/license/... -run "TestSetInitial|TestStartMonitor" -v`
Expected: FAIL — `SetInitial`, `Current`, `StartMonitor` undefined.

- [ ] **Step 3: Implement the monitor**

```go
package license

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

var current atomic.Value // holds Info

// SetInitial seeds the state atomic.Value read by Current, synchronously,
// before StartMonitor's ticker begins. Call once, at startup, right after
// the first Evaluate — guarantees Current() never reads a zero-valued Info
// once the caller has started up (an unseeded Current() before this is
// ever called returns a zero-value Info{} whose State is "", which every
// enforcement point in this codebase treats as "not locked" — fail-open
// by construction, never fail-closed on a forgotten seed).
func SetInitial(info Info) {
	current.Store(info)
}

// Current returns the most recently stored evaluation (from SetInitial
// until the first tick, from the ticker thereafter).
func Current() Info {
	v := current.Load()
	if v == nil {
		return Info{}
	}
	return v.(Info)
}

// StartMonitor begins a background ticker that re-parses and re-evaluates
// the license at licPath every interval, overwriting the value SetInitial
// seeded. onLock is called at most once per transition into StateLocked
// (nil-safe — pass nil to skip). Stops when ctx is cancelled.
func StartMonitor(ctx context.Context, licPath string, interval time.Duration, onLock func()) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		wasLocked := Current().State == StateLocked
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lic, err := Get(licPath)
				if err != nil {
					log.Printf("[license] monitor: re-read failed: %v (keeping last known state)", err)
					continue
				}
				info, err := Evaluate(lic, time.Now().UTC())
				if err != nil {
					log.Printf("[license] monitor: re-evaluate failed: %v (keeping last known state)", err)
					continue
				}
				current.Store(info)
				nowLocked := info.State == StateLocked
				if nowLocked && !wasLocked && onLock != nil {
					onLock()
				}
				wasLocked = nowLocked
			}
		}
	}()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/license/... -v`
Expected: PASS — all tests from Tasks 1-3.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/license/monitor.go internal/license/monitor_test.go
git commit -m "feat(license): add background monitor for runtime grace/lockout transitions"
git push
```

---

## Task 4: `ws.Hub.CloseAllAgentConnections`

**Files:**
- Modify: `orchestrator/internal/ws/hub.go` (add method after `ConnectedAgents`, currently ending around line 173 — re-locate before editing)
- Test: `orchestrator/internal/ws/hub_test.go`

**Interfaces:**
- Consumes: nothing new — operates on `Hub`'s existing `agents map[string]*conn` and `mu sync.RWMutex` fields.
- Produces: `func (h *Hub) CloseAllAgentConnections()`.

- [ ] **Step 1: Write the failing test**

```go
func TestCloseAllAgentConnections_ClosesEveryAgentConn(t *testing.T) {
	h := NewHub()
	// Directly populate the agents map with fake conns backed by real
	// in-memory pipe websocket connections is more setup than this needs —
	// instead, verify the documented contract at the level this package's
	// other tests already use: that the method drains the agents map,
	// mirroring the same cleanup ServeAgentWS's own readPump-exit path
	// performs (see hub.go:75-78).
	h.mu.Lock()
	h.agents["agent-1"] = &conn{send: make(chan []byte, 1)}
	h.agents["agent-2"] = &conn{send: make(chan []byte, 1)}
	h.mu.Unlock()

	h.CloseAllAgentConnections()

	h.mu.RLock()
	remaining := len(h.agents)
	h.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("agents map has %d entries after CloseAllAgentConnections, want 0", remaining)
	}
}
```

Note: this test constructs `conn{send: ...}` with a nil `ws *websocket.Conn` field — `CloseAllAgentConnections`'s implementation in Step 3 must handle a nil `c.ws` gracefully (skip the close-frame write/close call, still remove from the map) so this lightweight test doesn't require standing up real TCP websocket connections. Document this nil-guard in the implementation as being for test convenience, not an expected production condition (a `conn` in `h.agents` always has a real `ws` in production — it's only ever constructed in `ServeAgentWS` after a successful `upgrader.Upgrade`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/ws/... -run TestCloseAllAgentConnections -v`
Expected: FAIL — `CloseAllAgentConnections` undefined.

- [ ] **Step 3: Implement the method**

```go
// CloseAllAgentConnections force-closes every currently-connected agent
// WebSocket session and clears the agents map. Called once, by the
// license monitor's onLock callback (see cmd/server/main.go), on the
// transition into license.StateLocked — agents must stop receiving new
// work and stop submitting results while the platform is locked.
func (h *Hub) CloseAllAgentConnections() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for agentID, c := range h.agents {
		if c.ws != nil {
			// Best-effort graceful close frame, mirroring writePump's own
			// graceful-close path (hub.go:187) — then force the underlying
			// connection closed so a blocked readPump's ReadMessage call
			// returns immediately instead of waiting out pongWait.
			c.ws.WriteMessage(websocket.CloseMessage, []byte{})
			c.ws.Close()
		}
		delete(h.agents, agentID)
		log.Printf("[ws] agent force-disconnected (license locked): %s", agentID)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/ws/... -v`
Expected: PASS — all existing `internal/ws` tests plus the new one.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/ws/hub.go internal/ws/hub_test.go
git commit -m "feat(ws): add Hub.CloseAllAgentConnections for license lockout"
git push
```

---

## Task 5: HTTP `LicenseGate` middleware + public `GET /api/license/status`

**Files:**
- Create: `orchestrator/internal/api/license_gate.go`
- Modify: `orchestrator/internal/api/routes.go` (mount the middleware near line 25, register the new route in the public-routes block near line 36-41 — re-locate exact lines before editing)
- Modify: `orchestrator/internal/api/handlers.go` (add `GetLicenseStatus` near the existing `GetLicenseInfo`, currently at line 460 — re-locate before editing)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add `"GET /api/license/status": true` to the `publicRoutes` map, currently starting line 359 — re-locate before editing)
- Test: `orchestrator/internal/api/license_gate_test.go`

**Interfaces:**
- Consumes: `license.Current()`, `license.StateLocked`, `license.State` from Tasks 1-3; existing `respond`/`jsonError` helpers (`handlers.go:2901`/`2941`, unchanged).
- Produces: `func LicenseGate(next http.Handler) http.Handler` (chi-compatible middleware); `func (h *Handler) GetLicenseStatus(w http.ResponseWriter, r *http.Request)`.

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/license"
)

func TestLicenseGate_AllowlistPassesThroughWhenLocked(t *testing.T) {
	license.SetInitial(license.Info{State: license.StateLocked})
	defer license.SetInitial(license.Info{}) // reset for other tests in this package

	allowlisted := []string{"/health", "/api/license/status"}
	for _, path := range allowlisted {
		called := false
		gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if !called {
			t.Errorf("path %q: handler was not called, want it to pass through the gate when locked", path)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("path %q: status = %d, want %d", path, rec.Code, http.StatusOK)
		}
	}
}

func TestLicenseGate_StaticShellPassesThroughWhenLocked(t *testing.T) {
	license.SetInitial(license.Info{State: license.StateLocked})
	defer license.SetInitial(license.Info{})

	called := false
	gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, req)
	if !called {
		t.Error("static asset path was blocked when locked, want it to pass through so the lockout screen can load")
	}
	_ = rec
}

func TestLicenseGate_BlocksAPIRoutesWhenLocked(t *testing.T) {
	license.SetInitial(license.Info{State: license.StateLocked})
	defer license.SetInitial(license.Info{})

	blocked := []string{"/api/auth/login", "/api/agents", "/ws/agent", "/scim/v2/Users"}
	for _, path := range blocked {
		called := false
		gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if called {
			t.Errorf("path %q: handler was called, want it blocked when locked", path)
		}
		if rec.Code != http.StatusPaymentRequired {
			t.Errorf("path %q: status = %d, want %d", path, rec.Code, http.StatusPaymentRequired)
		}
	}
}

func TestLicenseGate_PassesThroughWhenValidOrGrace(t *testing.T) {
	for _, state := range []license.State{license.StateValid, license.StateGrace} {
		license.SetInitial(license.Info{State: state})
		called := false
		gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if !called {
			t.Errorf("state %q: handler was not called, want normal pass-through", state)
		}
	}
	license.SetInitial(license.Info{}) // reset
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestLicenseGate -v`
Expected: FAIL — `LicenseGate` undefined.

- [ ] **Step 3: Implement the middleware and the status endpoint**

`internal/api/license_gate.go`:

```go
package api

import (
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/license"
)

// LicenseGate blocks all requests once the license is StateLocked, except
// the small allowlist needed to serve the lockout UI itself: the health
// check, the public license-status endpoint the frontend polls before
// login, and the static SPA shell (so the browser can load the JS that
// calls license-status and renders the lockout screen). See
// docs/superpowers/specs/2026-08-14-license-grace-period-design.md.
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
		gatedPrefixes := []string{"/api/", "/ws/", "/scim/", "/x/", "/login/"}
		for _, p := range gatedPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				jsonError(w, "license_locked", http.StatusPaymentRequired)
				return
			}
		}
		next.ServeHTTP(w, r) // anything else is the static SPA shell
	})
}
```

In `handlers.go`, add (near `GetLicenseInfo`):

```go
// GetLicenseStatus is public (no auth) — the frontend polls it before
// login to decide whether to render the normal app shell or the
// permanent lockout screen. Deliberately excludes customer/features
// (those stay behind auth in GetLicenseInfo) — only state + dates.
// GET /api/license/status
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

In `routes.go`, add `r.Use(LicenseGate)` immediately after `r.Use(middleware.StripSlashes)` (before the rate-limit variable declaration and before any route registration), and add the new route inside the existing "Public endpoints (no auth)" block:

```go
r.Get("/api/license/status", h.GetLicenseStatus)
```

In `rbac_matrix_test.go`, add to the `publicRoutes` map (matching the existing alignment style of that map exactly):

```go
"GET /api/license/status":                     true,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestLicenseGate -v`
Expected: PASS — all 4 test functions.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/api/license_gate.go internal/api/license_gate_test.go internal/api/routes.go internal/api/handlers.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add LicenseGate middleware and public GET /api/license/status"
git push
```

---

## Task 6: WebSocket upgrade gate

**Files:**
- Modify: `orchestrator/internal/api/routes.go` (`/ws/agent` handler around line 60-72, `/ws/browser` handler around line 76-87 — re-locate exact lines before editing)
- Test: extend `orchestrator/internal/api/license_gate_test.go` (from Task 5) with a router-level test rather than a unit test, since these handlers are inline closures in `routes.go`, not standalone methods

**Interfaces:**
- Consumes: `license.Current()`, `license.StateLocked` (Tasks 1-3); `Mount` (existing, `routes.go:19`).

- [ ] **Step 1: Write the failing test**

```go
func TestWSUpgrade_RejectedWhenLocked(t *testing.T) {
	h := New(sharedDB.Pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
	router := Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)

	license.SetInitial(license.Info{State: license.StateLocked})
	defer license.SetInitial(license.Info{})

	req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=test-agent", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("/ws/agent when locked: status = %d, want %d", rec.Code, http.StatusPaymentRequired)
	}
}
```

(This test only needs `sharedDB`, which the rest of this package's tests already set up via `TestMain`/`testmain_test.go` — no new test fixture required. If `New(...)`'s signature has drifted from what Task 5's tests already used, match whatever Task 5 actually compiled against.)

- [ ] **Step 2: Run test to verify it fails or passes vacuously**

Run: `cd orchestrator && go test ./internal/api/... -run TestWSUpgrade_RejectedWhenLocked -v`
Expected: this may already PASS if `LicenseGate`'s `/ws/` prefix check (Task 5) already covers it, since `LicenseGate` is mounted globally ahead of every route. If it passes already, that confirms the explicit per-handler check below is pure defense-in-depth — implement it anyway per the spec's instruction to prefer stating the guard explicitly at the WS entry points, but note in the commit message that `LicenseGate` was already sufficient.

- [ ] **Step 3: Add the explicit check to both WS handlers**

In the `/ws/agent` closure (`routes.go`), add at the very top, before the existing `agentSecret` check:

```go
if license.Current().State == license.StateLocked {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
```

In the `/ws/browser` closure, add the same check at the very top, before the existing `auth.TokenFromRequest` line. Add `"github.com/audspect/bas/internal/license"` to `routes.go`'s import block if not already present (it is not — `routes.go`'s current imports are `chi`, `chi/middleware`, `internal/auth`, `internal/exercise/tracker`, `internal/ws`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestWSUpgrade_RejectedWhenLocked -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/api/routes.go internal/api/license_gate_test.go
git commit -m "feat(api): explicit license-locked check on WS upgrade handlers (defense in depth)"
git push
```

---

## Task 7: `dispatchRun` license gate

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:1238` (top of `dispatchRun` — re-locate exact line before editing)
- Test: `orchestrator/internal/api/handlers_test.go` (or a new `dispatch_run_test.go` if `dispatchRun` already has a dedicated test file — check before creating a new one)

**Interfaces:**
- Consumes: `license.Current()`, `license.StateLocked` (Tasks 1-3); existing `dispatchRun(ctx, sc, agentID, o) (runID, skipReason string, err error)` signature (unchanged).

- [ ] **Step 1: Write the failing test**

First locate `dispatchRun`'s existing test coverage (grep `dispatchRun` in `internal/api/*_test.go`) to find the exact fixture pattern already used to call it directly (a real `*scenario.Scenario`, a seeded agent, etc. — mirror whatever an existing test for the "agent busy" skip path already sets up, since that's the closest analog).

```go
func TestDispatchRun_SkipsWhenLicenseLocked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		agentID := seedActiveAgent(t, pool) // reuse this package's existing helper

		license.SetInitial(license.Info{State: license.StateLocked})
		defer license.SetInitial(license.Info{})

		sc := minimalPostureScenario() // reuse this package's existing helper
		_, skipReason, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if skipReason != "license_locked" {
			t.Errorf("skipReason = %q, want %q", skipReason, "license_locked")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestDispatchRun_SkipsWhenLicenseLocked -v`
Expected: FAIL — `skipReason` will be whatever the existing agent-state/OS/concurrency checks produce (likely empty string, proceeding to actual dispatch), not `"license_locked"`.

- [ ] **Step 3: Add the gate**

At the very top of `dispatchRun`, before the existing `live := o.Mode == "telemetry" || o.Mode == "lab"` line:

```go
func (h *Handler) dispatchRun(ctx context.Context, sc *scenario.Scenario, agentID string, o dispatchOpts) (runID string, skipReason string, err error) {
	if license.Current().State == license.StateLocked {
		return "", "license_locked", nil
	}
	live := o.Mode == "telemetry" || o.Mode == "lab"
	// ... rest unchanged
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestDispatchRun_SkipsWhenLicenseLocked -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/api/handlers.go internal/api/handlers_test.go
git commit -m "feat(api): gate dispatchRun on license_locked — covers manual runs, campaigns, sweeps, scheduled assessments"
git push
```

---

## Task 8: `GetLicenseInfo` — surface real state to the authenticated Settings panel

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`GetLicenseInfo`, at line 460 — re-locate exact lines before editing)

**Interfaces:**
- Consumes: `license.Current()` (Tasks 1-3); existing `license.Get(h.licPath)` (unchanged).

- [ ] **Step 1: Write the failing test**

```go
func TestGetLicenseInfo_ReturnsRealStateAndGraceFields(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		license.SetInitial(license.Info{
			State:         license.StateGrace,
			DaysRemaining: 3,
			LockoutAt:     time.Date(2026, 8, 19, 23, 59, 59, 0, time.UTC),
		})
		defer license.SetInitial(license.Info{})

		req := httptest.NewRequest(http.MethodGet, "/api/license", nil)
		rec := httptest.NewRecorder()
		h.GetLicenseInfo(rec, req)

		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if body["status"] != "grace" {
			t.Errorf("status = %v, want %q", body["status"], "grace")
		}
		if body["daysRemaining"] != float64(3) {
			t.Errorf("daysRemaining = %v, want 3", body["daysRemaining"])
		}
		if body["lockoutAt"] == nil {
			t.Error("lockoutAt missing from response")
		}
	})
}
```

Note: this test requires a real license file at `h.licPath` for `license.Get` to succeed (the handler calls `license.Get` first and 404s on failure, per the existing code at `handlers.go:461-465`) — locate how existing tests in this package that exercise `GetLicenseInfo`-adjacent code (if any) provision `h.licPath`, or write a temp `.lic` file with `Customer`/`ExpiresAt`/valid-enough JSON for `license.Get`'s parse step (it does not re-verify the signature — see `license.go:93-106`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetLicenseInfo_ReturnsRealStateAndGraceFields -v`
Expected: FAIL — `status` is currently `license.Status(lic.ExpiresAt)`'s old three-way value derived from the license file's actual date, not `license.Current().State`; `daysRemaining`/`lockoutAt` are absent from the response entirely.

- [ ] **Step 3: Update the handler**

```go
func (h *Handler) GetLicenseInfo(w http.ResponseWriter, r *http.Request) {
	lic, err := license.Get(h.licPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	info := license.Current()
	respond(w, map[string]any{
		"customer":      lic.Customer,
		"customerId":    lic.CustomerID,
		"issuedAt":      lic.IssuedAt,
		"expiresAt":     lic.ExpiresAt,
		"features":      lic.Features,
		"status":        string(info.State),
		"daysRemaining": info.DaysRemaining,
		"lockoutAt":     info.LockoutAt.Format("2006-01-02"),
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetLicenseInfo_ReturnsRealStateAndGraceFields -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/api/handlers.go internal/api/handlers_test.go
git commit -m "feat(api): GetLicenseInfo surfaces real grace/lockout state and countdown"
git push
```

---

## Task 9: `main.go` wiring — seed initial state, start the monitor, wire `onLock` to the Hub

**Files:**
- Modify: `orchestrator/cmd/server/main.go` (two insertion points — re-locate exact current line numbers before editing: (a) immediately after the existing `license.Check(cfg.LicensePath)` block, currently around line 78-81; (b) immediately after `hub := ws.NewHub()`, currently around line 487)

**Interfaces:**
- Consumes: `license.Get`, `license.Evaluate`, `license.SetInitial`, `license.StartMonitor`, `license.StateLocked`, `license.StateGrace` (Tasks 1-3); `hub.CloseAllAgentConnections` (Task 4).

This task has no isolated unit test of its own — `main.go` is an entrypoint, not a package other tests import. Verification is: the orchestrator still builds and starts cleanly (Step 3 below), and the full test suite (which exercises every package this wiring touches) stays green (Task 10's final full-suite run covers this).

- [ ] **Step 1: Insert the initial-state seed right after the existing license check**

```go
	// ── License Check ─────────────────────────────────────────────────────
	if err := license.Check(cfg.LicensePath); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	lic, licErr := license.Get(cfg.LicensePath)
	if licErr != nil {
		log.Fatalf("[FATAL] %v", licErr) // Check() just verified this file parses; only reachable on a race with file deletion
	}
	initialLicenseInfo, licErr := license.Evaluate(lic, time.Now().UTC())
	if licErr != nil {
		log.Fatalf("[FATAL] %v", licErr)
	}
	license.SetInitial(initialLicenseInfo)
	switch initialLicenseInfo.State {
	case license.StateLocked:
		log.Printf("[license] LOCKED — grace period expired on %s. Serving lockout-only mode.", initialLicenseInfo.LockoutAt.Format(time.RFC3339))
	case license.StateGrace:
		log.Printf("[license] WARNING: in grace period — %d day(s) remaining before lockout on %s", initialLicenseInfo.DaysRemaining, initialLicenseInfo.LockoutAt.Format(time.RFC3339))
	}
```

(`time` is already imported in `main.go` — confirm before assuming.)

- [ ] **Step 2: Start the monitor right after `hub := ws.NewHub()`**

```go
	hub := ws.NewHub()
	licenseMonitorCtx, licenseMonitorCancel := context.WithCancel(context.Background())
	defer licenseMonitorCancel()
	license.StartMonitor(licenseMonitorCtx, cfg.LicensePath, 5*time.Minute, func() {
		hub.CloseAllAgentConnections()
	})
```

(`context` is already imported in `main.go`, used earlier for `db.Connect`'s timeout context — confirm the exact existing import alias/usage before assuming no conflict; use a distinctly-named `licenseMonitorCtx`/`licenseMonitorCancel` pair specifically to avoid shadowing any `ctx`/`cancel` already in scope from the earlier DB-connect block, which per the code read earlier this session are already declared and reused — do not reuse those names.)

- [ ] **Step 3: Verify the orchestrator builds and starts**

Run: `cd orchestrator && go build ./cmd/server/`
Expected: builds cleanly with no errors.

Run (manual smoke check, not automated): start the orchestrator against a dev Postgres with the placeholder `PublicKeyPEM = "KEYGEN_REQUIRED"` license bypass (per `license.go:43-46`, which still short-circuits `Check()` entirely — unaffected by this plan) and confirm the log lines from Step 1 do not appear (since `Check()`'s bypass path returns before ever reaching the new `license.Get`/`Evaluate` calls added in Step 1 — note this ordering: the `KEYGEN_REQUIRED` bypass in `Check()` returns `nil` immediately, so Step 1's `license.Get(cfg.LicensePath)` call still executes afterward and will likely fail if no `bas.lic` exists in dev. **Flag this as a real gap to resolve during implementation**: either skip Step 1's seeding when `license.PublicKeyPEM == "KEYGEN_REQUIRED"` (mirroring `Check()`'s own dev-mode bypass condition), or ensure dev environments always have a placeholder `.lic` file. Recommended: add the same `PublicKeyPEM == "KEYGEN_REQUIRED"` guard around Step 1's block, seeding `license.SetInitial(license.Info{State: license.StateValid})` unconditionally in that dev-only branch instead of calling `Get`/`Evaluate`.

- [ ] **Step 4: Apply the dev-mode guard found in Step 3**

```go
	if err := license.Check(cfg.LicensePath); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	if license.PublicKeyPEM == "KEYGEN_REQUIRED" {
		license.SetInitial(license.Info{State: license.StateValid})
	} else {
		lic, licErr := license.Get(cfg.LicensePath)
		if licErr != nil {
			log.Fatalf("[FATAL] %v", licErr)
		}
		initialLicenseInfo, licErr := license.Evaluate(lic, time.Now().UTC())
		if licErr != nil {
			log.Fatalf("[FATAL] %v", licErr)
		}
		license.SetInitial(initialLicenseInfo)
		switch initialLicenseInfo.State {
		case license.StateLocked:
			log.Printf("[license] LOCKED — grace period expired on %s. Serving lockout-only mode.", initialLicenseInfo.LockoutAt.Format(time.RFC3339))
		case license.StateGrace:
			log.Printf("[license] WARNING: in grace period — %d day(s) remaining before lockout on %s", initialLicenseInfo.DaysRemaining, initialLicenseInfo.LockoutAt.Format(time.RFC3339))
		}
	}
```

Re-run: `cd orchestrator && go build ./cmd/server/`
Expected: builds cleanly.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add cmd/server/main.go
git commit -m "feat(server): wire license state seeding, monitor, and agent-disconnect-on-lock into startup"
git push
```

---

## Task 10: Frontend — pre-login lockout screen, grace banner, session modal, Settings card update

**Files:**
- Modify: `orchestrator/wwwroot/index.html`:
  - The `DOMContentLoaded` listener at line 4795 (add the pre-login license-status check as its first statement)
  - Add new functions `renderLicenseLockedScreen(info)`, `renderLicenseGraceBanner(info)`, `maybeShowLicenseGraceModal(info)` (placed near `bootApp`, currently at line 4844)
  - `loadLicenseInfo()` at lines 16226-16257 (status badge/color logic + grace-countdown line)

This task has no Go test — it's manually verified in a browser per this project's established convention for frontend-only changes (see memory: frontend work is verified via `Pending Manual QA Backlog`, not automated). Steps below are implementation + manual verification, not TDD.

- [ ] **Step 1: Add the pre-login license-status check**

At the very top of the `DOMContentLoaded` listener body (`index.html:4795`), before the existing `document.getElementById('inp-pass')...` line:

```javascript
window.addEventListener('DOMContentLoaded', function() {
  fetch('/api/license/status').then(function(r) { return r.json(); }).then(function(info) {
    if (info.state === 'locked') {
      renderLicenseLockedScreen(info);
      return;
    }
    if (info.state === 'grace') {
      renderLicenseGraceBanner(info);
    }
    initLoginScreen();
  }).catch(function() {
    initLoginScreen(); // license-status endpoint unreachable — fail open to the normal login flow rather than stranding the operator
  });
});

function initLoginScreen() {
  document.getElementById('inp-pass').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') doLogin();
  });
  // If role is stored, attempt to resume session via cookie.
  // A 401 response means the cookie is expired — fall through to login screen.
  if (ROLE) {
    fetch('/api/agents', { credentials: 'same-origin' })
      .then(function(r) { if (r.ok) bootApp(); else { localStorage.removeItem('bas_role'); } })
      .catch(function() { localStorage.removeItem('bas_role'); });
  }
}
```

(This wraps the existing listener body in `initLoginScreen()`, called only when not locked — the rest of the original listener body moves into this new function unchanged.)

- [ ] **Step 2: Implement `renderLicenseLockedScreen`**

```javascript
function renderLicenseLockedScreen(info) {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'none';
  var el = document.createElement('div');
  el.id = 'license-locked-screen';
  el.style.cssText = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg,#0b0e14);z-index:9999;padding:2rem';
  el.innerHTML =
    '<div style="max-width:520px;text-align:center;color:var(--text,#e6e6e6)">' +
      '<div style="font-size:2.5rem;margin-bottom:1rem">&#x1F512;</div>' +
      '<h1 style="font-size:1.4rem;margin-bottom:0.75rem">BAS LICENSE EXPIRED</h1>' +
      '<p style="color:var(--muted,#9aa9bc);line-height:1.6;margin-bottom:1rem">This Audspect BAS installation is currently unavailable because its license and grace period have expired.</p>' +
      '<p style="color:var(--muted,#9aa9bc);line-height:1.6;margin-bottom:1.5rem">Please contact your licensing administrator to renew the license.</p>' +
      '<div style="font-size:0.85rem;color:var(--muted,#9aa9bc);margin-bottom:1.5rem">' +
        'License Expiry: ' + x(info.expiresAt) + '<br>' +
        'Access Disabled On: ' + x(info.lockoutAt) +
      '</div>' +
      '<a href="mailto:support@audspect.com" style="display:inline-block;padding:0.6rem 1.4rem;background:var(--danger,#da3633);color:#fff;border-radius:6px;text-decoration:none;font-weight:600">Contact Licensing Support</a>' +
    '</div>';
  document.body.appendChild(el);
}
```

(`x()` is this file's existing HTML-escaping helper, used throughout — e.g. `loadLicenseInfo` at line 16231 — confirm it's in scope/defined before this point in the file, which it will be since it's a top-level utility function used file-wide.)

- [ ] **Step 3: Implement `renderLicenseGraceBanner` and the once-per-session modal**

```javascript
function _licenseBannerHTML(info) {
  var dayWord = info.daysRemaining === 1 ? 'day' : 'days';
  var tomorrowNote = info.daysRemaining === 1 ? ' BAS access will be disabled tomorrow.' : '';
  return '<strong>&#x26A0;&#xFE0F; LICENSE EXPIRED — ACTION REQUIRED</strong><br>' +
    'Your Audspect BAS license expired on ' + x(info.expiresAt) + '. You are currently within the 5-day license grace period.<br>' +
    '<strong>Grace Period Remaining: ' + info.daysRemaining + ' ' + dayWord + '</strong><br>' +
    'The BAS platform will become inaccessible after the grace period expires. Please contact your Audspect administrator or licensing representative to renew your license.' + tomorrowNote + '<br>' +
    'License Expiry: ' + x(info.expiresAt) + ' &middot; Access Disabled On: ' + x(info.lockoutAt) + ' ' +
    '<a href="mailto:support@audspect.com" style="color:inherit;text-decoration:underline">[Contact Licensing Support]</a>';
}

function renderLicenseGraceBanner(info) {
  var existing = document.getElementById('license-grace-banner');
  if (existing) existing.remove();
  var el = document.createElement('div');
  el.id = 'license-grace-banner';
  el.style.cssText = 'position:relative;z-index:9998;padding:0.75rem 1.25rem;background:var(--warning,#d29922);color:#1a1200;font-size:0.85rem;line-height:1.5;text-align:center';
  el.innerHTML = _licenseBannerHTML(info);
  document.body.insertBefore(el, document.body.firstChild);
  maybeShowLicenseGraceModal(info);
}

function maybeShowLicenseGraceModal(info) {
  if (sessionStorage.getItem('bas_license_grace_modal_shown')) return;
  sessionStorage.setItem('bas_license_grace_modal_shown', '1');
  var overlay = document.createElement('div');
  overlay.id = 'license-grace-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);z-index:10000';
  overlay.innerHTML =
    '<div style="max-width:480px;background:var(--surface,#152338);border:1px solid var(--warning,#d29922);border-radius:8px;padding:1.5rem;color:var(--text,#e6e6e6)">' +
      _licenseBannerHTML(info) +
      '<div style="text-align:right;margin-top:1rem"><button id="license-grace-modal-dismiss" style="padding:0.4rem 1rem;border-radius:6px;border:1px solid var(--border,#22324a);background:transparent;color:inherit;cursor:pointer">Dismiss</button></div>' +
    '</div>';
  document.body.appendChild(overlay);
  document.getElementById('license-grace-modal-dismiss').addEventListener('click', function() {
    overlay.remove();
  });
}
```

Note: `renderLicenseGraceBanner` is called once from the pre-login flow (Step 1). It also needs to persist across `bootApp()`'s render (banner must appear "immediately after login" and "on the dashboard" per the spec, not just on the login screen) — call `renderLicenseGraceBanner(info)` again from inside `bootApp()` (line 4844 area) when the state is grace. Store the fetched `info` in a module-level variable (e.g. `var LICENSE_INFO = null;` near the other top-of-file state vars like `_targetMode` at line 4790) set inside the `DOMContentLoaded` fetch callback, so `bootApp()` can read it: `if (LICENSE_INFO && LICENSE_INFO.state === 'grace') renderLicenseGraceBanner(LICENSE_INFO);` as the first line of `bootApp()`.

- [ ] **Step 4: Update `loadLicenseInfo()`'s status badge for the 3-state model**

In `index.html:16232-16233` (re-locate exact lines before editing), replace:

```javascript
var statusColor = lic.status === 'valid' ? 'var(--success)' : lic.status === 'expiring_soon' ? 'var(--warning)' : 'var(--danger)';
var statusLabel = lic.status === 'valid' ? 'Active' : lic.status === 'expiring_soon' ? 'Expiring Soon' : lic.status === 'expired' ? 'Expired' : 'Unknown';
```

with:

```javascript
var statusColor = lic.status === 'valid' ? 'var(--success)' : lic.status === 'grace' ? 'var(--warning)' : lic.status === 'locked' ? 'var(--danger)' : 'var(--muted)';
var statusLabel = lic.status === 'valid' ? 'Active' : lic.status === 'grace' ? 'Grace Period' : lic.status === 'locked' ? 'Locked' : 'Unknown';
```

Add a grace-countdown row right after the existing `_licRow('Expires', ...)` line (currently `index.html:16246`):

```javascript
(lic.status === 'grace' ? _licRow('Grace Period', '<span style="color:var(--warning);font-weight:600">' + lic.daysRemaining + ' day(s) remaining — access disabled on ' + x(lic.lockoutAt) + '</span>') : '') +
```

- [ ] **Step 5: Manual browser verification**

Start the orchestrator in dev mode (placeholder license key, so `StateValid` is always seeded per Task 9's dev-mode branch). Confirm:
1. Login screen loads normally (no banner, no modal) — `StateValid` path unaffected.
2. Using browser devtools, temporarily stub the `/api/license/status` fetch response (or seed `license.SetInitial` to `StateGrace` via a debug build) to confirm the grace banner renders pre-login, the modal appears once per session (verify it does NOT reappear on a page refresh within the same tab, but DOES reappear after closing and reopening the tab / a fresh `sessionStorage`), and the banner persists after login on the dashboard and on the Settings → License page.
3. Stub `StateLocked` and confirm: the login form never renders, the full-screen lockout view appears with correct expiry/lockout dates, and the "Contact Licensing Support" link opens a mail client.

This step cannot be fully scripted — record the outcome in the PR/commit description as a manual QA note, consistent with this project's existing "Pending Manual QA Backlog" convention for frontend-only changes.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): add license grace-period banner/modal and permanent lockout screen"
git push
```

---

## Task 11: Full test suite verification

**Files:** none (verification-only task)

- [ ] **Step 1: Run the full orchestrator test suite in the background**

```bash
cd orchestrator
go test ./... > /tmp/full_suite_license_grace.log 2>&1 &
```

Use `run_in_background` via the Bash tool (not a literal `&`, which this shell doesn't reliably detach) — expected runtime 8-15 minutes, per this session's established convention for the full `internal/api` suite specifically (it includes container-backed tests via `sharedDB`).

- [ ] **Step 2: Wait for completion, then read the actual full log file**

Do not rely on a piped/truncated capture or a partial tail — this session hit two false alarms earlier from exactly that mistake. After the background-task completion notification arrives, read the complete `/tmp/full_suite_license_grace.log` file directly.

Expected: `ok` for every package, in particular `internal/license` (Tasks 1-3), `internal/ws` (Task 4), `internal/api` (Tasks 5-8) — including `TestRBACMatrix_NoDrift` (Task 5's `publicRoutes` addition) and every pre-existing `internal/api` test (none of which need any `license.SetInitial` seeding to pass, since an unseeded `Current()` returns a zero-value `Info{State: ""}`, which every gate in this plan treats as "not locked" — confirms the spec's flagged open question: no existing test fixtures need updating).

- [ ] **Step 3: If anything failed, fix and re-run before proceeding**

Do not commit on a red suite. Diagnose via the actual failure output in the log file, fix, and re-run Step 1-2 until green.

- [ ] **Step 4: No commit for this task** — it's verification-only; Task 10's commit (or a follow-up fixup commit, if Step 3 required changes) is the last commit of this plan.

---

## Self-Review Notes (already applied inline above)

- **Spec coverage:** every numbered component in the design spec (1. state machine, 2. runtime monitor, 3. main.go wiring, 4. HTTP enforcement, 5. WS enforcement, 6. dispatchRun gate, 7. frontend) maps to Tasks 1-2, 3, 9, 5, 6, 7, 10 respectively. The spec's "Check() must lose its expiry-fatal branch" correction (added during this session's spec self-review) is Task 2. All four "Open items for the plan to resolve" from the spec were resolved during this plan's fresh source reads: hub construction is at `main.go:487`, well after the license-check block (Task 9 places `StartMonitor` there, not earlier); `Hub` already has an `agents` map + `mu` to mirror (Task 4); the SPA boot sequence is the `DOMContentLoaded` listener at `index.html:4795` (Task 10); no existing test fixtures need `license.SetInitial` seeding (Task 11, confirmed by the zero-value-fails-open design).
- **Placeholder scan:** no TBD/TODO markers; the one deliberately-open decision (Task 9 Step 3's dev-mode license bypass interaction) is resolved inline in Step 4 of that same task, not left dangling.
- **Type consistency:** `Info`, `State`, `StateValid`/`StateGrace`/`StateLocked`, `Evaluate`, `SetInitial`, `Current`, `StartMonitor`, `CloseAllAgentConnections`, `LicenseGate`, `GetLicenseStatus` are each defined exactly once (Tasks 1, 3, 4, 5) and referenced identically (same names, same signatures) in every later task that consumes them.

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-08-14-license-grace-period.md`.

This session's established preference is **inline execution** (not subagent-driven) — say "go" to proceed with `superpowers:executing-plans` in this same session, or say "subagents" for the fresh-subagent-per-task approach instead.
