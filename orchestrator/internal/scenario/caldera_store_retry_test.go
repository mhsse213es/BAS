package scenario

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// abilitiesJSON is a minimal /api/v2/abilities payload with one indexable
// ability (psh executor + technique ID).
const abilitiesJSON = `[{"ability_id":"a1","name":"Test Ability","technique_id":"T1059.001",
  "tactic":"execution","privilege":"",
  "executors":[{"platform":"windows","name":"psh","command":"echo hi"}]}]`

// waitForLoad polls until the store reports loaded, or fails the test.
func waitForLoad(t *testing.T, s *CalderaStore, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if s.Loaded() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("store never loaded within %s", within)
}

// shortenCalderaRetry makes the background retry fast enough to test.
func shortenCalderaRetry(t *testing.T) {
	t.Helper()
	pi, pm := calderaRetryInitial, calderaRetryMax
	calderaRetryInitial, calderaRetryMax = 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { calderaRetryInitial, calderaRetryMax = pi, pm })
}

// The incident this fixes: on a cold boot the orchestrator's one-shot fetch
// raced ahead of Caldera, got connection refused, and the store stayed
// PERMANENTLY empty -- Caldera came up healthy ~90s later but nothing retried,
// so it took a manual orchestrator restart. Compose worked around it by making
// the orchestrator wait for Caldera to be healthy, which is why a reboot took
// ~10 minutes to bring the console back.
func TestNewCalderaStore_RetriesUntilCalderaIsUp(t *testing.T) {
	shortenCalderaRetry(t)

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail like a Caldera that is still loading its ability library.
		if atomic.AddInt32(&attempts, 1) <= 3 {
			http.Error(w, "starting up", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, abilitiesJSON)
	}))
	defer srv.Close()

	s := NewCalderaStore(srv.URL, "")

	// Must not block startup: the constructor returns before Caldera is ready.
	if s == nil {
		t.Fatal("NewCalderaStore returned nil")
	}
	waitForLoad(t, s, 5*time.Second)

	if got := s.GetAbilities("T1059.001"); len(got) != 1 {
		t.Errorf("GetAbilities after retry = %d abilities, want 1", len(got))
	}
	if n := atomic.LoadInt32(&attempts); n < 4 {
		t.Errorf("attempts = %d, want at least 4 (3 failures then a success)", n)
	}
}

// When Caldera is already up, the store must be populated by the time the
// constructor returns -- existing callers rely on that.
func TestNewCalderaStore_LoadsSynchronouslyWhenAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, abilitiesJSON)
	}))
	defer srv.Close()

	s := NewCalderaStore(srv.URL, "")
	if !s.Loaded() {
		t.Error("store must be loaded synchronously when Caldera answers immediately")
	}
	if got := s.GetAbilities("T1059.001"); len(got) != 1 {
		t.Errorf("GetAbilities = %d abilities, want 1", len(got))
	}
}

// Caldera not configured: no fetch, no retry goroutine, and the store stays a
// usable empty one (the soft off-state the rest of the integration expects).
func TestNewCalderaStore_UnconfiguredDoesNotRetry(t *testing.T) {
	s := NewCalderaStore("", "")
	if s == nil {
		t.Fatal("NewCalderaStore(\"\") returned nil")
	}
	if s.Loaded() {
		t.Error("an unconfigured store must not report itself loaded")
	}
	if got := s.GetAbilities("T1059.001"); got != nil {
		t.Errorf("GetAbilities on an unconfigured store = %v, want nil", got)
	}
}

// A store built from steps (tests, sweeps) is already populated and must never
// attempt a fetch.
func TestNewCalderaStoreFromSteps_IsLoaded(t *testing.T) {
	s := NewCalderaStoreFromSteps(map[string][]ScenarioStep{"T1059.001": {{TechniqueID: "T1059.001"}}})
	if !s.Loaded() {
		t.Error("a store built from steps must report loaded")
	}
}
