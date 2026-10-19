package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PH-CHN-004 creates and deletes a real calendar event, so it must not be executable
// until its side-effect review is complete. Registration is the gate, so it is absent.
func TestPHCHN004_NotRegistered(t *testing.T) {
	if _, ok := LookupPhishingRunExecutor("PH-CHN-004"); ok {
		t.Fatal("PH-CHN-004 is registered; it must stay out of executable discovery until its side-effect review")
	}
}

// Its capability reports catalog-only, never available, whatever calendar wiring exists.
func TestPHCHN004_CapabilityNeverAvailable(t *testing.T) {
	env := PhishingRunExecutorEnv{CalendarEventLure: &fakeCalendarLure{}, CalendarEventAllow: testCalendarAllow}
	c := phishingCapabilityFor(env, "PH-CHN-004", false)
	if c.Status == CapAvailable || c.Status == CapExperimental {
		t.Errorf("PH-CHN-004 status=%q; it must not be runnable", c.Status)
	}
}

// A crafted trigger cannot start it, and creates no run row.
func TestTriggerPhishingRun_PHCHN004RefusedWithNoRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, nil, nil, testJWTSecret)
		body := map[string]any{"scenarioId": "PH-CHN-004", "parameters": map[string]any{
			"organizerUserId": "organizer@contoso.example", "attendeeEmail": "a@contoso.example"}}
		rec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, body))
		if rec.Code == http.StatusCreated || rec.Code == http.StatusAccepted {
			t.Fatalf("trigger accepted PH-CHN-004 with status %d; it must be refused", rec.Code)
		}
		var rows int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM phishing_runs WHERE scenario_id = 'PH-CHN-004'`).Scan(&rows); err != nil {
			t.Fatalf("count runs: %v", err)
		}
		if rows != 0 {
			t.Errorf("%d PH-CHN-004 run row(s) created; want 0", rows)
		}
	})
}
