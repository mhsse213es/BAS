package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// seedSkipActor creates an actor threat and returns its id.
func seedSkipActor(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	var profile, threat string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ($1, '{}') RETURNING id`, name).Scan(&profile); err != nil {
		t.Fatalf("seed profile %s: %v", name, err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`, profile, name).Scan(&threat); err != nil {
		t.Fatalf("seed threat %s: %v", name, err)
	}
	return threat
}

func seedGenAttempt(t *testing.T, pool *pgxpool.Pool, threatID, outcome, reason string, ago time.Duration) {
	t.Helper()
	at := time.Now().Add(-ago)
	if _, err := pool.Exec(context.Background(), `INSERT INTO content_generation_attempts
		(cycle_id, threat_id, outcome, reason_code, generator_version, started_at)
		VALUES ('cyc', $1, $2, $3, '4', $4)`, threatID, outcome, reason, at); err != nil {
		t.Fatalf("seed attempt: %v", err)
	}
}

// The Threat-Intel category says which actors got no scenario because the connector gave them too few
// techniques, so a missing scenario is not read as missing intelligence or a broken connector. Only an actor's
// LATEST generator record counts: once it is generated, it is no longer listed.
func TestGetIntelSkippedActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		stillSkipped := seedSkipActor(t, pool, "UNC788")
		seedGenAttempt(t, pool, stillSkipped, "skipped", "below_min_techniques", time.Hour)

		nowGenerated := seedSkipActor(t, pool, "Recovered Actor")
		seedGenAttempt(t, pool, nowGenerated, "skipped", "below_min_techniques", 2*time.Hour)
		seedGenAttempt(t, pool, nowGenerated, "created", "ok", time.Hour)

		unchanged := seedSkipActor(t, pool, "Steady Actor")
		seedGenAttempt(t, pool, unchanged, "skipped", "already_registered", time.Hour)

		failed := seedSkipActor(t, pool, "Failing Actor")
		seedGenAttempt(t, pool, failed, "failed", "registrar_error", time.Hour)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetIntelSkippedActors(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/intel-skipped", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			MinTechniques int `json:"minTechniques"`
			Actors        []struct {
				Name   string `json:"name"`
				Reason string `json:"reason"`
			} `json:"actors"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		if out.MinTechniques != 2 {
			t.Errorf("minTechniques = %d, want 2", out.MinTechniques)
		}
		if len(out.Actors) != 1 || out.Actors[0].Name != "UNC788" || out.Actors[0].Reason != "below_min_techniques" {
			t.Fatalf("actors = %+v, want only UNC788 / below_min_techniques", out.Actors)
		}
	})
}

func TestGetIntelSkippedActors_NoneWhenNothingSkipped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetIntelSkippedActors(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/intel-skipped", nil))
		if rec.Code != http.StatusOK || !jsonHasEmptyActors(rec.Body.Bytes()) {
			t.Fatalf("status=%d body=%s, want 200 with an empty actors list (not null)", rec.Code, rec.Body.String())
		}
	})
}

func jsonHasEmptyActors(b []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	return string(m["actors"]) == "[]"
}
