package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A crafted request cannot start an identity scenario, even with an allowlist set
// and targets inside it. The capability gate refuses it first, so no run row is created.
func TestTriggerPhishingRun_IdentityScenariosRefusedWithNoRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t.Setenv(EnvPhishIdentityTargetUsers, "alice@contoso.example")
		t.Setenv(EnvPhishOAuthSPObjectIDs, goodClientGUID)
		h := New(pool, nil, nil, testJWTSecret)

		cases := map[string]map[string]any{
			"PH-ID-003 out of scope": {"scenarioId": "PH-ID-003", "parameters": map[string]any{"userIds": []any{"bob@contoso.example"}}},
			"PH-ID-003 in scope":     {"scenarioId": "PH-ID-003", "parameters": map[string]any{"userIds": []any{"alice@contoso.example"}}},
			"PH-ID-002 out of scope": {"scenarioId": "PH-ID-002", "parameters": map[string]any{"runId": "r1", "clientIds": []any{otherClientGUID}}},
			"PH-ID-002 in scope":     {"scenarioId": "PH-ID-002", "parameters": map[string]any{"runId": "r1", "clientIds": []any{goodClientGUID}}},
		}
		for name, body := range cases {
			rec := callAuthed(h.TriggerPhishingRun, triggerPhishingRunReq(t, pool, body))
			if rec.Code == http.StatusCreated {
				t.Errorf("%s: trigger accepted a request for an unavailable identity scenario", name)
			}
		}
		var rows int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM phishing_runs WHERE scenario_id LIKE 'PH-ID-00%'`).Scan(&rows); err != nil {
			t.Fatalf("count runs: %v", err)
		}
		if rows != 0 {
			t.Errorf("%d identity run row(s) created by direct requests; want 0", rows)
		}
	})
}
