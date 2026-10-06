package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/threatidentity"
	"github.com/audspect/bas/internal/ws"
)

func resolutionRequest(method, id, query string, body any) *http.Request {
	rd := bytes.NewReader(nil)
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/x"+query, rd)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return withRole(req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx)), "admin1", auth.RoleAdmin)
}

// TCF Phase 2 spec §3.4: list the queue, decide once (audited), refuse a
// second decision, and map store errors to HTTP codes.
func TestActorResolutionAPI_DecideAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('A','{Panda}'), ('B','{Panda}')`); err != nil {
			t.Fatal(err)
		}
		res, err := threatidentity.NewStore(pool).ResolveAndPersist(ctx,
			threatidentity.Incoming{Name: "Panda", Sources: threatidentity.KeysFor("misp", "evt-1", "Panda")},
			threatidentity.ProfileFields{Source: "misp"})
		if err != nil || res.CandidateID == "" {
			t.Fatalf("seed candidate: %+v %v", res, err)
		}
		h := New(pool, ws.NewHub(), nil, "")

		rec := httptest.NewRecorder()
		h.ListActorResolutions(rec, resolutionRequest(http.MethodGet, "", "?status=unresolved", nil))
		var list struct {
			Items []threatidentity.Candidate `json:"items"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Items) != 1 || list.Items[0].ID != res.CandidateID {
			t.Fatalf("list: code=%d body=%s", rec.Code, rec.Body.String())
		}

		decide := func(id string, body any) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			h.DecideActorResolution(rec, resolutionRequest(http.MethodPost, id, "", body))
			return rec
		}
		if rec := decide(res.CandidateID, map[string]string{"action": "dismiss"}); rec.Code != http.StatusBadRequest {
			t.Fatalf("missing reason: code=%d body=%s", rec.Code, rec.Body.String())
		}
		rec = decide(res.CandidateID, map[string]string{"action": "dismiss", "decisionReason": "noise"})
		var got threatidentity.Candidate
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Status != "dismissed" ||
			got.DecidedBy == nil || *got.DecidedBy != "user:admin1" {
			t.Fatalf("dismiss: code=%d body=%s", rec.Code, rec.Body.String())
		}
		if rec := decide(res.CandidateID, map[string]string{"action": "dismiss", "decisionReason": "again"}); rec.Code != http.StatusConflict {
			t.Fatalf("second decision: code=%d", rec.Code)
		}
		if rec := decide("arc-missing", map[string]string{"action": "dismiss", "decisionReason": "x"}); rec.Code != http.StatusNotFound {
			t.Fatalf("missing candidate: code=%d", rec.Code)
		}

		// auditLog is asynchronous; wait briefly for the row.
		deadline := time.Now().Add(5 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'intel.actor_resolution.decide' AND resource = $1`,
				res.CandidateID).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit rows = %d, want 1", n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}
