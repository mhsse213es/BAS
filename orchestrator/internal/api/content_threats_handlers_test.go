package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/tcv"
	"github.com/audspect/bas/internal/ws"
)

func contentThreatsRequest(method, contentID, version string, body any) *http.Request {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/x", rd)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("contentId", contentID)
	rctx.URLParams.Add("n", version)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// TestLinkContentThreat_AdminLinksAlreadyExecutableCustomVersion exercises
// the full HTTP path for acceptance test 33: a grandfathered custom
// scenario is executable immediately (LOCAL_TRUSTED + PUBLISHED_LOCAL),
// so linking it must record the TCV stop within the same request.
func TestLinkContentThreat_AdminLinksAlreadyExecutableCustomVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e, reg, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "custom"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "custom", "link-test.yaml"), []byte("id: link-test\nname: G\nlocal_check: true\n"), 0o644)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		vs, err := reg.ListVersions(ctx, "link-test")
		if err != nil || len(vs) != 1 {
			t.Fatalf("ListVersions: %v %+v", err, vs)
		}

		var threatID string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('APT-link-handler', '{}') RETURNING id`).Scan(&threatID); err == nil {
			pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
				VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, 'APT-link-handler') RETURNING id`, threatID).Scan(&threatID)
		}

		h := New(pool, ws.NewHub(), e, "")
		req := withRole(contentThreatsRequest(http.MethodPost, "link-test", "1",
			map[string]string{"threatId": threatID, "reason": "confirmed emulation"}), "admin1", auth.RoleAdmin)
		rec := httptest.NewRecorder()
		h.LinkContentThreat(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}

		var coverageCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&coverageCount); err != nil {
			t.Fatal(err)
		}
		if coverageCount != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1", coverageCount)
		}
	})
}

func TestLinkContentThreat_UnknownVersionIs404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		h := New(pool, ws.NewHub(), e, "")
		req := withRole(contentThreatsRequest(http.MethodPost, "no-such-content", "1",
			map[string]string{"threatId": "thr-x", "reason": "x"}), "admin1", auth.RoleAdmin)
		rec := httptest.NewRecorder()
		h.LinkContentThreat(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code=%d, want 404", rec.Code)
		}
	})
}

func TestGetThreatTCV_NoClocksStartedReturnsNoClockForAllFour(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		var threatID string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('APT-tcv-handler', '{}') RETURNING id`).Scan(&threatID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
			VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, 'APT-tcv-handler') RETURNING id`, threatID).Scan(&threatID); err != nil {
			t.Fatal(err)
		}

		h := New(pool, ws.NewHub(), nil, "")
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", threatID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		h.GetThreatTCV(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		var m tcv.ThreatTCV
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		for name, metric := range map[string]tcv.Metric{
			"threatToEmulation": m.ThreatToEmulation, "threatToGeneration": m.ThreatToGeneration,
			"intelligenceToEmulation": m.IntelligenceToEmulation, "intelligenceToGeneration": m.IntelligenceToGeneration,
		} {
			if metric.State != tcv.StateNoClock {
				t.Errorf("%s.State = %q, want no_clock", name, metric.State)
			}
		}
	})
}
