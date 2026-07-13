package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func tamperHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func seedTamperEvent(t *testing.T, pool *pgxpool.Pool, id, path, eventType, severity string, acknowledged bool, detectedAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tamper_events (id, detected_at, path, event_type, severity, acknowledged)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, detectedAt, path, eventType, severity, acknowledged); err != nil {
		t.Fatalf("seed tamper_event: %v", err)
	}
}

func tamperReq(path, query string) *http.Request {
	if query != "" {
		path += "?" + query
	}
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func TestGetTamperEvents_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetTamperEvents(rec, tamperReq("/api/tamper-events", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out == nil || len(out) != 0 {
			t.Fatalf("out = %v, want empty (non-nil) array", out)
		}
	})
}

func TestGetTamperEvents_UnacknowledgedFilterAndOrdering(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedTamperEvent(t, pool, "te-old", "/opt/bas/binary", "write", "critical", false, t0)
		seedTamperEvent(t, pool, "te-new", "/opt/bas/config.yaml", "remove", "warning", false, t0.Add(1*time.Hour))
		seedTamperEvent(t, pool, "te-acked", "/opt/bas/other", "create", "warning", true, t0.Add(2*time.Hour))
		h := tamperHandler(t, pool)

		all := httptest.NewRecorder()
		h.GetTamperEvents(all, tamperReq("/api/tamper-events", ""))
		var allOut []struct {
			ID string `json:"id"`
		}
		json.Unmarshal(all.Body.Bytes(), &allOut)
		if len(allOut) != 3 {
			t.Fatalf("all: got %d events, want 3", len(allOut))
		}
		if allOut[0].ID != "te-acked" {
			t.Errorf("all[0].id = %q, want te-acked (most recent first)", allOut[0].ID)
		}

		unack := httptest.NewRecorder()
		h.GetTamperEvents(unack, tamperReq("/api/tamper-events", "unacknowledged=true"))
		var unackOut []struct {
			ID string `json:"id"`
		}
		json.Unmarshal(unack.Body.Bytes(), &unackOut)
		if len(unackOut) != 2 {
			t.Fatalf("unacknowledged: got %d events, want 2", len(unackOut))
		}
		if unackOut[0].ID != "te-new" || unackOut[1].ID != "te-old" {
			t.Errorf("unacknowledged order = %+v, want [te-new, te-old]", unackOut)
		}
	})
}

func TestAcknowledgeTamperEvent_MissingID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		rec := httptest.NewRecorder()
		h.AcknowledgeTamperEvent(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", ""))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestAcknowledgeTamperEvent_StampsAckerAndTimestamp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedTamperEvent(t, pool, "ate-ok", "/opt/bas/binary", "write", "warning", false, t0)
		uid := seedUser(t, pool, "ate-user", "pw-Password1!", "admin", true)
		h := tamperHandler(t, pool)

		req := authedRequest(t, http.MethodPost, "/api/tamper-events/ate-ok/ack", nil, auth.RoleAdmin, uid)
		req = withURLParam(req, "id", "ate-ok")
		rec := callAuthed(h.AcknowledgeTamperEvent, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var acked bool
		var ackedBy string
		var ackedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT acknowledged, COALESCE(acked_by,''), acked_at FROM tamper_events WHERE id='ate-ok'`,
		).Scan(&acked, &ackedBy, &ackedAt); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !acked || ackedBy != uid || ackedAt == nil {
			t.Fatalf("acknowledged=%v ackedBy=%q ackedAt=%v, want true/%s/non-nil", acked, ackedBy, ackedAt, uid)
		}
	})
}

// TestAcknowledgeTamperEvent_ClearsDispatchBlockedWhenLastCritical pins the
// integrity.DispatchBlocked reset: acknowledging the LAST unacknowledged
// critical event clears the global block; a remaining critical event keeps
// it set.
func TestAcknowledgeTamperEvent_ClearsDispatchBlockedWhenLastCritical(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedTamperEvent(t, pool, "adb-crit-1", "/opt/bas/binary", "write", "critical", false, t0)
		seedTamperEvent(t, pool, "adb-crit-2", "/opt/bas/agent", "write", "critical", false, t0.Add(1*time.Minute))
		uid := seedUser(t, pool, "adb-user", "pw-Password1!", "admin", true)
		h := tamperHandler(t, pool)
		integrity.DispatchBlocked.Store(true)
		t.Cleanup(func() { integrity.DispatchBlocked.Store(false) })

		ackOne := func(id string) *httptest.ResponseRecorder {
			req := authedRequest(t, http.MethodPost, "/api/tamper-events/"+id+"/ack", nil, auth.RoleAdmin, uid)
			req = withURLParam(req, "id", id)
			return callAuthed(h.AcknowledgeTamperEvent, req)
		}

		if rec := ackOne("adb-crit-1"); rec.Code != http.StatusOK {
			t.Fatalf("ack 1: status = %d", rec.Code)
		}
		if integrity.DispatchBlocked.Load() != true {
			t.Fatal("DispatchBlocked should remain true — one critical event is still unacknowledged")
		}

		if rec := ackOne("adb-crit-2"); rec.Code != http.StatusOK {
			t.Fatalf("ack 2: status = %d", rec.Code)
		}
		if integrity.DispatchBlocked.Load() != false {
			t.Fatal("DispatchBlocked should clear once the last critical event is acknowledged")
		}
	})
}

func TestAcknowledgeAllTamperEvents_MarksAllAcknowledged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedTamperEvent(t, pool, "aa-1", "/opt/bas/a", "write", "warning", false, t0)
		seedTamperEvent(t, pool, "aa-2", "/opt/bas/b", "write", "warning", false, t0)
		uid := seedUser(t, pool, "aa-user", "pw-Password1!", "admin", true)
		h := tamperHandler(t, pool)

		req := authedRequest(t, http.MethodPost, "/api/tamper-events/ack-all", nil, auth.RoleAdmin, uid)
		rec := callAuthed(h.AcknowledgeAllTamperEvents, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var unackedCount int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM tamper_events WHERE acknowledged=false`).Scan(&unackedCount)
		if unackedCount != 0 {
			t.Fatalf("unacknowledged count = %d, want 0", unackedCount)
		}
	})
}

// TestAcknowledgeAllTamperEvents_DoesNotClearDispatchBlocked characterizes a
// gap rather than an idealized behavior: unlike AcknowledgeTamperEvent,
// AcknowledgeAllTamperEvents never touches integrity.DispatchBlocked at all
// — so acknowledging every event via "Acknowledge All", including a critical
// one, leaves dispatch blocked. Flagged as a product finding, not fixed here
// — out of 3e.3's scope per the user's minimal-changes standing instruction.
func TestAcknowledgeAllTamperEvents_DoesNotClearDispatchBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedTamperEvent(t, pool, "nab-crit", "/opt/bas/binary", "write", "critical", false, t0)
		uid := seedUser(t, pool, "nab-user", "pw-Password1!", "admin", true)
		h := tamperHandler(t, pool)
		integrity.DispatchBlocked.Store(true)
		t.Cleanup(func() { integrity.DispatchBlocked.Store(false) })

		req := authedRequest(t, http.MethodPost, "/api/tamper-events/ack-all", nil, auth.RoleAdmin, uid)
		rec := callAuthed(h.AcknowledgeAllTamperEvents, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}

		var unackedCritical int
		pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM tamper_events WHERE acknowledged=false AND severity='critical'`).Scan(&unackedCritical)
		if unackedCritical != 0 {
			t.Fatalf("precondition failed: %d critical events still unacknowledged", unackedCritical)
		}
		if integrity.DispatchBlocked.Load() != true {
			t.Fatal("this test documents that DispatchBlocked stays true after Acknowledge All (see comment) — if this now fails, the product gap has been fixed and this test should be updated")
		}
	})
}
