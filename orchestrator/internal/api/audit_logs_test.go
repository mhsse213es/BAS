package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedAuditLog inserts an audit_logs row directly — auditLog/auditLogAs are
// fire-and-forget goroutines (see audit.go), so tests exercise GetAuditLogs'
// read side against deterministic seeded rows rather than racing the async
// write path.
func seedAuditLog(t *testing.T, pool *pgxpool.Pool, actorID, action, resource, outcome string, ts time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO audit_logs (ts, actor_id, action, resource, outcome) VALUES ($1,$2,$3,$4,$5)`,
		ts, actorID, action, resource, outcome); err != nil {
		t.Fatalf("seed audit_log: %v", err)
	}
}

func auditLogsReq(query string) *http.Request {
	path := "/api/audit-logs"
	if query != "" {
		path += "?" + query
	}
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func TestGetAuditLogs_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetAuditLogs(rec, auditLogsReq(""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			Entries []map[string]any `json:"entries"`
			Limit   int              `json:"limit"`
			Offset  int              `json:"offset"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Entries == nil || len(out.Entries) != 0 || out.Limit != 100 || out.Offset != 0 {
			t.Fatalf("out = %+v, want empty entries, limit=100, offset=0 (defaults)", out)
		}
	})
}

func TestGetAuditLogs_OrderingAndPagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		for i, action := range []string{"a1", "a2", "a3"} {
			seedAuditLog(t, pool, "", action, "res", "ok", t0.Add(time.Duration(i)*time.Minute))
		}
		h := tamperHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetAuditLogs(rec, auditLogsReq("limit=2"))
		var out struct {
			Entries []struct {
				Action string `json:"action"`
			} `json:"entries"`
			Limit int `json:"limit"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Limit != 2 || len(out.Entries) != 2 {
			t.Fatalf("out = %+v, want limit=2 with 2 entries", out)
		}
		if out.Entries[0].Action != "a3" || out.Entries[1].Action != "a2" {
			t.Fatalf("entries = %+v, want [a3, a2] (most recent first)", out.Entries)
		}

		rec2 := httptest.NewRecorder()
		h.GetAuditLogs(rec2, auditLogsReq("limit=2&offset=2"))
		var out2 struct {
			Entries []struct {
				Action string `json:"action"`
			} `json:"entries"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if len(out2.Entries) != 1 || out2.Entries[0].Action != "a1" {
			t.Fatalf("page 2 entries = %+v, want just [a1]", out2.Entries)
		}
	})
}

// TestGetAuditLogs_LimitValidation pins the limit param's guard: only 1..500
// is honored; anything else (0, negative, >500, non-numeric) silently falls
// back to the default of 100 rather than erroring.
func TestGetAuditLogs_LimitValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tamperHandler(t, pool)
		cases := []string{"limit=0", "limit=-5", "limit=501", "limit=notanumber"}
		for _, q := range cases {
			rec := httptest.NewRecorder()
			h.GetAuditLogs(rec, auditLogsReq(q))
			var out struct {
				Limit int `json:"limit"`
			}
			json.Unmarshal(rec.Body.Bytes(), &out)
			if out.Limit != 100 {
				t.Errorf("%s: limit = %d, want default 100", q, out.Limit)
			}
		}
	})
}

func TestGetAuditLogs_ActionFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedAuditLog(t, pool, "", "campaign.create", "res1", "ok", t0)
		seedAuditLog(t, pool, "", "campaign.stop", "res2", "ok", t0.Add(1*time.Minute))
		h := tamperHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetAuditLogs(rec, auditLogsReq("action=campaign.stop"))
		var out struct {
			Entries []struct {
				Action string `json:"action"`
			} `json:"entries"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Entries) != 1 || out.Entries[0].Action != "campaign.stop" {
			t.Fatalf("entries = %+v, want just [campaign.stop]", out.Entries)
		}
	})
}

func TestGetAuditLogs_ActorFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		uid := seedUser(t, pool, "gal-alice", "pw-Password1!", "admin", true)
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedAuditLog(t, pool, uid, "user.login", "res1", "ok", t0)
		seedAuditLog(t, pool, "", "system.job", "res2", "ok", t0.Add(1*time.Minute))
		h := tamperHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetAuditLogs(rec, auditLogsReq("actor=alice"))
		var out struct {
			Entries []struct {
				ActorName string `json:"actorName"`
				Action    string `json:"action"`
			} `json:"entries"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Entries) != 1 || out.Entries[0].Action != "user.login" || out.Entries[0].ActorName != "gal-alice" {
			t.Fatalf("entries = %+v, want just user.login by gal-alice", out.Entries)
		}
	})
}

// TestGetAuditLogs_ActorNameFallback pins the actor_name resolution: a
// system-initiated entry (actor_id=”) displays as "system"; a deleted
// user's entry (actor_id set, no matching users row) falls back to the raw
// actor_id.
func TestGetAuditLogs_ActorNameFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedAuditLog(t, pool, "", "system.job", "res1", "ok", t0)
		seedAuditLog(t, pool, "deleted-user-id-123", "user.login", "res2", "ok", t0.Add(1*time.Minute))
		h := tamperHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetAuditLogs(rec, auditLogsReq(""))
		var out struct {
			Entries []struct {
				ActorName string `json:"actorName"`
				Action    string `json:"action"`
			} `json:"entries"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Entries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(out.Entries))
		}
		if out.Entries[0].ActorName != "deleted-user-id-123" {
			t.Errorf("deleted-user entry actorName = %q, want the raw actor_id", out.Entries[0].ActorName)
		}
		if out.Entries[1].ActorName != "system" {
			t.Errorf("system entry actorName = %q, want system", out.Entries[1].ActorName)
		}
	})
}
