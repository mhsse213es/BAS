package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func authedAdminReq(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	claims := &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}
	return req.WithContext(auth.ContextWithClaims(req.Context(), claims))
}

func TestCreateBackupJob_InsertsRequestedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "bkp-create-sc")
		h := New(pool, ws.NewHub(), engine, "")
		rec := httptest.NewRecorder()
		h.CreateBackupJob(rec, authedAdminReq(http.MethodPost, "/api/backups", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var id string
		var jobType, trigger, status, requestedBy string
		if err := pool.QueryRow(context.Background(),
			`SELECT id, job_type, trigger, status, requested_by FROM backup_jobs ORDER BY requested_at DESC LIMIT 1`,
		).Scan(&id, &jobType, &trigger, &status, &requestedBy); err != nil {
			t.Fatalf("query inserted row: %v", err)
		}
		if jobType != "backup" || trigger != "console" || status != "requested" || requestedBy != "admin-1" {
			t.Errorf("row = (%s, %s, %s, %s), want (backup, console, requested, admin-1)", jobType, trigger, status, requestedBy)
		}
	})
}

func TestListBackupJobs_ReturnsRequestedFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "bkp-list-sc")
		h := New(pool, ws.NewHub(), engine, "")
		h.CreateBackupJob(httptest.NewRecorder(), authedAdminReq(http.MethodPost, "/api/backups", nil))
		rec := httptest.NewRecorder()
		h.ListBackupJobs(rec, authedAdminReq(http.MethodGet, "/api/backups", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte(`"status":"requested"`)) {
			t.Errorf("body missing requested job: %s", rec.Body.String())
		}
	})
}
