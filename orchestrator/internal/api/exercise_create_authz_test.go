package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

func countExerciseExecutions(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM exercise_executions`).Scan(&n); err != nil {
		t.Fatalf("count exercise_executions: %v", err)
	}
	return n
}

func TestCreateExerciseExecution_ViewerForbidden_NoRowCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("exercise-viewer", auth.RoleViewer, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		before := countExerciseExecutions(t, pool)
		req := httptest.NewRequest(http.MethodPost, "/api/exercises/executions", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %s, want 403 (viewer lacks CanLaunchExerciseExecution)", rec.Code, rec.Body.String())
		}
		if after := countExerciseExecutions(t, pool); after != before {
			t.Fatalf("exercise_executions rows %d -> %d; a denied create must insert nothing", before, after)
		}
	})
}

func TestCreateExerciseExecution_AnalystPassesGate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("exercise-analyst", auth.RoleAnalyst, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/exercises/executions", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Fatalf("status = %d, analyst holds CanLaunchExerciseExecution and must pass the gate", rec.Code)
		}
	})
}
