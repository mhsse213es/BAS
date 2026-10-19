package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
	"github.com/audspect/bas/internal/ws"
)

func mountTestRouterWithVerification(pool *pgxpool.Pool, t *testing.T) http.Handler {
	t.Helper()
	h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
		WithVerificationStore(verification.NewStore(pool))
	return Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)
}

// Evidence rows have no foreign key to their verification, so an evidence
// row can outlive or predate its parent. Such a row must not be served.
func TestDownloadEvidence_OrphanedEvidence_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		ev, err := verification.NewStore(pool).AddEvidence(ctx, verification.EvidenceInput{
			VerificationID: "no-such-verification", OriginalFilename: "orphan.txt", Bytes: []byte("secret"),
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		router := mountTestRouterWithVerification(pool, t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("evidence-analyst", auth.RoleAnalyst, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/evidence/"+ev.ID+"/download", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 for evidence with no parent verification", rec.Code)
		}
		if rec.Body.String() == "secret" {
			t.Fatal("orphaned evidence bytes were served")
		}
	})
}

func TestDownloadEvidence_AuthorizedParent_Served(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := verification.NewStore(pool)
		rec0, err := store.Attest(ctx, verification.AttestInput{
			RunID: "run-evidence-1", ExpectationID: "exp-1", ProfileName: "p", ProfileVersion: 1,
			TechniqueID: "T1059", Domain: "endpoint", Provider: "test", Result: "pass",
			Source: "test", VerifiedBy: "tester",
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		ev, err := store.AddEvidence(ctx, verification.EvidenceInput{
			VerificationID: rec0.ID, OriginalFilename: "ok.txt", Bytes: []byte("payload"),
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		router := mountTestRouterWithVerification(pool, t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("evidence-viewer", auth.RoleViewer, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/evidence/"+ev.ID+"/download", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s; a viewer must download evidence whose parent verification exists", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != "payload" {
			t.Fatalf("body = %q, want the stored bytes", rec.Body.String())
		}
	})
}

func TestDownloadEvidence_Unauthenticated_401(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouterWithVerification(pool, t)
		req := httptest.NewRequest(http.MethodGet, "/api/evidence/any-id/download", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}
