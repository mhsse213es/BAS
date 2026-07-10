package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHasPermission_FullMatrix(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		{RoleAdmin, CanVerify, true},
		{RoleAdmin, CanUploadEvidence, true},
		{RoleAdmin, CanDeleteEvidence, true},
		{RoleAdmin, CanReview, true},
		{RoleAdmin, CanExport, true},
		{RoleAdmin, CanCurateThreatIntel, true},
		{RoleAdmin, CanReviewThreatIntel, true},

		{RoleAnalyst, CanVerify, true},
		{RoleAnalyst, CanUploadEvidence, true},
		{RoleAnalyst, CanDeleteEvidence, false}, // withheld: accountability
		{RoleAnalyst, CanReview, true},
		{RoleAnalyst, CanExport, true},
		{RoleAnalyst, CanCurateThreatIntel, true},
		{RoleAnalyst, CanReviewThreatIntel, false}, // withheld: no self-approval

		{RoleViewer, CanVerify, false},
		{RoleViewer, CanUploadEvidence, false},
		{RoleViewer, CanDeleteEvidence, false},
		{RoleViewer, CanReview, false},
		{RoleViewer, CanExport, false},
		{RoleViewer, CanCurateThreatIntel, false},
		{RoleViewer, CanReviewThreatIntel, false},
	}
	for _, tc := range cases {
		if got := HasPermission(tc.role, tc.perm); got != tc.want {
			t.Errorf("HasPermission(%s, %s) = %v, want %v", tc.role, tc.perm, got, tc.want)
		}
	}
}

// TestHasPermission_MatrixIsComplete guards against a new Permission
// constant being added without a corresponding row above: it fails loudly
// if the tested set diverges from the set of permissions admin actually
// holds (admin currently holds every defined permission — see
// rolePermissions in permissions.go). A permission added but NOT granted
// to admin would not trip this check; that's an inherent limitation of Go
// having no enum reflection, not something this test can close.
func TestHasPermission_MatrixIsComplete(t *testing.T) {
	tested := map[Permission]bool{
		CanVerify: true, CanUploadEvidence: true, CanDeleteEvidence: true,
		CanReview: true, CanExport: true, CanCurateThreatIntel: true, CanReviewThreatIntel: true,
	}
	for _, p := range Permissions(RoleAdmin) {
		if !tested[p] {
			t.Errorf("permission %q is granted to admin but has no row in TestHasPermission_FullMatrix", p)
		}
	}
	if len(tested) != len(Permissions(RoleAdmin)) {
		t.Errorf("tested %d permissions, admin holds %d — counts diverged", len(tested), len(Permissions(RoleAdmin)))
	}
}

func TestPermissions_Ordering(t *testing.T) {
	got := Permissions(RoleAdmin)
	want := []Permission{CanVerify, CanUploadEvidence, CanDeleteEvidence, CanReview, CanExport, CanCurateThreatIntel, CanReviewThreatIntel}
	if len(got) != len(want) {
		t.Fatalf("Permissions(RoleAdmin) len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Permissions(RoleAdmin)[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if got := Permissions(RoleViewer); len(got) != 0 {
		t.Fatalf("Permissions(RoleViewer) = %v, want empty", got)
	}
}

func TestRequirePermission_GrantedDeniedNoClaims(t *testing.T) {
	adminTok, _ := GenerateToken("a1", RoleAdmin, "secret", time.Hour)
	viewerTok, _ := GenerateToken("v1", RoleViewer, "secret", time.Hour)

	newHandler := func() (http.Handler, *bool) {
		called := false
		h := RequirePermission(CanDeleteEvidence)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		return h, &called
	}

	// Granted: admin holds CanDeleteEvidence.
	h, called := newHandler()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	rec := httptest.NewRecorder()
	Middleware("secret")(h).ServeHTTP(rec, req)
	if !*called || rec.Code != http.StatusOK {
		t.Fatalf("granted case: called=%v status=%d", *called, rec.Code)
	}

	// Denied: viewer holds no permissions.
	h, called = newHandler()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Authorization", "Bearer "+viewerTok)
	rec = httptest.NewRecorder()
	Middleware("secret")(h).ServeHTTP(rec, req)
	if *called || rec.Code != http.StatusForbidden {
		t.Fatalf("denied case: called=%v status=%d, want called=false status=403", *called, rec.Code)
	}

	// No claims at all (RequirePermission invoked with no Middleware in front).
	h, called = newHandler()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if *called || rec.Code != http.StatusForbidden {
		t.Fatalf("no-claims case: called=%v status=%d, want called=false status=403", *called, rec.Code)
	}
}
