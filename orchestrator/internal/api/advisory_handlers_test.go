package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/advisory"
	"github.com/audspect/bas/internal/auth"
	"github.com/go-chi/chi/v5"
)

// advisoryRouter mounts the decision routes behind the same permission gate
// the production router uses, so the tests exercise the real access rule.
func advisoryRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.With(auth.RequirePermission(auth.CanDecideAdvisoryRelevance)).Post("/api/advisories/{id}/decision", h.DecideAdvisory)
	r.With(auth.RequirePermission(auth.CanDecideAdvisoryRelevance)).Post("/api/advisories/{id}/reverse", h.ReverseAdvisoryDecision)
	return r
}

func postDecision(t *testing.T, h http.Handler, claims *auth.Claims, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if claims != nil {
		req = req.WithContext(auth.ContextWithClaims(context.Background(), claims))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdvisoryDecisionRequiresPermission(t *testing.T) {
	h := &Handler{}
	h.WithAdvisoryStore(advisory.NewStore(nil))
	router := advisoryRouter(h)
	body := `{"decision":"relevant"}`

	if rec := postDecision(t, router, nil, "/api/advisories/a1/decision", body); rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
		t.Errorf("no claims: status %d, want 401 or 403", rec.Code)
	}
	viewer := &auth.Claims{UserID: "v1", Role: auth.RoleViewer}
	if rec := postDecision(t, router, viewer, "/api/advisories/a1/decision", body); rec.Code != http.StatusForbidden {
		t.Errorf("viewer: status %d, want 403", rec.Code)
	}
}

func TestAdvisoryDecisionRejectsBadInputBeforeStorage(t *testing.T) {
	h := &Handler{}
	h.WithAdvisoryStore(advisory.NewStore(nil))
	router := advisoryRouter(h)
	analyst := &auth.Claims{UserID: "a1", Role: auth.RoleAnalyst}

	cases := map[string]string{
		"exclusion without code":   `{"decision":"excluded"}`,
		"exclusion with free text": `{"decision":"excluded","reasonCode":"not sure"}`,
		"relevant with a code":     `{"decision":"relevant","reasonCode":"relevance"}`,
		"unknown decision":         `{"decision":"maybe"}`,
		"malformed JSON":           `{"decision":`,
	}
	for name, body := range cases {
		rec := postDecision(t, router, analyst, "/api/advisories/a1/decision", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", name, rec.Code, rec.Body.String())
		}
	}
}

func TestAdvisoryDecisionNeedsAuthenticatedUserID(t *testing.T) {
	h := &Handler{}
	h.WithAdvisoryStore(advisory.NewStore(nil))
	router := advisoryRouter(h)
	anon := &auth.Claims{UserID: "", Role: auth.RoleAnalyst}
	rec := postDecision(t, router, anon, "/api/advisories/a1/decision", `{"decision":"relevant"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("empty user id: status %d, want 401", rec.Code)
	}
}

func TestAdvisoryDecisionUnavailableWithoutStore(t *testing.T) {
	h := &Handler{}
	router := advisoryRouter(h)
	analyst := &auth.Claims{UserID: "a1", Role: auth.RoleAnalyst}
	rec := postDecision(t, router, analyst, "/api/advisories/a1/decision", `{"decision":"relevant"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no store: status %d, want 503", rec.Code)
	}
}
