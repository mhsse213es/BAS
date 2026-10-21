package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// The first-run setup endpoint refuses a password below the minimum before it touches the database.
func TestSetup_ShortPasswordRefused(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"email":"a@b.c","password":"short"}`))
	rec := httptest.NewRecorder()
	h.Setup(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short password: %d %s, want 400", rec.Code, rec.Body.String())
	}
}
