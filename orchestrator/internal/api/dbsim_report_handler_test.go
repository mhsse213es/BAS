package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// No database is used, but the api package TestMain needs Docker; run on the
// Docker host: go test -count=1 -p 1 ./internal/api/ -run WriteDBSimRunReport
func TestWriteDBSimRunReportNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	writeDBSimRunReport(w, db.DBSimRun{}, db.ErrDBSimRunNotFound)
	if w.Code != http.StatusNotFound {
		t.Fatalf("code %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", w.Header())
	}
}

func TestWriteDBSimRunReportGenericInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	writeDBSimRunReport(w, db.DBSimRun{}, errors.New("pq: secret internals"))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "secret internals") {
		t.Fatalf("code %d body %q", w.Code, w.Body.String())
	}
}

func TestWriteDBSimRunReportOKHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	writeDBSimRunReport(w, db.DBSimRun{ID: "x", RunID: "r", Report: []byte(`{"schema":1,"result":"PASS","scenario":{"id":"s"}}`)}, nil)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("code %d headers %v", w.Code, w.Header())
	}
}
