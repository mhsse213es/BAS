package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A render that fails partway must produce a clean error response, not a
// truncated document under a 200.
//
// This is the exact shape that hid a real bug: every report handler passed the
// http.ResponseWriter straight to the renderer, and html/template streams as it
// executes. The exercise report aborted at .Execution.Status for its whole
// lifetime, yet every request returned 200 with a valid-looking partial page,
// so a handler test asserting "200 and contains <html>" passed throughout.
func TestWriteBufferedReport_PartialRenderFailureIsCleanError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBufferedReport(rec, "text/html; charset=utf-8", "", "test report",
		func(out io.Writer) error {
			// Write a convincing prefix first, exactly as a streaming template
			// does before it hits a bad field.
			_, _ = io.WriteString(out, "<!doctype html><html><body><h1>Report</h1>")
			return errors.New("template: wrong type for value")
		})

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 — a failed render must not report success", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("partial document leaked to the client:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "wrong type for value") {
		t.Errorf("error body does not carry the render failure: %q", rec.Body.String())
	}
}

// The success path must send the document unchanged, with the headers the
// caller asked for and a real Content-Length (so a browser gets a determinate
// download rather than a stream that can simply stop early).
func TestWriteBufferedReport_SuccessSendsDocumentAndHeaders(t *testing.T) {
	const doc = "<!doctype html><html><body>complete</body></html>"

	rec := httptest.NewRecorder()
	writeBufferedReport(rec, "text/html; charset=utf-8", `attachment; filename="r.html"`, "test report",
		func(out io.Writer) error {
			_, err := io.WriteString(out, doc)
			return err
		})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != doc {
		t.Errorf("body = %q, want %q", got, doc)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="r.html"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(doc)) {
		t.Errorf("Content-Length = %q, want %d", got, len(doc))
	}
}

// No Content-Disposition when the caller passes none — an inline HTML report
// must not acquire a spurious download header.
func TestWriteBufferedReport_OmitsEmptyDisposition(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBufferedReport(rec, "text/html; charset=utf-8", "", "test report",
		func(out io.Writer) error { _, err := io.WriteString(out, "ok"); return err })

	if got := rec.Header().Get("Content-Disposition"); got != "" {
		t.Errorf("Content-Disposition = %q, want none", got)
	}
}
