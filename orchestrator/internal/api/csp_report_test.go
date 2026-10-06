package api

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/time/rate"
)

func postCSP(t *testing.T, ct, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	req := httptest.NewRequest(http.MethodPost, "/api/csp-report", strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	(&Handler{}).CSPReport(rec, req)
	return rec, buf.String()
}

func freshCSPLimiter(t *testing.T, burst int) {
	t.Helper()
	prev := cspReportLimiter
	cspReportLimiter = rate.NewLimiter(0, burst)
	cspReportsDropped.Store(0)
	t.Cleanup(func() { cspReportLimiter = prev; cspReportsDropped.Store(0) })
}

const legacyReport = `{"csp-report":{"document-uri":"https://bas.local/","violated-directive":"script-src-attr","effective-directive":"script-src-attr","blocked-uri":"inline","source-file":"https://bas.local/assets/app.X.js","line-number":12}}`

func TestCSPReport_LegacyFormatIsLogged(t *testing.T) {
	freshCSPLimiter(t, 10)
	rec, logs := postCSP(t, "application/csp-report", legacyReport)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	for _, want := range []string{"[csp] violation", `directive="script-src-attr"`, `blocked="inline"`, "line=12"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log missing %q: %s", want, logs)
		}
	}
}

func TestCSPReport_ReportingAPIFormatIsLogged(t *testing.T) {
	freshCSPLimiter(t, 10)
	body := `[{"type":"csp-violation","body":{"documentURL":"https://bas.local/","effectiveDirective":"font-src","blockedURL":"https://fonts.gstatic.com/x.woff2","sourceFile":"","lineNumber":0}},{"type":"deprecation","body":{}}]`
	rec, logs := postCSP(t, "application/reports+json", body)
	if rec.Code != http.StatusNoContent || strings.Count(logs, "[csp] violation") != 1 || !strings.Contains(logs, `directive="font-src"`) {
		t.Fatalf("status=%d logs=%s", rec.Code, logs)
	}
}

func TestCSPReport_RejectsOtherContentTypes(t *testing.T) {
	for _, ct := range []string{"application/json", "text/plain", ""} {
		if rec, _ := postCSP(t, ct, legacyReport); rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%q: status = %d, want 415", ct, rec.Code)
		}
	}
}

func TestCSPReport_RejectsOversizedBody(t *testing.T) {
	big := `{"csp-report":{"blocked-uri":"` + strings.Repeat("a", 20<<10) + `"}}`
	if rec, _ := postCSP(t, "application/csp-report", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestCSPReport_RejectsMalformedJSON(t *testing.T) {
	if rec, _ := postCSP(t, "application/csp-report", `{"csp-report":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCSPReport_LogIsSanitized(t *testing.T) {
	freshCSPLimiter(t, 10)
	body := `{"csp-report":{"blocked-uri":"x\nFAKE LOG LINE\r\u0007` + strings.Repeat("b", 400) + `","effective-directive":"img-src"}}`
	_, logs := postCSP(t, "application/csp-report", body)
	if strings.Count(logs, "\n") != 1 {
		t.Fatalf("report produced %d log lines, want 1: %q", strings.Count(logs, "\n"), logs)
	}
	if strings.Contains(logs, "\a") || strings.Contains(logs, strings.Repeat("b", 300)) {
		t.Fatalf("control character or untruncated field in log: %q", logs)
	}
}

func TestCSPReport_FloodIsDroppedAndCounted(t *testing.T) {
	freshCSPLimiter(t, 2)
	var all string
	for i := 0; i < 5; i++ {
		_, logs := postCSP(t, "application/csp-report", legacyReport)
		all += logs
	}
	if n := strings.Count(all, "[csp] violation"); n != 2 {
		t.Fatalf("logged %d reports, want 2 (burst)", n)
	}
	if got := cspReportsDropped.Load(); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
}
