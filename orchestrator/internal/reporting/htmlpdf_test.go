package reporting

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// When the Chromium sidecar is not configured, PDFFromReport must fall back to
// the built-in fpdf renderer and still return a valid PDF — so the endpoint
// never breaks on deployments without the chrome service.
func TestPDFFromReportFallsBackWithoutChrome(t *testing.T) {
	os.Unsetenv("CHROME_WS_URL")
	var buf bytes.Buffer
	e := &Engine{}
	if err := e.PDFFromReport(context.Background(), &buf, campaignScopeReport(), nil, nil); err != nil {
		t.Fatalf("PDFFromReport fallback: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "%PDF-") {
		t.Errorf("fallback did not produce a PDF (prefix %q)", buf.String()[:min(8, buf.Len())])
	}
	if buf.Len() < 3000 {
		t.Errorf("fallback PDF suspiciously small: %d bytes", buf.Len())
	}
}
