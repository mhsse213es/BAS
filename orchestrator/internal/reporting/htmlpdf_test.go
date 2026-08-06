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

func TestPrintToPDFParams_GeneratesDocumentOutline(t *testing.T) {
	p := printToPDFParams()
	if !p.GenerateDocumentOutline {
		t.Error("GenerateDocumentOutline = false, want true")
	}
	if !p.PrintBackground {
		t.Error("PrintBackground = false, want true (unchanged from before this refactor)")
	}
	if p.PaperWidth != 8.27 || p.PaperHeight != 11.69 {
		t.Errorf("paper size = %v x %v, want 8.27 x 11.69 (A4, unchanged from before this refactor)", p.PaperWidth, p.PaperHeight)
	}
}
