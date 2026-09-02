package reporting

import (
	"bytes"
	"context"
	"net"
	"net/url"
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

// Chrome's own DevTools HTTP handler rejects any request whose Host header
// isn't "localhost" or a literal IP (anti-DNS-rebinding check, no override
// flag) -- so a request already addressed by IP must pass through unchanged.
func TestResolveBaseToIP_AlreadyIPv4Unchanged(t *testing.T) {
	got := resolveBaseToIP("http://127.0.0.1:9222")
	if got != "http://127.0.0.1:9222" {
		t.Errorf("resolveBaseToIP(IPv4) = %q, want unchanged", got)
	}
}

func TestResolveBaseToIP_AlreadyIPv6Unchanged(t *testing.T) {
	got := resolveBaseToIP("http://[::1]:9222")
	if got != "http://[::1]:9222" {
		t.Errorf("resolveBaseToIP(IPv6) = %q, want unchanged", got)
	}
}

// A Docker Compose service name like "chrome" must resolve to an IP literal
// so Chrome's Host-header check accepts it -- "localhost" is used here as a
// hostname guaranteed resolvable in any test environment.
func TestResolveBaseToIP_HostnameResolves(t *testing.T) {
	got := resolveBaseToIP("http://localhost:9222")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("resolveBaseToIP returned unparseable URL %q: %v", got, err)
	}
	if u.Hostname() == "localhost" {
		t.Errorf("resolveBaseToIP(%q) = %q, host still a name, want an IP literal", "http://localhost:9222", got)
	}
	if net.ParseIP(u.Hostname()) == nil {
		t.Errorf("resolveBaseToIP(%q) = %q, host %q is not a valid IP literal", "http://localhost:9222", got, u.Hostname())
	}
	if u.Port() != "9222" {
		t.Errorf("resolveBaseToIP(%q) = %q, port = %q, want 9222 preserved", "http://localhost:9222", got, u.Port())
	}
}

// An unresolvable hostname (RFC 2606 reserved .invalid TLD, guaranteed never
// to resolve) must fall back to the original base unchanged -- so the
// existing reachability retry/fpdf-fallback path still applies to genuine
// outages instead of silently swallowing the failure here.
func TestResolveBaseToIP_UnresolvableFallsBackUnchanged(t *testing.T) {
	base := "http://this-host-does-not-exist.invalid:9222"
	got := resolveBaseToIP(base)
	if got != base {
		t.Errorf("resolveBaseToIP(unresolvable) = %q, want unchanged %q", got, base)
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
