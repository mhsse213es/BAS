package reporting

import (
	"strings"
	"testing"
)

func TestBrandingDefaultsAndFill(t *testing.T) {
	t.Cleanup(func() { SetBranding(Branding{}) }) // reset to defaults

	// Empty config → Audspect defaults.
	SetBranding(Branding{})
	if b := GetBranding(); b.ProductName != "Audspect BAS" || b.AccentColor != "#2563eb" {
		t.Errorf("empty branding should default, got %+v", b)
	}

	// Partial config fills only the empty fields.
	SetBranding(Branding{ProductName: "Acme SecOps"})
	b := GetBranding()
	if b.ProductName != "Acme SecOps" {
		t.Errorf("product name not applied: %+v", b)
	}
	if b.OrgName != "Audspect BAS" || b.AccentColor != "#2563eb" {
		t.Errorf("empty fields should fall back to defaults, got %+v", b)
	}
}

func TestBrandingViewLogo(t *testing.T) {
	t.Cleanup(func() { SetBranding(Branding{}) })

	// Default name keeps the two-tone styled logo.
	SetBranding(Branding{})
	if !strings.Contains(string(brandingView().LogoHTML), "<span>") {
		t.Error("default logo should be two-tone styled text")
	}
	// Custom name renders escaped plain text.
	SetBranding(Branding{ProductName: "Acme & Co <SecOps>"})
	logo := string(brandingView().LogoHTML)
	if strings.Contains(logo, "<SecOps>") || !strings.Contains(logo, "&amp;") {
		t.Errorf("custom logo should be HTML-escaped, got %q", logo)
	}
}

func TestBrandingUnsafeColorRejected(t *testing.T) {
	t.Cleanup(func() { SetBranding(Branding{}) })
	SetBranding(Branding{AccentColor: "red;} body{display:none"})
	if v := brandingView(); string(v.AccentCSS) != "#2563eb" {
		t.Errorf("unsafe color should fall back to default, got %q", v.AccentCSS)
	}
	SetBranding(Branding{AccentColor: "#ff8800"})
	if v := brandingView(); string(v.AccentCSS) != "#ff8800" {
		t.Errorf("valid hex color should pass through, got %q", v.AccentCSS)
	}
}

func TestBrandingAppliedToComplianceReport(t *testing.T) {
	t.Cleanup(func() { SetBranding(Branding{}) })
	SetBranding(Branding{ProductName: "Acme SecOps", OrgName: "Acme Security", AccentColor: "#ff8800"})
	cr := buildTestComplianceReport(t)
	var buf strings.Builder
	if err := RenderComplianceHTML(&buf, cr, ""); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Acme SecOps") {
		t.Error("custom product name not rendered in report")
	}
	if !strings.Contains(out, "Acme Security &middot; Confidential") {
		t.Error("custom org name not rendered in footer")
	}
	if !strings.Contains(out, "--accent:#ff8800") {
		t.Error("custom accent color not injected")
	}
}
