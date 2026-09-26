package reporting

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/models"
)

// buildTestComplianceReport produces a real ComplianceReport via the actual
// mapper (embedded framework YAMLs) so the renderer is exercised against the
// genuine data shape, not a hand-built stub.
func buildTestComplianceReport(t *testing.T) *compliance.ComplianceReport {
	t.Helper()
	m, err := compliance.NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	fws := m.Frameworks()
	if len(fws) == 0 {
		t.Fatal("no frameworks loaded")
	}
	// Feed a mix of pass/fail results so the report has both statuses. The
	// technique IDs need not all map — the mapper simply records what overlaps.
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping"}, Result: models.ResultFail,
			ThreatImpact: "Credentials exposed", Remediation: "Enable Credential Guard"},
		{Technique: models.AttackTechnique{ID: "T1059", Name: "Command and Scripting Interpreter"}, Result: models.ResultPass},
		{Technique: models.AttackTechnique{ID: "T1071", Name: "Application Layer Protocol"}, Result: models.ResultFail,
			Remediation: "Inspect egress traffic"},
		{Technique: models.AttackTechnique{ID: "T1053", Name: "Scheduled Task/Job"}, Result: models.ResultPass},
	}
	cr, err := m.GenerateReport(results, fws[0].ID, "WIN-TEST-01", "", "Unit Test Scenario")
	if err != nil {
		t.Fatalf("GenerateReport(%s): %v", fws[0].ID, err)
	}
	return cr
}

func TestRenderComplianceHTML(t *testing.T) {
	cr := buildTestComplianceReport(t)

	var buf bytes.Buffer
	if err := RenderComplianceHTML(&buf, cr, "analyst@bank.example"); err != nil {
		t.Fatalf("RenderComplianceHTML: %v", err)
	}
	out := buf.String()

	// Structural sanity: it is a complete HTML document.
	for _, want := range []string{"<!DOCTYPE html>", "</html>", "Regulatory Compliance Report"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	// The framework name from the real mapper must appear.
	if cr.Framework.Name != "" && !strings.Contains(out, cr.Framework.Name) {
		t.Errorf("output missing framework name %q", cr.Framework.Name)
	}
	// The per-control detail section and its column headers must render — the
	// whole point of P0-1 (detail that was previously CSV/JSON-only).
	for _, want := range []string{"Control Detail", "Domain Breakdown", "Compliance (passing / tested)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing section %q", want)
		}
	}
	// At least one control ID from the framework must appear.
	if len(cr.Controls) == 0 {
		t.Fatal("mapper returned no controls")
	}
	if !strings.Contains(out, cr.Controls[0].ID) {
		t.Errorf("output missing first control id %q", cr.Controls[0].ID)
	}
	// A status pill label must be present.
	if !strings.Contains(out, "PASSING") && !strings.Contains(out, "FAILING") &&
		!strings.Contains(out, "UNTESTED") && !strings.Contains(out, "MANUAL ATTESTATION") {
		t.Error("output has no status pill labels")
	}
}

func TestRenderComplianceHTML_Nil(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderComplianceHTML(&buf, nil, ""); err == nil {
		t.Error("expected error for nil report, got nil")
	}
}

// TestRenderComplianceHTML_Attestation verifies the tamper-evidence block (P0-2)
// renders and reflects whether signing is enabled.
func TestRenderComplianceHTML_Attestation(t *testing.T) {
	cr := buildTestComplianceReport(t)

	// Signed path.
	SetSigningSecret("unit-test-deployment-secret-key-32bytes!!")
	t.Cleanup(func() { SetSigningSecret("") })
	var signed bytes.Buffer
	if err := RenderComplianceHTML(&signed, cr, "analyst@bank.example"); err != nil {
		t.Fatal(err)
	}
	s := signed.String()
	if !strings.Contains(s, "HMAC-SHA256") {
		t.Error("signed report should advertise HMAC-SHA256")
	}
	if !strings.Contains(s, "Digest (SHA-256)") {
		t.Error("report missing SHA-256 digest line")
	}
	if !strings.Contains(s, "analyst@bank.example") {
		t.Error("report missing generator identity")
	}

	// Unsigned path (no key) still emits a digest, no signature.
	SetSigningSecret("")
	var unsigned bytes.Buffer
	if err := RenderComplianceHTML(&unsigned, cr, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unsigned.String(), "SHA-256 (unsigned)") {
		t.Error("unsigned report should say SHA-256 (unsigned)")
	}
}

// TestAttestationSignAndVerify checks the HMAC attestation round-trips and that
// tampering with the content is detected.
func TestAttestationSignAndVerify(t *testing.T) {
	SetSigningSecret("deployment-secret-for-attestation-tests!")
	t.Cleanup(func() { SetSigningSecret("") })

	att := Attest([]byte("hello report"), "user-123")
	if att.Algorithm != "HMAC-SHA256" || att.Signature == "" {
		t.Fatalf("expected signed attestation, got %+v", att)
	}
	ok, err := att.Verify()
	if err != nil || !ok {
		t.Fatalf("Verify failed: ok=%v err=%v", ok, err)
	}
	// Tamper: a different digest must fail verification.
	tampered := att
	tampered.ContentSHA256 = strings.Repeat("0", 64)
	if ok, _ := tampered.Verify(); ok {
		t.Error("tampered attestation verified as valid")
	}
}

// TestBuildManifest checks the manifest is sha256sum-compatible and sorted.
func TestBuildManifest(t *testing.T) {
	out := string(BuildManifest([]ManifestEntry{
		{Path: "z.json", SHA256: "bbb"},
		{Path: "a.txt", SHA256: "aaa"},
	}))
	if !strings.HasPrefix(out, "aaa  a.txt\n") {
		t.Errorf("manifest not sorted / wrong format:\n%s", out)
	}
	if !strings.Contains(out, "bbb  z.json") {
		t.Errorf("manifest missing entry:\n%s", out)
	}
}

// TestRenderCompliancePDF_NoSidecar verifies the PDF path fails cleanly (so the
// handler can fall back to HTML) when the Chrome sidecar is not configured,
// rather than panicking.
func TestRenderCompliancePDF_NoSidecar(t *testing.T) {
	t.Setenv("CHROME_WS_URL", "")
	cr := buildTestComplianceReport(t)
	var buf bytes.Buffer
	if err := RenderCompliancePDF(context.Background(), &buf, cr, ""); err == nil {
		t.Error("expected error when chrome sidecar unconfigured, got nil")
	}
}

func TestComplianceArc(t *testing.T) {
	// 0% => zero filled; 100% => full circumference filled.
	if got := complianceArc(0, 52); !strings.HasPrefix(got, "0.00 ") {
		t.Errorf("arc(0) = %q, want leading 0.00", got)
	}
	full := complianceArc(100, 52)
	parts := strings.Fields(full)
	if len(parts) != 2 || parts[0] != parts[1] {
		t.Errorf("arc(100) = %q, want filled==circumference", full)
	}
}
