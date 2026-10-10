package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/admatrix"
)

func sampleADReport() ADAssessmentReport {
	return ADAssessmentReport{
		GeneratedAt: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		Report:      admatrix.Report(),
	}
}

func TestADAssessmentReportJSON_IsTheBackendReportVerbatim(t *testing.T) {
	rep := sampleADReport()
	var buf bytes.Buffer
	if err := ADAssessmentReportJSON(&buf, rep); err != nil {
		t.Fatalf("json: %v", err)
	}
	var got ADAssessmentReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The exported JSON must carry the same counts the UI reads from
	// admatrix.Report() -- no separate hardcoded tallies.
	if got.Report.CapabilityStateSummary.Total != rep.Report.CapabilityStateSummary.Total {
		t.Fatalf("summary total drifted: %d vs %d", got.Report.CapabilityStateSummary.Total, rep.Report.CapabilityStateSummary.Total)
	}
	if len(got.Report.CapabilityStates) != len(rep.Report.CapabilityStates) {
		t.Fatalf("capability count drifted: %d vs %d", len(got.Report.CapabilityStates), len(rep.Report.CapabilityStates))
	}
}

func TestADAssessmentReportHTML_RendersEnterpriseSections(t *testing.T) {
	var buf bytes.Buffer
	if err := ADAssessmentReportHTML(&buf, sampleADReport()); err != nil {
		t.Fatalf("html: %v", err)
	}
	s := buf.String()
	for _, want := range []string{"Executive Summary", "Coverage Summary", "Capability Results", "Limitations", "Outstanding", "Methodology"} {
		if !strings.Contains(s, want) {
			t.Errorf("report HTML missing section %q", want)
		}
	}
}

func TestADAssessmentReportHTML_StatesModeledNotValidatedHonestly(t *testing.T) {
	// A report where nothing is executed or detection-validated (today's
	// reality) must say so plainly and never present modeled coverage as
	// validated AD security.
	rep := ADAssessmentReport{
		GeneratedAt: time.Now(),
		Report: admatrix.CoverageReport{
			CapabilityStateSummary: admatrix.CapabilityStateSummary{Total: 28, Modeled: 28, ScenarioComposed: 10, Executed: 0, DetectionValidated: 0},
			CapabilityStates: []admatrix.CapabilityState{{
				PrimitiveID: "acl-genericall-takeover", Name: "ACL takeover", Family: "ACL",
				Modeled: true, ContentAvailability: admatrix.ContentModelOnly,
				ExecutionValidation: admatrix.ExecNotExecuted, DetectionValidation: admatrix.DetNotValidated,
			}},
		},
	}
	var buf bytes.Buffer
	if err := ADAssessmentReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, "not") || !strings.Contains(strings.ToLower(s), "not validated against") {
		t.Errorf("report must state the modeled-vs-validated gap plainly")
	}
	if strings.Contains(s, "0 of 28 capabilities executed") == false {
		t.Errorf("report must state the real executed count (0 of 28)")
	}
}

func TestADAssessmentReportHTML_EscapesHostileCapabilityNames(t *testing.T) {
	rep := ADAssessmentReport{
		GeneratedAt: time.Now(),
		Report: admatrix.CoverageReport{
			CapabilityStateSummary: admatrix.CapabilityStateSummary{Total: 1, Modeled: 1},
			CapabilityStates: []admatrix.CapabilityState{{
				PrimitiveID: "x", Name: `<script>globalThis.x=1</script>`, Family: `"><img src=x onerror=1>`,
				Limitations: []string{`<script>bad()</script>`},
			}},
		},
	}
	var buf bytes.Buffer
	if err := ADAssessmentReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	s := buf.String()
	if strings.Contains(s, "<script>globalThis") || strings.Contains(s, "<script>bad()") {
		t.Errorf("hostile capability strings must be HTML-escaped, not emitted raw")
	}
	if !strings.Contains(s, "&lt;script&gt;globalThis") {
		t.Errorf("escaped form of the hostile name should be present")
	}
}

func TestADAssessmentReportPDF_FallsBackWithoutSidecar(t *testing.T) {
	t.Setenv("CHROME_WS_URL", "") // force the fpdf fallback path
	var buf bytes.Buffer
	if err := ADAssessmentReportPDF(context.Background(), &buf, sampleADReport()); err != nil {
		t.Fatalf("pdf: %v", err)
	}
	if buf.Len() == 0 || !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) {
		t.Fatalf("expected a %%PDF document, got %d bytes", buf.Len())
	}
}
