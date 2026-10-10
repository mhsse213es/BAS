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

func TestADAssessmentReportHTML_StatesLiveStoreAttachment(t *testing.T) {
	// Partial attachment must read as incomplete, never as a verified absence.
	partial := ADAssessmentReport{
		GeneratedAt: time.Now(), ARTStoreLoaded: true, CalderaStoreLoaded: false,
		Report: admatrix.CoverageReport{CapabilityStateSummary: admatrix.CapabilityStateSummary{Total: 1}},
	}
	var buf bytes.Buffer
	if err := ADAssessmentReportHTML(&buf, partial); err != nil {
		t.Fatalf("html: %v", err)
	}
	s := strings.ToLower(buf.String())
	if !strings.Contains(s, "caldera") || !strings.Contains(s, "not attached") {
		t.Errorf("report must state the Caldera store is not attached")
	}
	if !strings.Contains(s, "not a verified absence") {
		t.Errorf("report must warn that an incomplete inventory is not a verified absence of content")
	}

	both := partial
	both.CalderaStoreLoaded = true
	buf.Reset()
	if err := ADAssessmentReportHTML(&buf, both); err != nil {
		t.Fatalf("html: %v", err)
	}
	if !strings.Contains(buf.String(), "ART and Caldera") && !strings.Contains(strings.ToLower(buf.String()), "both") {
		t.Errorf("with both stores attached the report should say so")
	}
}

func TestADAssessmentReportHTML_RendersContentProvenance(t *testing.T) {
	rep := ADAssessmentReport{
		GeneratedAt: time.Now(),
		Report: admatrix.CoverageReport{
			CapabilityStateSummary: admatrix.CapabilityStateSummary{Total: 1, Modeled: 1},
			CapabilityStates: []admatrix.CapabilityState{{
				PrimitiveID: "spn-enumerate", Name: "SPN enumeration", Family: "Kerberoasting",
				ContentAvailability: admatrix.ContentScenarioComposable, ContentRepoVerified: true,
				ContentSource: "scenarios/kerberoasting-ad-drill.yaml (Stage 1, T1558.003)",
			}},
		},
	}
	var buf bytes.Buffer
	if err := ADAssessmentReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	if !strings.Contains(buf.String(), "scenarios/kerberoasting-ad-drill.yaml (Stage 1, T1558.003)") {
		t.Errorf("report must render each capability's content provenance (ContentSource)")
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
