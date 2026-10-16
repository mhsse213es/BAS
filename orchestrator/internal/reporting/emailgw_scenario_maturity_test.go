package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

func TestBuildEmailGWScenarioMaturityReport_CarriesEveryRowThrough(t *testing.T) {
	now := time.Now()
	entries := []emailgwefficacy.ScenarioMaturityEntry{
		{ScenarioID: "EG-001", Name: "Domain spoofing", Maturity: emailgwefficacy.MaturityVerifiedThroughExecution},
		{ScenarioID: "EG-007", Name: "External auto-forwarding", Maturity: emailgwefficacy.MaturityExecutedWithoutEvidence},
	}
	rep := BuildEmailGWScenarioMaturityReport(entries, now)

	if !rep.GeneratedAt.Equal(now) {
		t.Errorf("GeneratedAt = %v, want %v", rep.GeneratedAt, now)
	}
	if len(rep.Rows) != 2 {
		t.Fatalf("len(Rows) = %d, want 2", len(rep.Rows))
	}
	if rep.Rows[0].ScenarioID != "EG-001" || rep.Rows[0].Maturity != string(emailgwefficacy.MaturityVerifiedThroughExecution) {
		t.Errorf("Rows[0] = %+v, want EG-001/verified-through-execution", rep.Rows[0])
	}
	if rep.Rows[1].ScenarioID != "EG-007" || rep.Rows[1].Maturity != string(emailgwefficacy.MaturityExecutedWithoutEvidence) {
		t.Errorf("Rows[1] = %+v, want EG-007/executed-without-sufficient-evidence", rep.Rows[1])
	}
}

func TestEmailGWScenarioMaturityReportHTML_RendersEveryRow(t *testing.T) {
	entries := []emailgwefficacy.ScenarioMaturityEntry{
		{ScenarioID: "EG-001", Name: "Domain spoofing", Maturity: emailgwefficacy.MaturityVerifiedThroughExecution},
		{ScenarioID: "EG-007", Name: "External auto-forwarding", Maturity: emailgwefficacy.MaturityExecutedWithoutEvidence},
	}
	rep := BuildEmailGWScenarioMaturityReport(entries, time.Now())

	var buf bytes.Buffer
	if err := EmailGWScenarioMaturityReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, "<!DOCTYPE html>") {
		t.Error("output is not a full HTML document")
	}
	for _, row := range rep.Rows {
		if !strings.Contains(s, row.ScenarioID) {
			t.Errorf("HTML missing scenario ID %q", row.ScenarioID)
		}
		if !strings.Contains(s, row.Maturity) {
			t.Errorf("HTML missing maturity status %q", row.Maturity)
		}
	}
}

// TestEmailGWScenarioMaturityReportHTML_EscapesHostileContent proves
// html/template's auto-escaping is in effect -- a scenario name
// containing markup could never inject it into the page.
func TestEmailGWScenarioMaturityReportHTML_EscapesHostileContent(t *testing.T) {
	rep := EmailGWScenarioMaturityReport{
		Rows: []EmailGWScenarioMaturityRow{
			{ScenarioID: "EG-999", Name: "<script>alert(1)</script>", Maturity: "not-implemented"},
		},
	}
	var buf bytes.Buffer
	if err := EmailGWScenarioMaturityReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("output contains an unescaped <script> tag")
	}
}

// TestBuildEmailGWScenarioMaturityReport_RealRegistryIDs proves the
// report renderer handles every real EG-ID in emailgwefficacy's own
// catalogue, not just a synthetic pair -- a structural check, not a
// claim about any particular scenario's real maturity (which, per
// this file's own package-level comment, only a real execution can
// establish).
func TestBuildEmailGWScenarioMaturityReport_RealRegistryIDs(t *testing.T) {
	entries := emailgwefficacy.BuildScenarioMaturityReport(emailgwefficacy.EmailGWScenarioRegistry(), nil)
	rep := BuildEmailGWScenarioMaturityReport(entries, time.Now())
	if len(rep.Rows) != len(emailgwefficacy.AllEmailGWScenarioIDs()) {
		t.Fatalf("len(Rows) = %d, want %d", len(rep.Rows), len(emailgwefficacy.AllEmailGWScenarioIDs()))
	}
	var buf bytes.Buffer
	if err := EmailGWScenarioMaturityReportHTML(&buf, rep); err != nil {
		t.Fatalf("html: %v", err)
	}
	for _, id := range emailgwefficacy.AllEmailGWScenarioIDs() {
		if !strings.Contains(buf.String(), id) {
			t.Errorf("HTML missing catalogue ID %q", id)
		}
	}
}
