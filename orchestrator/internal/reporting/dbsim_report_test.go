package reporting

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dlpreport"
)

func dbsimTestReport(id string, res dbsim.RunResult, d dbsim.Dimensions) dbsim.StoredReport {
	return dbsim.StoredReport{
		Schema: 1, Result: res, Reason: "reason text",
		Scenario:   dbsim.ScenarioMeta{ID: id, Version: "1", ControlObjective: "objective"},
		Dimensions: d,
		Record: dlpreport.Record{
			Enforcement: dlpreport.EnforcementBlocked, Classification: dlpreport.ClassificationNotEvaluated,
			Telemetry: dlpreport.TelemetryPresent, Response: dlpreport.ResponseNotTested,
			Confidence: "high", Limitations: "record limitation",
		},
	}
}

func dbsimRender(t *testing.T, r dbsim.StoredReport) string {
	t.Helper()
	out, err := BuildDBSimReport(r, DBSimReportOptions{RunID: "run-1", GeneratedAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReportRendersEveryDimensionState(t *testing.T) {
	out := dbsimRender(t, dbsimTestReport("dbsim-db03-unauthorized-access", dbsim.ResultFail, dbsim.Dimensions{
		Prevention: dbsim.DimPass, Detection: dbsim.DimFail, Response: dbsim.DimNotExpected,
		Classification: dbsim.DimSkipped, Audit: dbsim.DimUnverifiable, Policy: dbsim.DimNotExpected,
	}))
	for _, want := range []string{"pass", "fail", "not_expected", "skipped", "unverifiable"} {
		if !strings.Contains(out, ">"+want+"<") {
			t.Errorf("state %q not rendered as itself", want)
		}
	}
	for _, label := range []string{"Prevention", "Detection", "Response", "Classification", "Audit", "Policy"} {
		if !strings.Contains(out, label) {
			t.Errorf("dimension %q missing", label)
		}
	}
}

func TestReportShowsLimitationsConfidenceAndAlertSourceUnavailable(t *testing.T) {
	r := dbsimTestReport("dbsim-db05-suspicious-read", dbsim.ResultFail, dbsim.Dimensions{
		Prevention: dbsim.DimPass, Detection: dbsim.DimUnverifiable, Response: dbsim.DimNotExpected,
		Classification: dbsim.DimNotExpected, Audit: dbsim.DimNotExpected, Policy: dbsim.DimNotExpected,
	})
	r.Record.Telemetry = dlpreport.TelemetryUnverifiable
	r.Evidence.Corr.Limitations = "elastic unreachable"
	out := dbsimRender(t, r)
	for _, want := range []string{"record limitation", "high", "elastic unreachable", "Alert source unavailable", "Not tested"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestReportRemediationOnlyOnEstablishedFailure(t *testing.T) {
	id := "dbsim-db03-unauthorized-access"
	text := DBSimRemediation(id, "prevention")
	if text == "" {
		t.Fatal("no remediation text for db03 prevention")
	}
	base := dbsim.Dimensions{Prevention: dbsim.DimFail, Detection: dbsim.DimNotExpected, Response: dbsim.DimNotExpected,
		Classification: dbsim.DimNotExpected, Audit: dbsim.DimNotExpected, Policy: dbsim.DimNotExpected}
	if !strings.Contains(dbsimRender(t, dbsimTestReport(id, dbsim.ResultFail, base)), text[:20]) {
		t.Error("remediation missing on fail")
	}
	for _, g := range []dbsim.DimensionGrade{dbsim.DimPass, dbsim.DimUnverifiable, dbsim.DimSkipped, dbsim.DimNotExpected} {
		d := base
		d.Prevention = g
		if strings.Contains(dbsimRender(t, dbsimTestReport(id, dbsim.ResultFail, d)), text[:20]) {
			t.Errorf("remediation shown for %s", g)
		}
	}
	// ERROR result with a stale fail dimension must not claim an established failure.
	if strings.Contains(dbsimRender(t, dbsimTestReport(id, dbsim.ResultError, base)), text[:20]) {
		t.Error("remediation shown on ERROR result")
	}
	if DBSimRemediation("unknown", "prevention") != "" || DBSimRemediation(id, "response") != "" {
		t.Error("unexpected text for unknown key")
	}
}

func TestDBSimRemediationCoversShippedScenariosConditionally(t *testing.T) {
	for _, id := range []string{
		"dbsim-db01-auth-policy", "dbsim-db02-excessive-grants", "dbsim-db03-unauthorized-access",
		"dbsim-db04-audit-coverage", "dbsim-db05-suspicious-read", "dbsim-db06-account-revocation",
		"dbsim-db07-sensitive-classification", "dbsim-db08-audit-tamper-resistance",
		"dbsim-db09-bounded-bulk-read", "dbsim-db10-write-delete-prevention", "dbsim-db11-backup-export-permissions",
	} {
		n := 0
		for _, dim := range []string{"prevention", "detection", "audit", "policy", "classification"} {
			txt := DBSimRemediation(id, dim)
			if txt == "" {
				continue
			}
			n++
			if !strings.HasPrefix(txt, "If ") && !strings.HasPrefix(txt, "Review ") {
				t.Errorf("%s/%s not conditionally worded: %q", id, dim, txt)
			}
		}
		if n == 0 {
			t.Errorf("%s has no remediation entries", id)
		}
	}
}

func TestReportEscapesEvidence(t *testing.T) {
	r := dbsimTestReport("dbsim-db05-suspicious-read", dbsim.ResultFail, dbsim.Dimensions{
		Prevention: dbsim.DimPass, Detection: dbsim.DimPass, Response: dbsim.DimNotExpected,
		Classification: dbsim.DimNotExpected, Audit: dbsim.DimNotExpected, Policy: dbsim.DimNotExpected,
	})
	r.Reason = "<script>alert(1)</script>"
	r.Evidence.Principal = "<img src=x onerror=1>"
	r.Evidence.Notes = []string{"<b>note</b>"}
	r.Evidence.Corr.AlertRefs = []dbsim.AlertRef{{ID: "a", Rule: "<i>rule</i>", Host: "h", Excerpt: "<script>x</script>"}}
	out := dbsimRender(t, r)
	for _, bad := range []string{"<script>alert", "<img src=x", "<b>note", "<i>rule", "<script>x"} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped %q", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("reason not escaped as text")
	}
}
