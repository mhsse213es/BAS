package reporting

import (
	"encoding/csv"
	"io"
	"regexp"
	"strings"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// cveRe matches an explicit CVE reference. We surface a CVE in the forensic CSV
// ONLY when a result's own text genuinely references one — never auto-mapped or
// inferred from the technique (per the platform's no-fabricated-CVE rule).
var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// forensicStatusLabel maps the 4-verdict taxonomy to report language.
func forensicStatusLabel(r models.CheckResult) string {
	switch r {
	case models.ResultPass, models.ResultBlocked:
		return "Prevented"
	case models.ResultFail:
		return "Not Prevented"
	case models.ResultError:
		return "Error"
	case models.ResultSkipped:
		return "Skipped"
	}
	return string(r)
}

// WriteForensicCSV writes the technical evidence layer — one row per simulation
// result — that SOC analysts, consultants, and auditors work from. It complements
// the executive report (the "what happened / why it matters" layer) with the raw
// per-technique forensic detail. CVE is included only when the result's own text
// references one; Detection is the locally-observed verdict for unprevented
// techniques, "—" otherwise.
func WriteForensicCSV(w io.Writer, scenarioName string, results []models.SimulationResult) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"Timestamp", "Scenario", "Tactic", "Technique ID", "Technique", "Severity",
		"Status", "Requested Priv", "Executed As", "Detection", "Threat Impact", "Mitigation", "Evidence", "CVE", "ATT&CK URL",
	})
	for _, r := range results {
		detection := "—"
		if r.Result == models.ResultFail {
			detection = classifyDetection(r.Events).Status
		}
		cve := ""
		for _, s := range []string{r.Details, r.Remediation, r.RawOutput, r.ThreatImpact} {
			if m := cveRe.FindString(s); m != "" {
				cve = m
				break
			}
		}
		url := ""
		if e := attackdata.Lookup(r.Technique.ID); e != nil {
			url = e.URL
		}
		evidence := strings.TrimSpace(r.Details)
		if evidence == "" {
			evidence = strings.TrimSpace(r.RawOutput)
		}
		ts := ""
		if !r.ExecutedAt.IsZero() {
			ts = r.ExecutedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		reqPriv := r.RequestedPriv
		if reqPriv == "" {
			reqPriv = "Legacy"
		}
		execAs := r.ExecutedAs
		if execAs == "" {
			execAs = "Legacy"
		}
		_ = cw.Write([]string{
			ts, scenarioName, humanizeTactic(r.Technique.Tactic), r.Technique.ID, r.Technique.Name,
			r.Severity, forensicStatusLabel(r.Result), reqPriv, execAs, detection, strings.TrimSpace(r.ThreatImpact),
			strings.TrimSpace(r.Remediation), truncateStr(evidence, 500), cve, url,
		})
	}
	cw.Flush()
}
