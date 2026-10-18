package reporting

import (
	"strings"

	"github.com/audspect/bas/internal/models"
)

// AppControlSection is the Application Control Efficacy section of a run
// report. It is built from one run's own results and is hidden when the run
// contains no application-control steps.
//
// Prevention (Outcome) and telemetry visibility are separate fields on every
// row. Families that were not run, were not applicable, or produced no
// structured evidence are listed as such and are never shown as passing.
type AppControlSection struct {
	HasData bool   `json:"hasData"`
	RunID   string `json:"runId"`
	// Hostname labels the section in a campaign report, where several runs
	// appear. It is empty for a single-run report.
	Hostname    string                   `json:"hostname,omitempty"`
	Rows        []AppControlRow          `json:"rows"`
	Families    []AppControlFamilyStatus `json:"families"`
	Limitations []string                 `json:"limitations"`
}

// AppControlRow is one evaluated path: prevention outcome and telemetry
// visibility as independent facts.
type AppControlRow struct {
	StepName   string `json:"stepName"`
	Family     string `json:"family"`
	Technique  string `json:"technique"`
	Outcome    string `json:"outcome"`
	Visibility string `json:"visibility"`
}

// AppControlFamilyStatus is the coverage state of one behavioral family in
// this run. Status is an observed outcome, or one of: not_run, unverified,
// inconclusive (conflicting outcomes within the run).
type AppControlFamilyStatus struct {
	Family string `json:"family"`
	Status string `json:"status"`
	Note   string `json:"note"`
}

const (
	appCtlStatusNotRun     = "not_run"
	appCtlStatusUnverified = "unverified"
)

// appCtlFamilyOrder fixes the order families appear in and the vocabulary a
// family can take in a report.
var appCtlFamilyOrder = []string{
	"indirect_execution", "alternate_binary", "script_host_proxy",
	"alternate_ps_host", "parent_child_asr",
}

// appCtlStepFamilies maps a step name prefix to its family. It is the fallback
// when a step produced no APPCTL_FAMILY line, so a step that ran with missing
// output still appears in the report as unverified.
var appCtlStepFamilies = map[string]string{
	"Application control indirect execution":   "indirect_execution",
	"Application control alternate binary":     "alternate_binary",
	"Application control script host proxy":    "script_host_proxy",
	"Application control alternate PowerShell": "alternate_ps_host",
	"Application control parent-child ASR":     "parent_child_asr",
}

// appCtlLimitations is stated in every section that has data. These are
// report-level facts, not footnotes: a passing fixture or a stubbed test is
// never evidence that a live control enforces.
var appCtlLimitations = []string{
	"Live AppLocker and ASR enforcement is verified only where this run executed on a host with those controls configured and enforced. Fixture tests that validate the report code are not evidence of enforcement.",
	"Telemetry visibility records whether Sysmon process-creation telemetry saw the attempt. It is not a prevention verdict and not a security-product detection verdict. Not visible does not mean the attempt did not happen.",
	"Vendor-specific correlation (Microsoft Defender, SentinelOne) is not included and remains unverified until tested against a configured tenant.",
	"Results hold only for the tested Windows build, policy version, and execution path. Families not run, not applicable, or unverified are not reported as passing.",
}

// buildAppControlSection builds the section from one run's results. The caller
// passes only that run's results, so every row maps to runID.
func buildAppControlSection(runID string, results []models.SimulationResult) AppControlSection {
	sec := AppControlSection{RunID: runID, Limitations: appCtlLimitations}
	perFamily := map[string][]string{} // family -> outcomes observed in the run
	unverified := map[string]bool{}

	for _, r := range results {
		if !isAppControlResult(r) {
			continue
		}
		sec.HasData = true
		family := appCtlFamilyOf(r)
		outcome, ok := ParseAppControlOutcome(r.RawOutput)
		if !ok {
			unverified[family] = true
			continue
		}
		vis, _ := ParseAppControlVisibility(r.RawOutput)
		if vis == "" {
			vis = "unknown"
		}
		sec.Rows = append(sec.Rows, AppControlRow{
			StepName:   r.StepName,
			Family:     family,
			Technique:  r.Technique.ID,
			Outcome:    outcome,
			Visibility: vis,
		})
		perFamily[family] = append(perFamily[family], outcome)
	}

	for _, fam := range appCtlFamilyOrder {
		sec.Families = append(sec.Families, appCtlFamilyStatusFor(fam, perFamily[fam], unverified[fam]))
	}
	return sec
}

func appCtlFamilyStatusFor(family string, outcomes []string, unverified bool) AppControlFamilyStatus {
	switch {
	case len(outcomes) == 0 && unverified:
		return AppControlFamilyStatus{Family: family, Status: appCtlStatusUnverified,
			Note: "step ran without a structured APPCTL_OUTCOME; no verdict"}
	case len(outcomes) == 0:
		return AppControlFamilyStatus{Family: family, Status: appCtlStatusNotRun,
			Note: "no step for this family in this run"}
	}
	first := outcomes[0]
	for _, o := range outcomes[1:] {
		if o != first {
			return AppControlFamilyStatus{Family: family, Status: "inconclusive",
				Note: "conflicting outcomes within this run"}
		}
	}
	return AppControlFamilyStatus{Family: family, Status: first}
}

// isAppControlResult reports whether a result belongs to an application-control
// step, by its structured markers or by its step name.
func isAppControlResult(r models.SimulationResult) bool {
	if strings.Contains(r.RawOutput, "APPCTL_") {
		return true
	}
	return appCtlFamilyByStepName(r.StepName) != ""
}

func appCtlFamilyOf(r models.SimulationResult) string {
	if fam, ok := ParseAppControlFamily(r.RawOutput); ok {
		return fam
	}
	if fam := appCtlFamilyByStepName(r.StepName); fam != "" {
		return fam
	}
	return "unknown"
}

func appCtlFamilyByStepName(name string) string {
	for prefix, fam := range appCtlStepFamilies {
		if strings.HasPrefix(name, prefix) {
			return fam
		}
	}
	return ""
}
