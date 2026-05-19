package scenario

import (
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/models"
)

// Interpret converts a raw ExecResult into a normalised SimulationResult.
// ATT&CK technique ID is normalised, name resolved from TechniqueNameMap,
// and ThreatImpact / Remediation populated from the BFSI-aware helpers.
func Interpret(step Step, result ExecResult) models.SimulationResult {
	techniqueID := models.NormalizeID(step.TechniqueID)
	techniqueName := models.LookupTechniqueName(techniqueID)
	if techniqueName == "" {
		techniqueName = step.Name // fallback for local checks and unknown IDs
	}

	tactic := models.LookupTactic(techniqueID)
	sev := models.Severity(tactic)
	if sev == "" {
		sev = "Medium"
	}

	execAt := result.ExecutedAt
	if execAt.IsZero() {
		execAt = time.Now()
	}

	combined := strings.TrimSpace(result.Stdout + "\n" + result.Stderr)

	framework := step.Framework
	if framework == "" {
		framework = "custom"
	}

	var checkResult models.CheckResult
	var details string

	switch framework {
	case "art":
		checkResult, details = interpretART(result, combined)
	case "caldera":
		checkResult, details = interpretCaldera(result, combined)
	default:
		checkResult, details = interpretCustom(result, combined)
	}

	return models.SimulationResult{
		ID: TaskID(step.TechniqueID, step.Name),
		Technique: models.AttackTechnique{
			ID:     techniqueID,
			Name:   techniqueName,
			Tactic: tactic,
		},
		Result:       checkResult,
		Severity:     sev,
		ThreatImpact: models.ThreatImpact(tactic, techniqueID, techniqueName),
		Details:      details,
		Remediation:  models.Remediation(checkResult, tactic, techniqueID, techniqueName),
		RawOutput:    truncate(combined, 3000),
		DurationMs:   result.DurationMs,
		ExecutedAt:   execAt,
		Framework:    framework,
		Events:       result.Events,
	}
}

// interpretART interprets raw command output from an ART atomic test.
// The orchestrator now resolves commands locally and sends raw PowerShell/cmd —
// no Invoke-AtomicTest on the endpoint, so output is plain shell output.
//
//   - access denied / blocked by control  → PASS  (control worked)
//   - exit 0 / technique ran              → FAIL  (control did not stop it)
//   - exit non-zero without clear signal  → FAIL  (attempted; outcome uncertain)
func interpretART(r ExecResult, combined string) (models.CheckResult, string) {
	lower := strings.ToLower(combined)

	if strings.Contains(lower, "access is denied") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "blocked by") ||
		strings.Contains(lower, "quarantined") ||
		strings.Contains(lower, "this program is blocked") ||
		strings.Contains(lower, "operation did not complete successfully") {
		return models.ResultPass, "Security control blocked the technique: " + firstLine(combined)
	}

	if r.ExitCode == 0 {
		out := firstLine(combined)
		if out == "" {
			out = "technique ran to completion"
		}
		return models.ResultFail, "Technique executed: " + out
	}
	return models.ResultFail, fmt.Sprintf("Technique exited %d: %s", r.ExitCode, firstLine(combined))
}

// interpretCaldera interprets a Caldera ability execution result.
func interpretCaldera(r ExecResult, combined string) (models.CheckResult, string) {
	lower := strings.ToLower(combined)

	if strings.Contains(lower, "skip:") {
		return models.ResultSkipped, stripPrefix(firstLine(combined))
	}
	if strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "blocked") ||
		strings.Contains(lower, "restricted") {
		return models.ResultPass, "Ability was blocked by security controls: " + firstLine(combined)
	}
	if r.ExitCode != 0 {
		return models.ResultFail, fmt.Sprintf("Ability exited with code %d: %s", r.ExitCode, firstLine(combined))
	}
	return models.ResultFail, "Ability executed: " + firstLine(combined)
}

// interpretCustom interprets a custom PowerShell check or local posture check.
// Checks output "PASS: ...", "FAIL: ...", or "SKIP: ..." as the first line.
// If no structured prefix: exit 0 = pass, non-zero = fail.
func interpretCustom(r ExecResult, combined string) (models.CheckResult, string) {
	first := strings.TrimSpace(firstLine(combined))
	lower := strings.ToLower(first)

	switch {
	case strings.HasPrefix(lower, "pass:"):
		return models.ResultPass, stripPrefix(first)
	case strings.HasPrefix(lower, "fail:"):
		return models.ResultFail, stripPrefix(first)
	case strings.HasPrefix(lower, "skip:"):
		return models.ResultSkipped, stripPrefix(first)
	}

	if r.ExitCode == 0 {
		return models.ResultPass, "Step completed: " + first
	}
	lower2 := strings.ToLower(combined)
	if strings.Contains(lower2, "access denied") || strings.Contains(lower2, "blocked") {
		return models.ResultPass, "Blocked by security controls: " + first
	}
	return models.ResultFail, fmt.Sprintf("Step failed (exit %d): %s", r.ExitCode, first)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return s
}

func stripPrefix(s string) string {
	if i := strings.Index(s, ":"); i >= 0 && i < 8 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
