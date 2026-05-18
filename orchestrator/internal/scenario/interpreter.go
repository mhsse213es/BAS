package scenario

import (
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/models"
)

// Interpret converts a raw ExecResult into a SimulationResult.
// The step provides the framework context the agent doesn't see.
// Convention for custom/scan PowerShell checks: first output line starts with
// "PASS:", "FAIL:", or "SKIP:" — the interpreter uses this for structured results.
func Interpret(step Step, result ExecResult) models.SimulationResult {
	tactic := models.LookupTactic(step.TechniqueID)
	sev := models.Severity(tactic)
	if sev == "" {
		sev = "Medium"
	}

	execAt := result.ExecutedAt
	if execAt.IsZero() {
		execAt = time.Now()
	}

	combined := strings.TrimSpace(result.Stdout + "\n" + result.Stderr)

	var checkResult models.CheckResult
	var details string

	switch step.Framework {
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
			ID:     step.TechniqueID,
			Name:   step.Name,
			Tactic: tactic,
		},
		Result:       checkResult,
		Severity:     sev,
		ThreatImpact: fmt.Sprintf("[%s] %s", strings.ToUpper(step.Framework), step.Name),
		Details:      details,
		Remediation:  "Review MITRE ATT&CK mitigations — attack.mitre.org/techniques/" + strings.ReplaceAll(step.TechniqueID, ".", "/"),
		RawOutput:    truncate(combined, 3000),
		DurationMs:   result.DurationMs,
		ExecutedAt:   execAt,
		Framework:    step.Framework,
		Events:       result.Events,
	}
}

// interpretART interprets raw Invoke-AtomicTest output.
//
// Semantics:
//   - blocked/access-denied by security control → PASS (control worked)
//   - test ran successfully                      → FAIL (control did not stop it)
//   - module not installed / prereqs missing     → SKIPPED
func interpretART(r ExecResult, combined string) (models.CheckResult, string) {
	lower := strings.ToLower(combined)

	// Module not installed
	if strings.Contains(lower, "is not recognized") ||
		(strings.Contains(lower, "invoke-atomictest") && strings.Contains(lower, "not found")) ||
		strings.Contains(lower, "art_error") {
		return models.ResultSkipped,
			"AtomicRedTeam not installed — run: IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam"
	}

	// Prerequisites not met
	if (strings.Contains(lower, "prerequisite") || strings.Contains(lower, "prereq")) &&
		(strings.Contains(lower, "not met") || strings.Contains(lower, "missing") || strings.Contains(lower, "failed")) {
		return models.ResultSkipped, "Prerequisites not met: " + firstLine(combined)
	}

	// Blocked by security controls
	if strings.Contains(lower, "access is denied") ||
		strings.Contains(lower, "access denied") ||
		strings.Contains(lower, "blocked by") ||
		strings.Contains(lower, "quarantined") ||
		strings.Contains(lower, "this program is blocked") {
		return models.ResultPass, "Security control blocked the technique: " + firstLine(combined)
	}

	// Explicit ART success
	if strings.Contains(lower, "successfully") || strings.Contains(lower, "done executing") {
		return models.ResultFail, "Technique executed without blockage: " + firstLine(combined)
	}

	if r.ExitCode != 0 {
		return models.ResultFail, fmt.Sprintf("Technique exited with code %d: %s", r.ExitCode, firstLine(combined))
	}
	return models.ResultFail, "Technique completed — no blockage detected: " + firstLine(combined)
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

// interpretCustom interprets a custom PowerShell check.
// Checks should output "PASS: ...", "FAIL: ...", or "SKIP: ..." as the first line.
// If no prefix, exit code 0 = pass, non-zero = fail.
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

	// No structured prefix — fall back to exit code
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
