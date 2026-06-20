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
		Result:         checkResult,
		Severity:       sev,
		ThreatImpact:   models.ThreatImpact(tactic, techniqueID, techniqueName),
		Details:        details,
		Remediation:    models.Remediation(checkResult, tactic, techniqueID, techniqueName),
		RawOutput:      truncate(combined, 3000),
		DurationMs:     result.DurationMs,
		ExecutedAt:     execAt,
		Framework:      framework,
		Events:         result.Events,
		CleanupVerdict: result.CleanupVerdict,
	}
}

// interpretART interprets raw command output from an ART atomic test.
// The orchestrator now resolves commands locally and sends raw PowerShell/cmd —
// no Invoke-AtomicTest on the endpoint, so output is plain shell output.
//
// Classification is delegated to classifyExecution (outcome.go), which separates
// a real security outcome from a BAS execution problem:
//   - blocked by a control                → PASS  (control worked)
//   - technique ran (exit 0 / completion) → FAIL  (control did not stop it)
//   - timeout/contention/missing/malformed → ERROR (BAS could not execute)
//   - explicit skip marker                → SKIPPED
func interpretART(r ExecResult, combined string) (models.CheckResult, string) {
	outcome, _, detail := classifyExecution(r, combined)
	switch outcome {
	case OutcomeSkipped:
		return models.ResultSkipped, detail
	case OutcomeBlocked:
		return models.ResultPass, detail
	case OutcomeError:
		return models.ResultError, detail
	default: // OutcomeExecuted
		return models.ResultFail, detail
	}
}

// blockSignature returns a short label when the output contains a known
// access-denied / antivirus / policy-block signature, or "" if none match.
// lower must already be lower-cased.
func blockSignature(lower string) string {
	switch {
	case strings.Contains(lower, "access is denied"),
		strings.Contains(lower, "access denied"),
		strings.Contains(lower, "permission denied"),
		strings.Contains(lower, "denied by"):
		return "access denied"
	case strings.Contains(lower, "blocked by group policy"),
		strings.Contains(lower, "blocked by your administrator"),
		strings.Contains(lower, "restricted by"),
		strings.Contains(lower, "blocked by"),
		strings.Contains(lower, "this program is blocked"),
		strings.Contains(lower, "this app has been blocked"),
		strings.Contains(lower, "operation was blocked"):
		return "policy block"
	case strings.Contains(lower, "windows defender"),
		strings.Contains(lower, "antivirus"),
		strings.Contains(lower, "threat detected"),
		strings.Contains(lower, "malware"),
		strings.Contains(lower, "virus detected"),
		strings.Contains(lower, "quarantined"),
		strings.Contains(lower, "operation did not complete successfully"):
		return "antivirus"
	}
	return ""
}

// isBlockExitCode reports whether an exit code indicates the process was denied
// or terminated by a security control rather than run to completion.
//   - 5            ERROR_ACCESS_DENIED (Win32)
//   - 0xC0000022   STATUS_ACCESS_DENIED (NTSTATUS, surfaces as -1073741790)
//   - 0xC0000142   STATUS_DLL_INIT_FAILED (commonly seen on EDR injection block)
func isBlockExitCode(code int) bool {
	switch int64(code) {
	case 5, // ERROR_ACCESS_DENIED
		-1073741790, 3221225506, // 0xC0000022 STATUS_ACCESS_DENIED (signed32 / unsigned)
		-1073741502, 3221225794: // 0xC0000142 STATUS_DLL_INIT_FAILED (signed32 / unsigned)
		return true
	}
	return false
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
	// A BAS execution problem (timeout, contention, missing prereq, malformed) is
	// not a security outcome — record it as ERROR, not a finding.
	if reason := classifyExecutionError(lower, r.ExitCode); reason != ErrNone {
		return models.ResultError, "Execution error (" + errorReasonLabel(reason) + "): " + firstLine(combined)
	}
	if r.ExitCode != 0 {
		return models.ResultError, fmt.Sprintf("Execution error (exit %d): %s", r.ExitCode, firstLine(combined))
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
	// A check whose own script could not execute (parse error, timeout, missing
	// prerequisite, …) is a BAS problem, not a security finding — record ERROR so
	// it is excluded from scoring rather than inflating the failure count.
	if reason := classifyExecutionError(lower2, r.ExitCode); reason != ErrNone {
		return models.ResultError, "Execution error (" + errorReasonLabel(reason) + "): " + first
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
