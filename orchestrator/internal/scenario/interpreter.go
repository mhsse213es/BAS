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

	outputLimit := 3000
	if step.MaxOutputBytes > 0 {
		outputLimit = step.MaxOutputBytes
	}
	truncated := len(combined) > outputLimit

	framework := step.Framework
	if framework == "" {
		framework = "custom"
	}

	var checkResult models.CheckResult
	var details string

	// A step the agent killed on its own deadline never reached a result, so
	// nothing in its partial output is evidence of anything. This is checked
	// BEFORE the framework interpreters because every one of them would
	// otherwise read that partial output as a security outcome:
	//
	//   - interpretART -> classifyExecution -> blockSignature matches
	//     "permission denied" and returns PASS. Observed live 2026-09-03:
	//     T1552.001 Test 3 (`grep -ri password /`) emits thousands of
	//     "grep: /proc/...: Permission denied" lines, ran 123001ms, was killed
	//     at its 120s deadline, and was scored PASS -- a technique that never
	//     completed counted as a control success, inflating the prevention
	//     score.
	//   - interpretCaldera matches "blocked"/"restricted" BEFORE its execution-
	//     error check, so the same partial output scores PASS there too.
	//   - interpretCustom returns PASS on exit 0, and matches "access denied"
	//     or "blocked" on any non-zero exit.
	//
	// The agent has always reported TimedOut on the wire (types.go); no
	// interpreter consulted it. Doing so here fixes ART, Caldera and custom
	// checks together, on every platform, and for results from already-deployed
	// agents -- this is server-side classification, so no agent upgrade is
	// needed for the correction to take effect.
	//
	// ERROR (not FAIL) is the honest verdict: we cannot claim the control
	// allowed the technique either. The step is excluded from scoring rather
	// than counted for or against the endpoint. See classifyOutcome in
	// internal/reporting, which excludes ResultError.
	if result.Vetoed {
		// Checked here, before the framework switch, for the exact same
		// reason TimedOut is: only interpretART's classifyExecution knew
		// about Vetoed, so a vetoed step with any other framework --
		// "custom" (em-07 and every hand-authored scenario in this
		// codebase), "caldera", or the default -- fell through to an
		// interpreter with no knowledge of B5 at all and scored FAIL,
		// fabricating a "technique executed and was not stopped" finding
		// for a step Audspect never attempted (final whole-branch review,
		// C1). This is server-side classification -- no agent upgrade is
		// needed for the correction to take effect.
		checkResult = models.ResultVetoed
		details = fmt.Sprintf(
			"VETOED — Audspect prevented execution under its local destructive-action policy (action=%s, class=%s, source=%s). Customer defensive controls were not tested by this step.",
			result.VetoedActionKey, result.VetoedExecutionClass, result.VetoedBlockSource)
	} else if result.TimedOut {
		checkResult = models.ResultError
		details = fmt.Sprintf(
			"Execution error (timed out): the step was killed after %s without completing, so its partial output is not evidence that a control blocked or allowed the technique.%s Re-run with a longer timeout to obtain a measurable result.",
			(time.Duration(result.DurationMs) * time.Millisecond).Round(time.Second),
			terminationEvidence(result.Termination))
	} else {
		switch framework {
		case "art":
			checkResult, details = interpretART(result, combined)
		case "caldera":
			checkResult, details = interpretCaldera(result, combined)
		default:
			checkResult, details = interpretCustom(result, combined)
		}
	}

	var skipReason string
	if checkResult == models.ResultSkipped {
		skipReason = classifySkipReason(details)
	}

	return models.SimulationResult{
		ID:       TaskID(step.TechniqueID, step.Name),
		CheckID:  step.CheckID,
		StepName: step.Name,
		Technique: models.AttackTechnique{
			ID:     techniqueID,
			Name:   techniqueName,
			Tactic: tactic,
		},
		Result:       checkResult,
		Severity:     sev,
		ThreatImpact: models.ThreatImpact(tactic, techniqueID, techniqueName),
		Details:      details,
		SkipReason:   skipReason,
		// Structured mirrors of the VETOED explanation already embedded in
		// Details above -- zero-valued (omitempty) for any non-vetoed step,
		// since the agent only ever populates result.Vetoed* when Vetoed is
		// true (final whole-branch review, I5).
		VetoedActionKey:      result.VetoedActionKey,
		VetoedExecutionClass: result.VetoedExecutionClass,
		VetoedBlockSource:    result.VetoedBlockSource,
		Remediation:          models.Remediation(checkResult, tactic, techniqueID, techniqueName),
		RawOutput:            truncate(combined, outputLimit),
		Truncated:            truncated,
		OriginalOutputBytes:  len(combined),
		DurationMs:           result.DurationMs,
		ExecutedAt:           execAt,
		Framework:            framework,
		Events:               result.Events,
		CleanupVerdict:       result.CleanupVerdict,
		CleanupResidual:      result.CleanupResidual,
		CleanupError:         result.CleanupError,
		RequestedPriv:        result.RequestedPriv,
		RequestedPrivMin:     step.RequiresPriv.Minimum,
		RequestedPrivPref:    step.RequiresPriv.Preferred,
		ExecutedAs:           result.ExecutedAs,
		Command:              step.Command,
		ExitCode:             result.ExitCode,
		TimedOut:             result.TimedOut,
		Termination:          result.Termination,
		PID:                  result.PID,
		StartedAt:            result.StartedAt,
	}
}

// interpretART interprets raw command output from an ART atomic test.
// The orchestrator now resolves commands locally and sends raw PowerShell/cmd —
// no Invoke-AtomicTest on the endpoint, so output is plain shell output.
//
// Classification is delegated to classifyExecution (outcome.go), which separates
// a real security outcome from a BAS execution problem:
//   - Audspect's own B5 guardrail vetoed it → VETOED (never attempted)
//   - blocked by a control                → PASS  (control worked)
//   - technique ran (exit 0 / completion) → FAIL  (control did not stop it)
//   - timeout/contention/missing/malformed → ERROR (BAS could not execute)
//   - explicit skip marker                → SKIPPED
func interpretART(r ExecResult, combined string) (models.CheckResult, string) {
	outcome, _, detail := classifyExecution(r, combined)
	switch outcome {
	case OutcomeVetoed:
		return models.ResultVetoed, detail
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
// Looks for a "PASS: ...", "FAIL: ...", or "SKIP: ..." structured verdict line
// ANYWHERE in the output, not only the first line (found 2026-10-09: ~38
// builtin scenarios, including scenarios/kerberoasting-ad-drill.yaml, write an
// informational line -- e.g. "EXEC T1558.003: found 3 kerberoastable
// accounts" -- before their verdict line; a first-line-only check never saw
// the verdict and silently scored every one of those findings Pass via the
// exit-code default below). If no structured prefix is found anywhere: exit 0
// = pass, non-zero = fail. If more than one verdict TYPE is present, see
// dominantVerdict's fail-safe resolution policy.
func interpretCustom(r ExecResult, combined string) (models.CheckResult, string) {
	first := strings.TrimSpace(firstLine(combined))

	if verdict, result, ok := dominantVerdict(combined); ok {
		return result, stripPrefix(verdict)
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

// dominantVerdict scans every non-empty line of s for Audspect's structured
// pass:/fail:/skip: verdict prefix -- not just the first line, see
// interpretCustom's doc comment -- and returns the fail-safe-resolved
// verdict.
//
// No committed scenario today emits more than one verdict TYPE from a single
// step execution: every step's branches are mutually exclusive (verified
// against scenarios/kerberoasting-ad-drill.yaml and the wider builtin corpus,
// 490 verdict lines across 45 files, 2026-10-09). This is a defensive
// contract for output that is malformed, corrupted, or hand-crafted, not a
// real authoring pattern -- but it must have one explicit, documented answer
// rather than an accidental one.
//
// Fail-safe policy: FAIL > SKIP > PASS, independent of line order. A FAIL
// line is never silently suppressed by a PASS or SKIP line found elsewhere in
// the same output -- mirroring this file's existing bias (see Interpret's
// Vetoed/TimedOut handling) toward never overstating a defensive win when
// there is ambiguity. Among multiple lines of the SAME winning type, the
// first one supplies the returned text.
func dominantVerdict(s string) (line string, result models.CheckResult, ok bool) {
	var failLine, skipLine, passLine string
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		lower := strings.ToLower(t)
		switch {
		case failLine == "" && strings.HasPrefix(lower, "fail:"):
			failLine = t
		case skipLine == "" && strings.HasPrefix(lower, "skip:"):
			skipLine = t
		case passLine == "" && strings.HasPrefix(lower, "pass:"):
			passLine = t
		}
	}
	switch {
	case failLine != "":
		return failLine, models.ResultFail, true
	case skipLine != "":
		return skipLine, models.ResultSkipped, true
	case passLine != "":
		return passLine, models.ResultPass, true
	}
	return "", "", false
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
