package scenario

import (
	"fmt"
	"strings"
)

// ExecutionOutcome is the coarse outcome of running a step, kept separate from
// the security verdict. It answers "what happened to the BAS execution" so the
// scoring layer can answer "did a security control allow the technique". A
// finding (FAIL) must mean the control let the technique run — not that the BAS
// engine hit a problem. See reportConclusion / agentFix.
type ExecutionOutcome int

const (
	OutcomeExecuted ExecutionOutcome = iota // ran to a real result; control did not stop it → FAIL
	OutcomeBlocked                          // a security control prevented it → PASS
	OutcomeError                            // BAS could not execute the technique correctly → ERROR
	OutcomeSkipped                          // intentionally not run → SKIPPED
)

// ErrorReason names *why* an execution errored. New infrastructure failures
// (agent disconnect, host reboot, worker kill, cancellation) get a named reason
// here rather than another ad-hoc string check scattered at the call site.
type ErrorReason string

const (
	ErrNone                ErrorReason = ""
	ErrTimeout             ErrorReason = "timeout"
	ErrSchedulerContention ErrorReason = "scheduler-contention"
	ErrMissingPrerequisite ErrorReason = "missing-prerequisite"
	ErrBinaryMissing       ErrorReason = "binary-missing"
	ErrDNSFailure          ErrorReason = "dns-failure"
	ErrInteractivePrompt   ErrorReason = "interactive-prompt"
	ErrMalformedContent    ErrorReason = "malformed-content"
	ErrExecution           ErrorReason = "execution-error"
)

// errorReasonLabel is the human phrase shown in the report's "What happened".
func errorReasonLabel(r ErrorReason) string {
	switch r {
	case ErrTimeout:
		return "execution timed out"
	case ErrSchedulerContention:
		return "scheduler contention (BAS resource lock)"
	case ErrMissingPrerequisite:
		return "missing prerequisite"
	case ErrBinaryMissing:
		return "required binary unavailable"
	case ErrDNSFailure:
		return "network/DNS resolution failed"
	case ErrInteractivePrompt:
		return "blocked on an interactive prompt"
	case ErrMalformedContent:
		return "malformed atomic content"
	default:
		return "execution error"
	}
}

// classifyExecutionError inspects already-lower-cased output plus the exit code
// and returns the matching ErrorReason, or ErrNone if this is not an execution
// error. Grouped by category so the set stays auditable as it grows.
func classifyExecutionError(lower string, exitCode int) ErrorReason {
	switch {
	// Our own scheduler / timeout supervisor — never a security outcome.
	case strings.Contains(lower, "schedule timeout: resource locks unavailable"):
		return ErrSchedulerContention
	case strings.Contains(lower, "exceeded execute timeout"):
		return ErrTimeout

	// Interactive prompt the test could not answer (e.g. reg save "Overwrite?").
	case strings.Contains(lower, "overwrite (yes/no)?"),
		strings.Contains(lower, "(y/n)?"),
		strings.Contains(lower, "press any key to continue"):
		return ErrInteractivePrompt

	// Network / lab-only target not reachable.
	case strings.Contains(lower, "could not resolve hostname"),
		strings.Contains(lower, "could not resolve host"),
		strings.Contains(lower, "no such host is known"):
		return ErrDNSFailure

	// Required binary/file absent or not runnable.
	case strings.Contains(lower, "test cannot continue"),
		strings.Contains(lower, "the system cannot execute the specified program"),
		strings.Contains(lower, "is not recognized as an internal or external command"),
		strings.Contains(lower, "is not recognized as the name of a cmdlet"),
		strings.Contains(lower, "curl: cannot open"):
		return ErrBinaryMissing

	// Prerequisite path/file missing.
	case strings.Contains(lower, "cannot find path"),
		strings.Contains(lower, "could not find"),
		strings.Contains(lower, "no such file or directory"),
		strings.Contains(lower, "the system cannot find the file"),
		strings.Contains(lower, "the system cannot find the path"),
		strings.Contains(lower, "cannot find the path"):
		return ErrMissingPrerequisite

	// Malformed content — parser/loader/shell rejected it before the technique
	// could run. Includes PowerShell/cmd parse errors (a crashed check script is
	// a BAS problem, not a security outcome).
	case strings.Contains(lower, "error: invalid syntax"),
		strings.Contains(lower, "error: invalid key name"),
		strings.Contains(lower, "incorrect format"),
		strings.Contains(lower, "could not load file or assembly"),
		strings.Contains(lower, "missing the terminator"),
		strings.Contains(lower, "unexpected token"),
		strings.Contains(lower, "parsererror"),
		strings.Contains(lower, "is not recognized as a cmdlet"):
		return ErrMalformedContent
	}

	// MSI / installer "invalid command line" surfaces as 1639 with no clear text.
	if exitCode == 1639 {
		return ErrMalformedContent
	}
	return ErrNone
}

// ranToCompletion reports whether output shows the technique actually executed,
// even on a non-zero exit (e.g. a trailing cleanup line failed). lower must be
// lower-cased.
func ranToCompletion(lower string) bool {
	return strings.Contains(lower, "the operation completed successfully") ||
		strings.Contains(lower, "technique ran to completion")
}

// classifyExecution maps a raw ART ExecResult to a coarse ExecutionOutcome plus,
// for errors, a reason. The returned detail is the report's "What happened" line.
func classifyExecution(r ExecResult, combined string) (ExecutionOutcome, ErrorReason, string) {
	lower := strings.ToLower(combined)

	// Explicit skip marker (missing payload, technique not in store).
	if first := strings.TrimSpace(firstLine(combined)); len(first) >= 5 && strings.EqualFold(first[:5], "skip:") {
		return OutcomeSkipped, ErrNone, strings.TrimSpace(first[5:])
	}

	// Security control prevented it.
	if sig := blockSignature(lower); sig != "" {
		return OutcomeBlocked, ErrNone, "Security control blocked the technique (" + sig + "): " + firstLine(combined)
	}
	if isBlockExitCode(r.ExitCode) {
		out := firstLine(combined)
		if out == "" {
			out = "process terminated before completion"
		}
		return OutcomeBlocked, ErrNone, fmt.Sprintf("Security control blocked the technique (exit 0x%X): %s", uint32(r.ExitCode), out)
	}

	// BAS execution error — not a security outcome.
	if reason := classifyExecutionError(lower, r.ExitCode); reason != ErrNone {
		return OutcomeError, reason, "Execution error (" + errorReasonLabel(reason) + "): " + firstLine(combined)
	}

	// Clear evidence the technique executed, even on a non-zero trailing exit.
	if ranToCompletion(lower) {
		return OutcomeExecuted, ErrNone, "Technique executed: " + firstLine(combined)
	}

	if r.ExitCode == 0 {
		out := firstLine(combined)
		if out == "" {
			out = "technique ran to completion"
		}
		return OutcomeExecuted, ErrNone, "Technique executed: " + out
	}

	// Non-zero exit with no recognizable signal: the technique did not reach a
	// real result and we cannot assert a control allowed it — record an
	// execution error rather than a false security finding.
	return OutcomeError, ErrExecution, fmt.Sprintf("Execution error (exit %d): %s", r.ExitCode, firstLine(combined))
}
