package scenario

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/models"
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
	ErrEnvArtifact         ErrorReason = "environmental-artifact"
	ErrExecution           ErrorReason = "execution-error"
	// ErrProcessSpawnFailed is Go's own fork/exec failure -- the agent's
	// OS-level attempt to launch the step's process failed before any
	// atomic content ever ran (e.g. a Windows CreateProcess handle
	// error). Distinct from ErrMalformedContent: this is an agent/host
	// problem, never anything about the atomic test's own content, and
	// must be classified before the generic "is invalid" match below
	// would otherwise catch Go's own "The handle is invalid." text and
	// mislabel it as malformed content.
	ErrProcessSpawnFailed ErrorReason = "process-spawn-failed"
	// ErrCancelled marks a step that was still in-flight when the scenario
	// itself was cancelled (stuck-technique force-cancel, manual stop, agent
	// shutdown). The agent kills the process and submits it anyway so its
	// partial output isn't lost, but the resulting exit code is an artifact
	// of the kill, not a real security outcome -- it must never be scored as
	// a FAIL/finding. See agent/executor.go's matching stderr marker.
	ErrCancelled ErrorReason = "cancelled"
)

// errorReasonLabel is the human phrase shown in the report's "What happened".
func errorReasonLabel(r ErrorReason) string {
	switch r {
	case ErrTimeout:
		return "execution timed out"
	case ErrCancelled:
		return "run cancelled — step was interrupted before completion"
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
	case ErrProcessSpawnFailed:
		return "agent could not launch the process — an OS/host problem, not the atomic's content"
	case ErrEnvArtifact:
		return "environmental artifact (resource already present)"
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

	// The step was still in-flight when the scenario itself was cancelled
	// (agent/executor.go tags it this way rather than leaving a bare,
	// ambiguous exit code). Never a security outcome — it's a kill artifact.
	case strings.Contains(lower, "step interrupted by scenario cancellation"):
		return ErrCancelled

	// Go's own exec.Cmd.Start() failure -- the agent process could not even
	// launch the step (e.g. a Windows CreateProcess handle error), before
	// any atomic content had a chance to run. Always begins "fork/exec " on
	// every platform Go supports (see agent/executor.go's cmd.Start() error
	// path), a specific, unambiguous signature -- must be checked before
	// the generic "is invalid" malformed-content match below, since Go's
	// own text ("The handle is invalid.") would otherwise collide with it
	// and mislabel an agent/host problem as bad atomic content.
	case strings.Contains(lower, "fork/exec "):
		return ErrProcessSpawnFailed

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

	// Prerequisite path/file/runtime-dependency missing. The technique never ran
	// because something it needed was absent — not a security outcome. Includes
	// the PowerShell IWR/Internet-Explorer-engine dependency (T1105-class tests)
	// which fails with exit 0 yet did nothing.
	case strings.Contains(lower, "cannot find path"),
		strings.Contains(lower, "could not find"),
		strings.Contains(lower, "no such file or directory"),
		strings.Contains(lower, "the system cannot find the file"),
		strings.Contains(lower, "the system cannot find the path"),
		strings.Contains(lower, "cannot find the path"),
		strings.Contains(lower, "internet explorer engine is not available"),
		strings.Contains(lower, "response content cannot be parsed"):
		return ErrMissingPrerequisite

	// Malformed content — parser/loader/shell rejected it, or the atomic passed a
	// bad path/argument, before the technique could run. Many of these surface on
	// a ZERO exit code (a PowerShell non-terminating error prints to the stream
	// but leaves $LASTEXITCODE 0), so they must be caught here — not assumed to be
	// a successful execution. A crashed/malformed step is a BAS problem, not a
	// security finding.
	case strings.Contains(lower, "error: invalid syntax"),
		strings.Contains(lower, "error: invalid key name"),
		strings.Contains(lower, "incorrect format"),
		strings.Contains(lower, "could not load file or assembly"),
		strings.Contains(lower, "missing the terminator"),
		strings.Contains(lower, "unexpected token"),
		strings.Contains(lower, "parsererror"),
		strings.Contains(lower, "is not recognized as a cmdlet"),
		strings.Contains(lower, "is invalid"),
		strings.Contains(lower, "is not valid"),
		strings.Contains(lower, "not a valid win32 application"):
		return ErrMalformedContent

	// Environmental artifact — the resource the atomic tried to create was already
	// present, so the create was a no-op. This is prior state, not proof the
	// technique succeeded (e.g. a persistence key/file that already existed).
	case strings.Contains(lower, "already exists"),
		strings.Contains(lower, "cannot create a file when that file already exists"):
		return ErrEnvArtifact
	}

	// MSI / installer "invalid command line" surfaces as 1639 with no clear text.
	if exitCode == 1639 {
		return ErrMalformedContent
	}
	return ErrNone
}

// classifySkipReason maps the free-text detail of a "SKIP:" marker (already
// stripped of its prefix) to a models.SkipReason* bucket. Every message this
// matches against is authored by our own server code (art.go/builder.go),
// never third-party program output, so this is a small, fully-enumerable
// vocabulary — not a fragile heuristic. Returns "" for unrecognized text
// (the reporting layer's bucket aggregation falls that back to Platform).
func classifySkipReason(detail string) string {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "not available on server"):
		return models.SkipReasonMissingContent
	case strings.Contains(lower, "not in local store"),
		strings.Contains(lower, "no command defined"),
		strings.Contains(lower, "caldera not configured"),
		strings.Contains(lower, "caldera ability") && strings.Contains(lower, "not found"):
		return models.SkipReasonPlatformUnavailable
	}
	return ""
}

// ranToCompletion reports whether output shows the technique actually executed,
// even on a non-zero exit (e.g. a trailing cleanup line failed). lower must be
// lower-cased.
func ranToCompletion(lower string) bool {
	return strings.Contains(lower, "the operation completed successfully") ||
		strings.Contains(lower, "technique ran to completion")
}

// executedDetail is the security-meaning prefix for a technique that ran
// without being stopped. Real evidence (the step's actual output) is appended
// via withEvidence below, clearly labelled -- never blended in unlabelled,
// which is what made raw output alone (e.g. "Hello, from PowerShell!")
// misread as if it were the important part rather than trivia. Leading with
// the security conclusion and labelling the output as evidence gives both:
// what a control failed to stop, and specifically what happened.
const executedDetail = "Security control did not prevent this technique — it executed without being blocked."

// withEvidence appends a step's actual output to a headline as clearly
// labelled evidence, so a reader gets the security conclusion AND the real,
// specific output — not one or the other. Returns headline unchanged when
// there's no output to show.
func withEvidence(headline, combined string) string {
	ev := strings.TrimSpace(firstLine(combined))
	if ev == "" {
		return headline
	}
	return headline + " Output: " + ev
}

// classifyExecution maps a raw ART ExecResult to a coarse ExecutionOutcome plus,
// for errors, a reason. The returned detail is the report's "What happened" line.
func classifyExecution(r ExecResult, combined string) (ExecutionOutcome, ErrorReason, string) {
	lower := strings.ToLower(combined)

	// A step killed on its own deadline produced no result, so its partial
	// output cannot be evidence of a security outcome. This MUST stay ahead of
	// blockSignature below: a timed-out `grep -ri password /` emits thousands of
	// "Permission denied" lines, which blockSignature reads as an access-denied
	// block and would score PASS -- counting a technique that never finished as
	// a control success. Interpret applies the same guard for every framework;
	// this one keeps the ART path correct when classifyExecution is called
	// directly. The structured flag is authoritative -- the "exceeded execute
	// timeout" text below is only a fallback, and it is absent whenever the
	// step wrote anything of its own to stderr.
	if r.TimedOut {
		return OutcomeError, ErrTimeout, "Execution error (timed out): step killed at its execute deadline without completing; partial output is not a security result"
	}

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
	// Lead with the SECURITY meaning — the control did not prevent it — then
	// append the actual output as labelled evidence (withEvidence), so the
	// headline states both the conclusion and specifically what happened.
	if ranToCompletion(lower) {
		return OutcomeExecuted, ErrNone, withEvidence(executedDetail, combined)
	}

	if r.ExitCode == 0 {
		return OutcomeExecuted, ErrNone, withEvidence(executedDetail, combined)
	}

	// Non-zero exit with no recognizable signal: the technique did not reach a
	// real result and we cannot assert a control allowed it — record an
	// execution error rather than a false security finding.
	return OutcomeError, ErrExecution, fmt.Sprintf("Execution error (exit %d): %s", r.ExitCode, firstLine(combined))
}
