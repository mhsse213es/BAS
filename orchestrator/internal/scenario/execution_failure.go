package scenario

import (
	"strings"

	"github.com/audspect/bas/internal/models"
)

// failureTemplate is the customer-facing wording and routing for one ErrorReason.
type failureTemplate struct {
	status, category, reason, stage, owner, remediation string
}

var failureTemplates = map[ErrorReason]failureTemplate{
	ErrBinaryMissing:       {"not_executed", "missing_dependency", "A tool this simulation needs is not available on the endpoint.", "prerequisite_validation", "environment", "Install the required tool on the endpoint, or exclude this simulation for this host."},
	ErrMissingPrerequisite: {"not_executed", "missing_prerequisite", "A Windows component, file or resource this simulation needs is not available.", "prerequisite_validation", "environment", "Check that the endpoint has the required component and that outbound downloads are allowed, then re-run."},
	ErrDNSFailure:          {"not_executed", "external_dependency", "A network name could not be resolved, so the simulation could not reach its target.", "execution", "environment", "Confirm DNS and outbound access from the endpoint to the simulation's target, then re-run."},
	ErrInteractivePrompt:   {"execution_error", "execution_error", "The simulation stopped at a prompt that needs a person to answer.", "execution", "audspect", "Report this simulation to Audspect: it needs to run without prompting."},
	ErrMalformedContent:    {"execution_error", "content_defect", "The simulation definition was rejected by Windows or the shell before it could run.", "execution", "audspect", "Report this simulation to Audspect. It is a content defect, not a problem with your environment."},
	ErrEnvArtifact:         {"not_executed", "environment_conflict", "A resource the simulation creates already exists on the endpoint, so it could not run cleanly.", "execution", "environment", "Remove the leftover resource or re-run after the endpoint has been restored."},
	ErrProcessSpawnFailed:  {"execution_error", "host_problem", "The agent could not launch the process for this simulation.", "launch", "audspect", "Check the agent's service account and host health; report it to Audspect if it repeats."},
	ErrSchedulerContention: {"not_executed", "host_problem", "The simulation waited for a shared resource and never got it.", "supervision", "audspect", "Re-run when fewer simulations are running on the endpoint."},
	ErrTimeout:             {"timed_out", "timeout", "The simulation exceeded its permitted run time and was stopped.", "supervision", "environment", "Re-run; if it repeats, the endpoint may be too slow or the technique may be waiting on something that never arrives."},
	ErrCancelled:           {"cancelled", "cancelled", "The run was stopped while this simulation was in progress.", "supervision", "environment", "Re-run the assessment if the result is needed."},
	ErrExecution:           {"execution_error", "execution_error", "The simulation failed unexpectedly and produced no usable result.", "execution", "audspect", "Review the technical diagnostics; report it to Audspect if it repeats."},
}

// assessExecutionFailure builds the normalised failure for an ERROR result, or nil for any other result. The reason is
// read back from the label the classifier wrote into details, so the two cannot disagree.
func assessExecutionFailure(res models.CheckResult, r ExecResult, details string) *models.ExecutionFailure {
	if res != models.ResultError {
		return nil
	}
	reason := ErrExecution
	lower := strings.ToLower(details)
	if r.TimedOut {
		reason = ErrTimeout
	} else {
		for code := range failureTemplates {
			if code == ErrExecution {
				continue
			}
			if strings.Contains(lower, "execution error ("+strings.ToLower(errorReasonLabel(code))+")") {
				reason = code
				break
			}
		}
	}
	t := failureTemplates[reason]
	raw := details
	if strings.HasPrefix(raw, "Execution error (") {
		if i := strings.Index(raw, "): "); i >= 0 {
			raw = raw[i+3:]
		}
	}
	return &models.ExecutionFailure{
		ExecutionStatus:    t.status,
		SecurityVerdict:    "not_assessed",
		Category:           t.category,
		Code:               string(reason),
		Reason:             t.reason,
		Stage:              t.stage,
		Owner:              t.owner,
		EvidenceConfidence: "none",
		Remediation:        t.remediation,
		RawError:           raw,
	}
}
