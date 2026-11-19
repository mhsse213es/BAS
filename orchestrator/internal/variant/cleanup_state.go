package variant

import (
	"fmt"
	"strings"
)

// CleanupState is the cleanup outcome of a whole variant run. It is recorded beside the attack verdict and never
// replaces it: a run can pass its detection objective and still fail cleanup.
type CleanupState string

const (
	CleanupNotRequired CleanupState = "NOT_REQUIRED" // no step changed state, so nothing needed reverting
	CleanupPending     CleanupState = "PENDING"      // a step needed cleanup and its result has not arrived
	CleanupSucceeded   CleanupState = "SUCCEEDED"    // every step that needed cleanup was reverted
	CleanupFailed      CleanupState = "FAILED"       // a cleanup was not clean, or a step ran with no verified cleanup
)

// CleanupStep is one variant step as it bears on cleanup.
type CleanupStep struct {
	TaskID       string
	NeedsCleanup bool   // the step carries a cleanup command, so the agent reverts it
	Unverified   bool   // the step ran with no cleanup and is not read-only, so nothing reverted it
	Verdict      string // the agent's CleanupVerdict: reverted | rescued | partial | leaked | "" if not yet reported
	Error        string // the agent's CleanupError for a failed revert
}

// SummarizeCleanup rolls step cleanups up into one run state, the failure text, and whether a person must remediate.
// A failure outranks pending work, so a run is never shown as clean while a revert is still unknown.
func SummarizeCleanup(steps []CleanupStep) (CleanupState, string, bool) {
	var failures []string
	pending, considered := false, false
	for _, s := range steps {
		if !s.NeedsCleanup && !s.Unverified {
			continue
		}
		considered = true
		switch {
		case s.Unverified:
			failures = append(failures, fmt.Sprintf("%s ran without a verified cleanup, so nothing reverted it", s.TaskID))
		case s.Verdict == "partial" || s.Verdict == "leaked":
			detail := s.Error
			if detail == "" {
				detail = "cleanup " + s.Verdict
			}
			failures = append(failures, fmt.Sprintf("%s: %s", s.TaskID, detail))
		case s.Verdict == "reverted" || s.Verdict == "rescued":
		default:
			pending = true
		}
	}
	switch {
	case len(failures) > 0:
		return CleanupFailed, strings.Join(failures, "; "), true
	case pending:
		return CleanupPending, "", false
	case considered:
		return CleanupSucceeded, "", false
	}
	return CleanupNotRequired, "", false
}
