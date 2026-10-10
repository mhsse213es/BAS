package rwevidence

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
)

// SurvivalResult is whether the recovery mechanisms targeted by an
// authorized T1490 attempt (the specific shadow copies / backup catalog
// entries involved) survived.
type SurvivalResult string

const (
	SurvivalConfirmed     SurvivalResult = "confirmed"     // targeted copies/catalog entries still present
	SurvivalLost          SurvivalResult = "lost"          // confirmed destroyed
	SurvivalIndeterminate SurvivalResult = "indeterminate" // could not verify either way
)

// RecoveryObserver observes whether the targeted recovery mechanisms
// survived an authorized attempt. No real implementation ships in this
// slice -- enumerating real shadow copies/backup catalogs needs a live
// endpoint.
type RecoveryObserver interface {
	ObserveSurvival(ctx context.Context, key AttemptKey) (SurvivalResult, error)
}

// FakeRecoveryObserver is the only observer in this slice, keyed by
// RunID+"/"+TechniqueID. An uncaptured key returns SurvivalIndeterminate --
// never guessed Confirmed or Lost from another key's data.
type FakeRecoveryObserver struct {
	Results map[string]SurvivalResult
	Err     map[string]error
}

func recoveryKey(key AttemptKey) string {
	return key.RunID + "/" + key.TechniqueID
}

func (f *FakeRecoveryObserver) ObserveSurvival(_ context.Context, key AttemptKey) (SurvivalResult, error) {
	k := recoveryKey(key)
	if err, ok := f.Err[k]; ok {
		return "", err
	}
	if r, ok := f.Results[k]; ok {
		return r, nil
	}
	return SurvivalIndeterminate, nil
}

// recoveryScopeNote is appended to every Recovery Reason so no caller can
// read a Confirmed/Lost result as a claim about overall backup posture.
const recoveryScopeNote = "scoped to the specific shadow copies/backup catalog entries targeted by this authorized attempt -- not a claim about overall backup recoverability"

// RecoveryFromSurvival grades the Recovery capability for tech from a
// SurvivalResult. corroboratingDetail (e.g. the existing
// windows_vss_inhibition detection-profile alerts) rides along in Reason as
// supporting detail ONLY -- it never changes the Verdict by itself, same
// invariant as DCSync's 4662 corroboration and latmove's
// SecondaryLogObserved.
func RecoveryFromSurvival(tech Technique, result SurvivalResult, corroboratingDetail string) CapabilityResult {
	cr := CapabilityResult{Capability: CapabilityRecovery, TechniqueID: tech.MitreID}
	switch result {
	case SurvivalConfirmed:
		cr.Verdict = controlval.VerdictPass
		cr.Reason = "targeted recovery data survived the attempt (" + recoveryScopeNote + ")"
	case SurvivalLost:
		cr.Verdict = controlval.VerdictFail
		cr.Reason = "targeted recovery data was destroyed (" + recoveryScopeNote + ")"
	default:
		cr.Verdict = controlval.VerdictSkipped
		cr.SkipReason = controlval.SkipInsufficientEvidence
		cr.Reason = "could not verify survival either way (" + recoveryScopeNote + ")"
	}
	if corroboratingDetail != "" {
		cr.Reason += "; corroboration: " + corroboratingDetail
	}
	return cr
}

// RecoveryResultFor combines an observer's outcome and technical error into
// a Recovery CapabilityResult. An operational error takes precedence over
// any SurvivalResult, same error-precedence rule controlval.Evaluate
// enforces for opErr.
func RecoveryResultFor(tech Technique, result SurvivalResult, obsErr error, corroboratingDetail string) CapabilityResult {
	if obsErr != nil {
		return CapabilityResult{
			Capability:  CapabilityRecovery,
			TechniqueID: tech.MitreID,
			Verdict:     controlval.VerdictError,
			Reason:      "recovery observation failed: " + obsErr.Error(),
		}
	}
	return RecoveryFromSurvival(tech, result, corroboratingDetail)
}
