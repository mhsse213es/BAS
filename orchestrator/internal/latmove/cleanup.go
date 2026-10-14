// Cleanup verification (movement-path step 7's missing half). Confirms a
// persistent artifact created by an attempt was GENUINELY removed -- not
// merely that a delete command ran. Independent evidence, same discipline as
// every other stream: it never reads AttemptResult/Observation, and no path
// here infers removal from the attempt's own success/failure.
package latmove

import (
	"context"

	"github.com/audspect/bas/internal/adprimitive"
)

// RequiresCleanupVerification reports whether tech creates a persistent
// artifact that must be confirmed removed. Derived from RiskClass, never
// re-decided per technique: potentially_destructive techniques (remote
// service creation, scheduled task) leave an artifact; non_destructive
// techniques (WMI, WinRM, RDP) create none, so there is nothing to verify.
func RequiresCleanupVerification(tech Technique) bool {
	return tech.RiskClass == adprimitive.RiskPotentiallyDestructive
}

// CleanupResult is whether a persistent artifact was confirmed removed.
type CleanupResult string

const (
	CleanupConfirmed     CleanupResult = "confirmed"     // artifact confirmed absent after teardown
	CleanupFailed        CleanupResult = "failed"        // artifact still present after a teardown attempt
	CleanupIndeterminate CleanupResult = "indeterminate" // could not verify either way
)

// CleanupVerifier confirms whether an attempt's persistent artifact was
// genuinely removed. No real implementation ships in this slice.
type CleanupVerifier interface {
	VerifyCleanup(ctx context.Context, key AttemptKey) (CleanupResult, error)
}

// FakeCleanupVerifier is the only verifier in this slice, keyed by
// RunID+"/"+Technique. An uncaptured key returns Indeterminate -- never
// guessed as Confirmed or Failed from another key's data.
type FakeCleanupVerifier struct {
	Results map[string]CleanupResult
	Err     map[string]error
}

func (f *FakeCleanupVerifier) VerifyCleanup(_ context.Context, key AttemptKey) (CleanupResult, error) {
	k := key.RunID + "/" + key.Technique
	if err, ok := f.Err[k]; ok {
		return "", err
	}
	if r, ok := f.Results[k]; ok {
		return r, nil
	}
	return CleanupIndeterminate, nil
}
