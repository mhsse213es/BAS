package correlation

import (
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/verification"
)

// lookupValidation checks the prevention verdict map first, then the
// validation (detection) map -- matching threatpriority.scoreActor's own
// precedence (engine.go:190-196). Returns nil when a technique has never
// been validated by either path.
func lookupValidation(techniqueID string, prevention, validation map[string]threatpriority.VerdictEntry) *ValidationStatus {
	id := strings.ToUpper(strings.TrimSpace(techniqueID))
	if v, ok := prevention[id]; ok {
		return &ValidationStatus{Verdict: v.Verdict, Source: "prevention", At: v.At}
	}
	if v, ok := validation[id]; ok {
		return &ValidationStatus{Verdict: v.Verdict, Source: "detection", At: v.At}
	}
	return nil
}

// isSuccessVerdict mirrors validation_factors.go's own two isSuccess
// predicates (v == "pass" for prevention, v == verification.ResultDetected
// for validation) collapsed into one function, since Recommendation doesn't
// need to know which path produced the verdict to judge success/failure.
func isSuccessVerdict(v string) bool {
	return v == "pass" || v == verification.ResultDetected
}

// computeRecommendation is the one judgment call this package makes.
func computeRecommendation(v *ValidationStatus, hasScenario bool) Recommendation {
	if v == nil {
		if hasScenario {
			return Recommendation{Action: "run", Reason: "Never validated"}
		}
		return Recommendation{Action: "no_scenario", Reason: "No scenario available for this technique"}
	}
	days := int(time.Since(v.At).Hours() / 24)
	if isSuccessVerdict(v.Verdict) {
		return Recommendation{Action: "none", Reason: fmt.Sprintf("Validated %d days ago", days)}
	}
	return Recommendation{Action: "revalidate", Reason: fmt.Sprintf("Last run %d days ago, %s", days, v.Verdict)}
}
