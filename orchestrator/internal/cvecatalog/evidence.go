package cvecatalog

import (
	"time"

	"github.com/audspect/bas/internal/cveval"
)

// EvaluateConfigIndicator compares an observed configuration indicator
// against this entry's two declared fixtures and returns the resulting
// cveval.Result. It is a pure, I/O-free comparison -- exact string equality
// only, no fuzzy or partial match, so a near-miss indicator never produces
// a false sense of coverage. An empty observed string is SKIPPED, never
// guessed at. now is injected so tests are deterministic.
func (e CVEEntry) EvaluateConfigIndicator(observed string, now time.Time) cveval.Result {
	if observed == "" {
		return cveval.Result{
			CVEID:   e.ID,
			Verdict: cveval.VerdictSkipped,
			Detail:  "no configuration indicator was supplied to compare against this entry's fixtures",
		}
	}
	switch observed {
	case e.VulnerableFixture.Indicator:
		return cveval.Result{
			CVEID:   e.ID,
			Verdict: cveval.VerdictVulnerable,
			Evidence: cveval.Evidence{
				Source:     cveval.SourceFixture,
				Detail:     "observed indicator matched the known-vulnerable fixture: " + e.VulnerableFixture.Description,
				ObservedAt: now,
			},
		}
	case e.PatchedFixture.Indicator:
		return cveval.Result{
			CVEID:   e.ID,
			Verdict: cveval.VerdictNotVulnerable,
			Evidence: cveval.Evidence{
				Source:     cveval.SourceFixture,
				Detail:     "observed indicator matched the known-patched fixture: " + e.PatchedFixture.Description,
				ObservedAt: now,
			},
		}
	default:
		return cveval.Result{
			CVEID:   e.ID,
			Verdict: cveval.VerdictInconclusive,
			Detail:  "observed indicator matched neither the vulnerable nor the patched fixture signature for " + e.ID,
		}
	}
}
