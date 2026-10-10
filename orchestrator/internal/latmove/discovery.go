// Discovery/rights-establishment (movement-path steps 1-2). This is
// independent evidence, same discipline as every other stream in this
// package: discovery observes whether a principal holds the rights a
// technique requires -- it does NOT attempt the technique, and an attempt's
// outcome is never read back to infer what discovery "should" have found.
package latmove

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
)

// AccessCondition is what discovery found about a principal's rights on a
// destination for a given technique.
type AccessCondition string

const (
	AccessGranted AccessCondition = "granted"
	AccessDenied  AccessCondition = "denied"
	AccessUnknown AccessCondition = "unknown" // discovery inconclusive
)

// AccessConditionSource discovers whether principal holds the rights tech
// requires on destination. No real implementation ships in this slice.
type AccessConditionSource interface {
	Discover(ctx context.Context, tech Technique, principal, destination string) (AccessCondition, error)
}

// FakeAccessConditionSource is the only source in this slice, keyed by
// principal+"/"+destination+"/"+tech.ID. An uncaptured key returns
// AccessUnknown -- never guessed from another principal's or destination's
// canned data.
type FakeAccessConditionSource struct {
	Conditions map[string]AccessCondition
	Err        map[string]error
}

func discoveryKey(tech Technique, principal, destination string) string {
	return principal + "/" + destination + "/" + tech.ID
}

func (f *FakeAccessConditionSource) Discover(_ context.Context, tech Technique, principal, destination string) (AccessCondition, error) {
	k := discoveryKey(tech, principal, destination)
	if err, ok := f.Err[k]; ok {
		return "", err
	}
	if c, ok := f.Conditions[k]; ok {
		return c, nil
	}
	return AccessUnknown, nil
}

// ExpectationFromDiscovery converts a discovered AccessCondition into the
// expectation for tech. ok is false for AccessUnknown: an inconclusive
// discovery must never be guessed into either expectation -- the caller
// should not evaluate this attempt at all, same fail-closed discipline as
// the rest of the package.
func ExpectationFromDiscovery(cond AccessCondition, tech Technique) (controlval.Expectation, bool) {
	switch cond {
	case AccessGranted:
		return PositiveExpectationFor(tech), true
	case AccessDenied:
		return NegativeExpectationFor(tech), true
	default:
		return controlval.Expectation{}, false
	}
}
