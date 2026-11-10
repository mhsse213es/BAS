package wafmodsec

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafval"
)

// BuildBurstCollectionResults turns a real, bounded burst of HTTP round
// trips (modsecwaf.Client.SendBurst) into the same two
// wafval.CollectionResult mechanisms BuildCollectionResults derives from one
// -- a rate-limit claim is only meaningful across the whole burst, so
// Enforcement here reflects whether the WAF/rate-limiter blocked AT LEAST
// ONE request once the declared limit was exceeded, not any single
// response's own status.
//
// wafval.EvaluateClaim cross-checks the WAF-engine and origin-app mechanisms
// as two views of the SAME event, so both must agree on direction here, the
// same way they do for one request in BuildCollectionResults: when at least
// one response was blocked, the origin evidence reported is the blocked
// subset's own (it never reached origin, by definition); only when NOTHING
// in the whole burst was ever blocked does the origin evidence reflect the
// allowed subset reaching it. Reporting both "some reached" and "some
// blocked" as independent facts would describe two different requests as
// one event and resolve Inconclusive by contradiction instead of the real
// finding -- a rate limit enforced, or not enforced at all.
func BuildBurstCollectionResults(responses []modsecwaf.RawResponse, key wafval.CorrelationKey, observedAt time.Time) []wafval.CollectionResult {
	reached, blocked := 0, 0
	for _, r := range responses {
		if originReceived(r) {
			reached++
		} else {
			blocked++
		}
	}
	enforced := blocked > 0

	enf := wafval.EnforcementAllowed
	if enforced {
		enf = wafval.EnforcementBlocked
	}
	waf := wafval.CollectionResult{
		Mechanism: wafval.MechanismWAFEngine,
		Coverage:  wafval.CoverageFound,
		Observations: []wafval.Observation{{
			Mechanism:    wafval.MechanismWAFEngine,
			Provider:     "modsecurity-crs",
			RequestID:    key.RequestID,
			ObservedAt:   observedAt,
			Enforcement:  enf,
			Detection:    wafval.DetectionUnknown,
			Origin:       wafval.OriginUnknown,
			EvidenceKind: wafval.EvidenceObserved,
			Detail:       fmt.Sprintf("burst of %d requests: %d reached origin, %d blocked", len(responses), reached, blocked),
		}},
	}

	originState := wafval.OriginNotObserved
	coverage := wafval.CoverageSearchedVerifiedNone
	detail := fmt.Sprintf("enforcement fired partway through the burst: the blocked requests never reached origin (%d/%d overall did)", reached, len(responses))
	if !enforced {
		originState = wafval.OriginReceived
		coverage = wafval.CoverageFound
		detail = fmt.Sprintf("no enforcement observed: all %d burst requests reached origin", len(responses))
	}
	origin := wafval.CollectionResult{
		Mechanism: wafval.MechanismOriginApp,
		Coverage:  coverage,
		Observations: []wafval.Observation{{
			Mechanism:    wafval.MechanismOriginApp,
			Provider:     "http-echo-origin",
			RequestID:    key.RequestID,
			ObservedAt:   observedAt,
			Enforcement:  wafval.EnforcementUnknown,
			Detection:    wafval.DetectionUnknown,
			Origin:       originState,
			EvidenceKind: wafval.EvidenceObserved,
			Detail:       detail,
		}},
	}

	return []wafval.CollectionResult{waf, origin}
}
