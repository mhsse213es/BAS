// Package wafmodsec is the real (non-fixture) bridge from a live
// ModSecurity + OWASP CRS WAF's actual HTTP responses, fetched via
// internal/vendors/modsecwaf, into internal/wafval's vendor-neutral
// evidence model. It performs no HTTP I/O itself and depends only on
// wafval and modsecwaf's already-produced RawResponse -- mirrors
// internal/avdefender's split from internal/vendors/defender exactly.
//
// This bridge reads only the live WAF's real HTTP status code and the
// origin echo server's distinctive response body -- see
// lab/wafmodsec/docker-compose.yml's own doc comment for why a single
// proxied HTTP response carries two independent mechanisms' evidence
// (the WAF's own enforcement decision, and the origin app's own
// receipt confirmation). It does NOT parse ModSecurity's audit log, so
// it never asserts wafval.DetectionMatched or wafval.DetectionNotMatched
// -- every Observation here carries wafval.DetectionUnknown. That means
// an allowed-through request can resolve to VerdictAllowed or
// VerdictIncorrectlyBlocked (ClaimFalsePositive, which depends on
// enforcement only) but never to the Prevention claim's VerdictMissed
// (which requires a resolved detection axis) -- it resolves to
// VerdictInconclusive instead, honestly reflecting that this version
// does not yet read detection evidence. Reading the audit log to close
// that gap is a deliberate, disclosed follow-up, not an oversight.
package wafmodsec

import (
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafval"
)

// originEchoMarker is the http-https-echo image's own, deterministic JSON
// field -- present in every response it produces, and in no ModSecurity or
// nginx error page. Its presence in a raw response body is the origin
// mechanism's own receipt evidence: the request reached the real backend.
const originEchoMarker = `"method":`

// originReceived reports whether resp's body is the origin echo server's own
// response, as opposed to a WAF/proxy-generated error page.
func originReceived(resp modsecwaf.RawResponse) bool {
	return strings.Contains(string(resp.Body), originEchoMarker)
}

// BuildCollectionResults turns one real HTTP round trip's raw response into
// the two independent wafval.CollectionResult values EvaluateClaim expects:
// the WAF engine's own enforcement decision, and the origin app's own
// receipt confirmation. observedAt is the real wall-clock time the response
// was received, supplied by the caller rather than read from time.Now() here
// to keep this function pure and testable.
func BuildCollectionResults(resp modsecwaf.RawResponse, key wafval.CorrelationKey, observedAt time.Time) []wafval.CollectionResult {
	reachedOrigin := originReceived(resp)

	enf := wafval.EnforcementBlocked
	if reachedOrigin {
		enf = wafval.EnforcementAllowed
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
			Detail:       fmt.Sprintf("live HTTP status %d", resp.StatusCode),
		}},
	}

	originState := wafval.OriginNotObserved
	coverage := wafval.CoverageSearchedVerifiedNone
	detail := "origin echo marker absent from response body"
	if reachedOrigin {
		originState = wafval.OriginReceived
		coverage = wafval.CoverageFound
		detail = "origin echo marker present in response body"
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
