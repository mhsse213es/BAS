// Package avdefender is the real (non-fixture) bridge from Microsoft
// Defender for Endpoint's actual API responses, fetched via
// internal/vendors/defender, into internal/avval's vendor-neutral
// evidence model. It performs no HTTP I/O itself and depends only on
// avval and vendors/defender's already-produced data/errors -- callers
// in internal/api own fetching the real data (QueryAlerts, ListMachines)
// and pass the results, or the real error, here.
//
// This bridge never asserts a Prevention outcome from alert evidence:
// a Defender alert tells you something was detected/investigated, not
// whether the underlying action was blocked before it ran. Every
// Observation it produces carries Prevention: avval.PreventionUnknown.
// It also never equates an absence of alerts with a confirmed negative
// unless the target device was independently confirmed healthy and
// reporting (deviceHealthy) -- an absence of evidence for a device that
// might not even be sending telemetry proves nothing.
package avdefender

import (
	"fmt"
	"slices"
	"strings"

	"github.com/audspect/bas/internal/avval"
	"github.com/audspect/bas/internal/vendors/defender"
)

// BuildCollectionResult turns one device+technique+window correlation
// target's real Defender evidence into an avval.CollectionResult.
// Exactly one of (alerts, queryErr) is meaningful: queryErr non-nil
// means the underlying defender.Client.QueryAlerts call itself failed,
// and alerts is ignored. deviceHealthy must come from an independent,
// real check (e.g. defender.Client.ListMachines confirming the device
// is Active/reporting) -- never assumed true.
//
// ControlSource is always avval.ControlSourceEDR: Defender's
// /security/alerts_v2 endpoint correlates behavioral and signature
// signals into XDR-style alerts, closer to avval's own EDR bucket than
// a raw AV-engine signature hit (see avval.ControlSource's own doc
// comment on EDR-vs-AV-engine attribution).
func BuildCollectionResult(deviceDNSName, techniqueID string, window avval.TimeWindow, deviceHealthy bool, alerts []defender.Alert, queryErr error) (avval.CollectionResult, error) {
	if queryErr != nil {
		return collectionResultForError(queryErr), nil
	}

	var matched *defender.Alert
	var anyForDevice bool
	for i := range alerts {
		a := &alerts[i]
		if !strings.EqualFold(a.DeviceDNSName, deviceDNSName) {
			continue
		}
		anyForDevice = true
		if containsTechnique(a.Techniques, techniqueID) {
			matched = a
			break
		}
	}

	if matched != nil {
		return avval.CollectionResult{
			ControlSource: avval.ControlSourceEDR,
			Coverage:      avval.CoverageFound,
			Observations: []avval.Observation{{
				ControlSource: avval.ControlSourceEDR,
				Provider:      "Microsoft Defender for Endpoint",
				EventID:       matched.ID,
				ObservedAt:    matched.Timestamp,
				Prevention:    avval.PreventionUnknown,
				Detection:     avval.DetectionDetected,
				MatchedRule:   matched.RuleName,
				EvidenceKind:  avval.EvidenceObserved,
				Detail:        fmt.Sprintf("alert %s matched technique %s on device %s", matched.ID, techniqueID, deviceDNSName),
			}},
		}, nil
	}

	// No alert matched this technique on this device. Whether that
	// absence is a confirmed negative depends entirely on whether the
	// device is independently known to be healthy and reporting --
	// anyForDevice (other alerts exist for this device) is one honest
	// signal of that, but deviceHealthy is the authoritative one since
	// a device can be healthy and genuinely have zero alerts at all.
	if deviceHealthy || anyForDevice {
		return avval.CollectionResult{
			ControlSource: avval.ControlSourceEDR,
			Coverage:      avval.CoverageSearchedVerifiedNone,
			Observations: []avval.Observation{{
				ControlSource: avval.ControlSourceEDR,
				Provider:      "Microsoft Defender for Endpoint",
				Detection:     avval.DetectionNotObservedInWindow,
				EvidenceKind:  avval.EvidenceObserved,
				Detail:        fmt.Sprintf("searched device %s for technique %s in the given window; device confirmed reporting, no matching alert found", deviceDNSName, techniqueID),
			}},
		}, nil
	}

	return avval.CollectionResult{
		ControlSource: avval.ControlSourceEDR,
		Coverage:      avval.CoverageSearchIncomplete,
	}, nil
}

func containsTechnique(techniques []string, techniqueID string) bool {
	return slices.Contains(techniques, techniqueID)
}

// collectionResultForError maps a real defender query failure into the
// correct avval.Coverage, distinguishing a permanent, never-self-
// resolving reason (no license, no permission, no valid token --
// CoverageSourceUnavailable) from a transient, retry-later reason (rate
// limited, server error, or an unclassified error -- CoverageSearchIncomplete).
// A *defender.ClassifiedError's Kind drives the distinction; any other
// error type is treated as search-incomplete, never as a confirmed
// negative.
func collectionResultForError(err error) avval.CollectionResult {
	ce, ok := err.(*defender.ClassifiedError)
	if !ok {
		return avval.CollectionResult{ControlSource: avval.ControlSourceEDR, Coverage: avval.CoverageSearchIncomplete}
	}
	switch ce.Kind {
	case defender.ErrKindFeatureDisabled:
		return sourceUnavailable("Defender for Endpoint is not licensed/enabled for this tenant (vendor error code DisabledFeature) -- this is a licensing gap, not a permission or connectivity problem")
	case defender.ErrKindInsufficientPermission:
		return sourceUnavailable("the app registration lacks the required application permission or admin consent for this call (vendor error code Forbidden) -- granting the missing permission is the fix, not a license purchase")
	case defender.ErrKindUnauthorized:
		return sourceUnavailable("the access token was missing, invalid, or expired (vendor error code Unauthorized) -- re-authenticating is the fix")
	case defender.ErrKindRateLimited, defender.ErrKindTransient:
		return avval.CollectionResult{ControlSource: avval.ControlSourceEDR, Coverage: avval.CoverageSearchIncomplete}
	default:
		return avval.CollectionResult{ControlSource: avval.ControlSourceEDR, Coverage: avval.CoverageSearchIncomplete}
	}
}

func sourceUnavailable(detail string) avval.CollectionResult {
	return avval.CollectionResult{
		ControlSource: avval.ControlSourceEDR,
		Coverage:      avval.CoverageSourceUnavailable,
		Observations: []avval.Observation{{
			ControlSource: avval.ControlSourceEDR,
			Provider:      "Microsoft Defender for Endpoint",
			Detection:     avval.DetectionUnknown,
			EvidenceKind:  avval.EvidenceObserved,
			Detail:        detail,
		}},
	}
}
