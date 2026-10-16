// Package avsentinelone is the real (non-fixture) bridge from
// SentinelOne's actual API responses, fetched via
// internal/vendors/sentinelone, into internal/avval's vendor-neutral
// evidence model. It performs no HTTP I/O itself and depends only on
// avval and vendors/sentinelone's already-produced data/errors --
// callers in internal/api own fetching the real data (QueryThreats,
// ListAgents) and pass the results, or the real error, here. Mirrors
// internal/avdefender's bridge, with two deliberate differences driven
// by SentinelOne's weaker schema confidence (see
// internal/vendors/sentinelone's package doc comment):
//
//  1. No MITRE ATT&CK technique-ID field is confirmed on SentinelOne's
//     Threat resource, so correlation is by device + time window +
//     an optional classification-name match (indicatorMatch), never by
//     technique.
//  2. A Forbidden (403) error cannot be split into "licensing" vs
//     "permission" the way Defender's DisabledFeature error code
//     allows -- both surface as a single, honestly-worded
//     CoverageSourceUnavailable detail that says the ambiguity exists,
//     rather than inventing a confident distinction.
//
// Like avdefender, this bridge never asserts a Prevention outcome from
// threat evidence: a recorded SentinelOne threat -- even one marked
// mitigated -- tells you detection/response history, not that the
// originating action was blocked before any part of it ran. Every
// Observation it produces carries Prevention: avval.PreventionUnknown.
package avsentinelone

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/avval"
	"github.com/audspect/bas/internal/vendors/sentinelone"
)

// BuildCollectionResult turns one device+window correlation target's
// real SentinelOne threat evidence into an avval.CollectionResult.
// Exactly one of (threats, queryErr) is meaningful: queryErr non-nil
// means the underlying sentinelone.Client.QueryThreats call itself
// failed, and threats is ignored. indicatorMatch, when non-empty, is
// matched case-insensitively against each threat's ClassificationName
// as a best-effort narrowing filter; when empty, any threat on the
// device within the window counts as a match. deviceHealthy must come
// from an independent, real check (e.g. sentinelone.Client.ListAgents
// confirming the device is active/reporting) -- never assumed true.
//
// ControlSource is always avval.ControlSourceEDR, matching
// avdefender's own choice for the same kind of correlated endpoint
// telemetry.
func BuildCollectionResult(computerName, indicatorMatch string, window avval.TimeWindow, deviceHealthy bool, threats []sentinelone.Threat, queryErr error) (avval.CollectionResult, error) {
	if queryErr != nil {
		return collectionResultForError(queryErr), nil
	}

	var matched *sentinelone.Threat
	var anyForDevice bool
	for i := range threats {
		th := &threats[i]
		if !strings.EqualFold(th.ComputerName, computerName) {
			continue
		}
		anyForDevice = true
		if indicatorMatch == "" || strings.EqualFold(th.ClassificationName, indicatorMatch) {
			matched = th
			break
		}
	}

	if matched != nil {
		return avval.CollectionResult{
			ControlSource: avval.ControlSourceEDR,
			Coverage:      avval.CoverageFound,
			Observations: []avval.Observation{{
				ControlSource: avval.ControlSourceEDR,
				Provider:      "SentinelOne",
				EventID:       matched.ID,
				ObservedAt:    matched.CreatedAt,
				Prevention:    avval.PreventionUnknown,
				Detection:     avval.DetectionDetected,
				EvidenceKind:  avval.EvidenceObserved,
				Detail:        fmt.Sprintf("threat %s (classification %q, mitigationStatus %q) matched on device %s", matched.ID, matched.ClassificationName, matched.MitigationStatus, computerName),
			}},
		}, nil
	}

	// No threat matched this device (and indicator, if given). Whether
	// that absence is a confirmed negative depends entirely on whether
	// the device is independently known to be healthy and reporting --
	// anyForDevice (other threats exist for this device) is one honest
	// signal of that, but deviceHealthy is the authoritative one since a
	// device can be healthy and genuinely have zero threats at all.
	if deviceHealthy || anyForDevice {
		return avval.CollectionResult{
			ControlSource: avval.ControlSourceEDR,
			Coverage:      avval.CoverageSearchedVerifiedNone,
			Observations: []avval.Observation{{
				ControlSource: avval.ControlSourceEDR,
				Provider:      "SentinelOne",
				Detection:     avval.DetectionNotObservedInWindow,
				EvidenceKind:  avval.EvidenceObserved,
				Detail:        fmt.Sprintf("searched device %s for matching threats in the given window; device confirmed reporting, no matching threat found", computerName),
			}},
		}, nil
	}

	return avval.CollectionResult{
		ControlSource: avval.ControlSourceEDR,
		Coverage:      avval.CoverageSearchIncomplete,
	}, nil
}

// collectionResultForError maps a real SentinelOne query failure into
// the correct avval.Coverage. Unlike avdefender's equivalent, a
// Forbidden/Unauthorized error here cannot be split into distinct
// licensing/permission/auth sub-reasons: see the package doc comment
// for why SentinelOne's classifier itself cannot tell them apart. Any
// error type other than *sentinelone.ClassifiedError, and any
// RateLimited/Transient/BadRequest/Unknown kind, is treated as
// search-incomplete, never as a confirmed negative.
func collectionResultForError(err error) avval.CollectionResult {
	ce, ok := err.(*sentinelone.ClassifiedError)
	if !ok {
		return avval.CollectionResult{ControlSource: avval.ControlSourceEDR, Coverage: avval.CoverageSearchIncomplete}
	}
	switch ce.Kind {
	case sentinelone.ErrKindForbidden:
		return sourceUnavailable("the API token lacks the required permission, OR the tenant's SentinelOne license doesn't cover this call -- SentinelOne's error response gives no confirmed machine-readable signal to tell these two apart (unlike Microsoft Defender's DisabledFeature error code); resolving this requires checking the tenant's entitlements and the token's role out-of-band")
	case sentinelone.ErrKindUnauthorized:
		return sourceUnavailable("the API token was missing, invalid, or revoked -- re-issuing the token from the console is the fix")
	case sentinelone.ErrKindRateLimited, sentinelone.ErrKindTransient, sentinelone.ErrKindBadRequest, sentinelone.ErrKindNotFound, sentinelone.ErrKindUnknown:
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
			Provider:      "SentinelOne",
			Detection:     avval.DetectionUnknown,
			EvidenceKind:  avval.EvidenceObserved,
			Detail:        detail,
		}},
	}
}
