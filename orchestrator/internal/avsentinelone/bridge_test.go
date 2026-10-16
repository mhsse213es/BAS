package avsentinelone

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/audspect/bas/internal/avval"
	"github.com/audspect/bas/internal/vendors/sentinelone"
)

func testWindow() avval.TimeWindow {
	now := time.Now().UTC()
	return avval.TimeWindow{Start: now.Add(-time.Hour), End: now}
}

// TestBuildCollectionResult_Forbidden_SourceUnavailable_CannotDistinguishLicensing
// is the key test for this vendor's real limitation: unlike Defender's
// bridge, a Forbidden error here can never be split into "licensing" vs
// "permission" because SentinelOne's classifier itself cannot tell them
// apart (no confirmed error-code field) -- the Detail text must say so
// honestly, not invent a confident distinction.
func TestBuildCollectionResult_Forbidden_SourceUnavailable_CannotDistinguishLicensing(t *testing.T) {
	err := &sentinelone.ClassifiedError{StatusCode: http.StatusForbidden, Kind: sentinelone.ErrKindForbidden}
	cr, buildErr := BuildCollectionResult("HOST1", "", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSourceUnavailable {
		t.Errorf("Coverage = %v, want CoverageSourceUnavailable", cr.Coverage)
	}
	if len(cr.Observations) != 1 {
		t.Fatalf("Observations = %+v, want 1", cr.Observations)
	}
	if cr.Observations[0].Detection != avval.DetectionUnknown {
		t.Errorf("Detection = %v, want DetectionUnknown -- must never fabricate an outcome", cr.Observations[0].Detection)
	}
}

func TestBuildCollectionResult_Unauthorized_SourceUnavailable(t *testing.T) {
	err := &sentinelone.ClassifiedError{StatusCode: http.StatusUnauthorized, Kind: sentinelone.ErrKindUnauthorized}
	cr, buildErr := BuildCollectionResult("HOST1", "", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSourceUnavailable {
		t.Errorf("Coverage = %v, want CoverageSourceUnavailable", cr.Coverage)
	}
}

func TestBuildCollectionResult_RateLimited_SearchIncomplete(t *testing.T) {
	err := &sentinelone.ClassifiedError{StatusCode: http.StatusTooManyRequests, Kind: sentinelone.ErrKindRateLimited}
	cr, buildErr := BuildCollectionResult("HOST1", "", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete", cr.Coverage)
	}
}

func TestBuildCollectionResult_TransientServerError_SearchIncomplete(t *testing.T) {
	err := &sentinelone.ClassifiedError{StatusCode: http.StatusInternalServerError, Kind: sentinelone.ErrKindTransient}
	cr, buildErr := BuildCollectionResult("HOST1", "", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete", cr.Coverage)
	}
}

func TestBuildCollectionResult_GenericUnclassifiedError_SearchIncomplete(t *testing.T) {
	cr, buildErr := BuildCollectionResult("HOST1", "", testWindow(), false, nil, errors.New("boom"))
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete", cr.Coverage)
	}
}

// TestBuildCollectionResult_MatchingThreat_FoundDetected_NeverAssertsPrevention
// is the key test for the "no fabricated prevention" rule: a recorded
// threat, even one marked mitigated, proves detection/response history,
// not that the originating action was blocked before any part of it ran.
func TestBuildCollectionResult_MatchingThreat_FoundDetected_NeverAssertsPrevention(t *testing.T) {
	ts := time.Now().UTC().Add(-30 * time.Minute)
	threats := []sentinelone.Threat{
		{ID: "t1", ComputerName: "host1", ClassificationName: "malware", MitigationStatus: "mitigated", CreatedAt: ts},
	}
	cr, err := BuildCollectionResult("HOST1", "", testWindow(), true, threats, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageFound {
		t.Errorf("Coverage = %v, want CoverageFound", cr.Coverage)
	}
	if len(cr.Observations) != 1 {
		t.Fatalf("Observations = %+v, want 1", cr.Observations)
	}
	o := cr.Observations[0]
	if o.Detection != avval.DetectionDetected {
		t.Errorf("Detection = %v, want DetectionDetected", o.Detection)
	}
	if o.Prevention != avval.PreventionUnknown {
		t.Errorf("Prevention = %v, want PreventionUnknown -- threat evidence alone must never assert a prevention outcome, even when MitigationStatus is 'mitigated'", o.Prevention)
	}
	if !o.ObservedAt.Equal(ts) {
		t.Errorf("ObservedAt = %v, want %v", o.ObservedAt, ts)
	}
}

func TestBuildCollectionResult_IndicatorMatchFiltersByClassification(t *testing.T) {
	threats := []sentinelone.Threat{
		{ID: "t1", ComputerName: "host1", ClassificationName: "ransomware", CreatedAt: time.Now()},
	}
	cr, err := BuildCollectionResult("HOST1", "malware", testWindow(), true, threats, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageSearchedVerifiedNone {
		t.Errorf("Coverage = %v, want CoverageSearchedVerifiedNone (classification doesn't match the requested indicator)", cr.Coverage)
	}
}

func TestBuildCollectionResult_DeviceMatchCaseInsensitive(t *testing.T) {
	threats := []sentinelone.Threat{{ID: "t1", ComputerName: "Host1.Contoso.Com", CreatedAt: time.Now()}}
	cr, err := BuildCollectionResult("host1.contoso.com", "", testWindow(), true, threats, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageFound {
		t.Errorf("Coverage = %v, want CoverageFound (case-insensitive device match)", cr.Coverage)
	}
}

func TestBuildCollectionResult_NoMatchingThreat_DeviceHealthy_VerifiedNone(t *testing.T) {
	cr, err := BuildCollectionResult("HOST1", "", testWindow(), true, nil, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageSearchedVerifiedNone {
		t.Errorf("Coverage = %v, want CoverageSearchedVerifiedNone", cr.Coverage)
	}
}

func TestBuildCollectionResult_NoMatchingThreat_DeviceNotHealthy_SearchIncomplete(t *testing.T) {
	cr, err := BuildCollectionResult("HOST1", "", testWindow(), false, nil, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete -- an unresolved/unhealthy device's silence proves nothing", cr.Coverage)
	}
}
