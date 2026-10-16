package avdefender

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/audspect/bas/internal/avval"
	"github.com/audspect/bas/internal/vendors/defender"
)

func testWindow() avval.TimeWindow {
	now := time.Now().UTC()
	return avval.TimeWindow{Start: now.Add(-time.Hour), End: now}
}

// TestBuildCollectionResult_FeatureDisabled_SourceUnavailable_NeverFabricatesCoverage
// is the key test for item #5's directive: a missing license must
// never be reported the same way as "we searched and found nothing".
func TestBuildCollectionResult_FeatureDisabled_SourceUnavailable(t *testing.T) {
	err := &defender.ClassifiedError{StatusCode: http.StatusForbidden, Kind: defender.ErrKindFeatureDisabled, Code: "DisabledFeature", Message: "Tenant feature isn't enabled."}
	cr, buildErr := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSourceUnavailable {
		t.Errorf("Coverage = %v, want CoverageSourceUnavailable", cr.Coverage)
	}
	if len(cr.Observations) != 1 {
		t.Fatalf("Observations = %+v, want exactly 1 explanatory observation", cr.Observations)
	}
	if cr.Observations[0].Detection != avval.DetectionUnknown {
		t.Errorf("Detection = %v, want DetectionUnknown -- a source-unavailable result must never fabricate a Detected/NotObserved outcome", cr.Observations[0].Detection)
	}
	if cr.Observations[0].Prevention != "" && cr.Observations[0].Prevention != avval.PreventionUnknown {
		t.Errorf("Prevention = %v, want empty or PreventionUnknown", cr.Observations[0].Prevention)
	}
}

func TestBuildCollectionResult_InsufficientPermission_SourceUnavailable_DistinctDetailFromLicensing(t *testing.T) {
	licenseErr := &defender.ClassifiedError{StatusCode: http.StatusForbidden, Kind: defender.ErrKindFeatureDisabled, Code: "DisabledFeature"}
	permErr := &defender.ClassifiedError{StatusCode: http.StatusForbidden, Kind: defender.ErrKindInsufficientPermission, Code: "Forbidden"}

	licenseCR, err := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, licenseErr)
	if err != nil {
		t.Fatalf("BuildCollectionResult (license): %v", err)
	}
	permCR, err := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, permErr)
	if err != nil {
		t.Fatalf("BuildCollectionResult (permission): %v", err)
	}
	if permCR.Coverage != avval.CoverageSourceUnavailable {
		t.Errorf("Coverage = %v, want CoverageSourceUnavailable", permCR.Coverage)
	}
	if len(licenseCR.Observations) == 0 || len(permCR.Observations) == 0 {
		t.Fatal("expected both to carry an explanatory Observation with Detail")
	}
	if licenseCR.Observations[0].Detail == permCR.Observations[0].Detail {
		t.Error("license and permission failures must carry distinct Detail text, never the same reason")
	}
}

func TestBuildCollectionResult_Unauthorized_SourceUnavailable(t *testing.T) {
	err := &defender.ClassifiedError{StatusCode: http.StatusUnauthorized, Kind: defender.ErrKindUnauthorized}
	cr, buildErr := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSourceUnavailable {
		t.Errorf("Coverage = %v, want CoverageSourceUnavailable", cr.Coverage)
	}
}

func TestBuildCollectionResult_RateLimited_SearchIncomplete_NotSourceUnavailable(t *testing.T) {
	err := &defender.ClassifiedError{StatusCode: http.StatusTooManyRequests, Kind: defender.ErrKindRateLimited}
	cr, buildErr := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete (retryable, distinct from a permanent source-unavailable reason)", cr.Coverage)
	}
}

func TestBuildCollectionResult_TransientServerError_SearchIncomplete(t *testing.T) {
	err := &defender.ClassifiedError{StatusCode: http.StatusInternalServerError, Kind: defender.ErrKindTransient}
	cr, buildErr := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, err)
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete", cr.Coverage)
	}
}

func TestBuildCollectionResult_GenericUnclassifiedError_SearchIncomplete(t *testing.T) {
	cr, buildErr := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, errors.New("boom"))
	if buildErr != nil {
		t.Fatalf("BuildCollectionResult: %v", buildErr)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete", cr.Coverage)
	}
}

// TestBuildCollectionResult_MatchingAlert_FoundDetected_NeverAssertsPrevention
// is the key test for item #6: a real matching alert proves detection,
// never prevention -- alert data alone never tells you whether the
// action was blocked pre-execution.
func TestBuildCollectionResult_MatchingAlert_FoundDetected_NeverAssertsPrevention(t *testing.T) {
	ts := time.Now().UTC().Add(-30 * time.Minute)
	alerts := []defender.Alert{
		{ID: "a1", DeviceDNSName: "host1", Techniques: []string{"T1055"}, Timestamp: ts},
	}
	cr, err := BuildCollectionResult("HOST1", "T1055", testWindow(), true, alerts, nil)
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
		t.Errorf("Prevention = %v, want PreventionUnknown -- alert evidence alone must never assert a prevention outcome", o.Prevention)
	}
	if o.EvidenceKind != avval.EvidenceObserved {
		t.Errorf("EvidenceKind = %v, want EvidenceObserved", o.EvidenceKind)
	}
	if !o.ObservedAt.Equal(ts) {
		t.Errorf("ObservedAt = %v, want %v", o.ObservedAt, ts)
	}
}

func TestBuildCollectionResult_DeviceMatchCaseInsensitive(t *testing.T) {
	alerts := []defender.Alert{{ID: "a1", DeviceDNSName: "Host1.Contoso.Com", Techniques: []string{"T1055"}, Timestamp: time.Now()}}
	cr, err := BuildCollectionResult("host1.contoso.com", "T1055", testWindow(), true, alerts, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageFound {
		t.Errorf("Coverage = %v, want CoverageFound (case-insensitive device match)", cr.Coverage)
	}
}

// TestBuildCollectionResult_NoMatchingAlert_DeviceHealthy_VerifiedNone proves
// a genuine negative: the device is confirmed healthy/reporting and
// simply has no alert for this technique.
func TestBuildCollectionResult_NoMatchingAlert_DeviceHealthy_VerifiedNone(t *testing.T) {
	alerts := []defender.Alert{{ID: "a1", DeviceDNSName: "host1", Techniques: []string{"T1003"}, Timestamp: time.Now()}}
	cr, err := BuildCollectionResult("HOST1", "T1055", testWindow(), true, alerts, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageSearchedVerifiedNone {
		t.Errorf("Coverage = %v, want CoverageSearchedVerifiedNone", cr.Coverage)
	}
	if len(cr.Observations) != 1 || cr.Observations[0].Detection != avval.DetectionNotObservedInWindow {
		t.Fatalf("Observations = %+v, want one DetectionNotObservedInWindow observation", cr.Observations)
	}
}

// TestBuildCollectionResult_NoMatchingAlert_DeviceNotHealthy_SearchIncomplete
// is the key test for the "missing telemetry" distinction in item #5:
// an absence of alerts for a device we never confirmed as healthy must
// never be reported as a verified negative.
func TestBuildCollectionResult_NoMatchingAlert_DeviceNotHealthy_SearchIncomplete(t *testing.T) {
	cr, err := BuildCollectionResult("HOST1", "T1055", testWindow(), false, nil, nil)
	if err != nil {
		t.Fatalf("BuildCollectionResult: %v", err)
	}
	if cr.Coverage != avval.CoverageSearchIncomplete {
		t.Errorf("Coverage = %v, want CoverageSearchIncomplete -- an unhealthy/unresolved device's silence proves nothing", cr.Coverage)
	}
}
