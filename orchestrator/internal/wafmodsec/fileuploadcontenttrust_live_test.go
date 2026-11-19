package wafmodsec

import (
	"context"
	"os"
	"testing"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_FileUploadContentTrustScenario_TwoOfThreeVectorsLive runs the
// real wafassessment.AudspectFileUploadContentTrustScenario -- unmodified
// -- with 2 of its 3 contributing vectors backed by live evidence over a
// genuine multipart/form-data upload. Confirmed empirically against the
// live container: FILEUP-003 (path-traversal filename) is genuinely
// Blocked -- CRS's generic traversal-pattern rule fires on the filename
// regardless of which header/field carries it. FILEUP-001 (PHP webshell
// content) is genuinely Allowed -- CRS's default rule set does not
// inspect uploaded file CONTENT for embedded PHP by default, an honest,
// confirmed limitation of this configuration, not a bug in the adapter --
// which resolves to VerdictInconclusive, not Missed, since wafmodsec never
// asserts DetectionMatched/NotMatched.
//
// Skipped unless WAF_MODSEC_LAB_URL is set -- see lab/wafmodsec/README.md.
func TestLive_FileUploadContentTrustScenario_TwoOfThreeVectorsLive(t *testing.T) {
	baseURL := os.Getenv("WAF_MODSEC_LAB_URL")
	if baseURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL not set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set WAF_MODSEC_LAB_URL=http://localhost:8888 to run it")
	}

	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	_, result, err := RunFileUploadContentTrustLive(context.Background(), client)
	if err != nil {
		t.Fatalf("RunFileUploadContentTrustLive: %v", err)
	}

	if result.Outcome != wafassessment.ScenarioIncomplete {
		t.Errorf("Outcome = %q, want %q", result.Outcome, wafassessment.ScenarioIncomplete)
	}
	wantVerdict := map[string]wafval.Verdict{
		"FILEUP-001": wafval.VerdictInconclusive,
		"FILEUP-003": wafval.VerdictBlocked,
	}
	if len(result.Assertions) != len(wantVerdict) {
		t.Fatalf("Assertions = %+v, want exactly %d", result.Assertions, len(wantVerdict))
	}
	for _, a := range result.Assertions {
		want, ok := wantVerdict[a.VectorID]
		if !ok {
			t.Errorf("unexpected vector %q in Assertions", a.VectorID)
			continue
		}
		if a.Verdict != want {
			t.Errorf("vector %q Verdict = %q, want %q", a.VectorID, a.Verdict, want)
		}
		if a.EvidenceSource != wafassessment.EvidenceSourceLiveExecution {
			t.Errorf("vector %q EvidenceSource = %q, want %q", a.VectorID, a.EvidenceSource, wafassessment.EvidenceSourceLiveExecution)
		}
	}

	if len(result.UntestedVectorIDs) != 1 || result.UntestedVectorIDs[0] != "FILEUP-002" {
		t.Errorf("UntestedVectorIDs = %v, want exactly [FILEUP-002]", result.UntestedVectorIDs)
	}
}
