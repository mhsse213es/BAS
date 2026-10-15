package webgwefficacy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudsink"
	"github.com/audspect/bas/internal/testutil"
)

// TestDLPUploadScenario_SyntheticMarkerBlockedByFixtureGateway proves
// Phase 2a's DLP-upload exit criterion end-to-end: a synthetic,
// non-sensitive marker payload is actually PUT over real HTTP to
// cloudsink's S3-mimicking endpoint (the real "destination-side"
// half -- did the attempt reach the destination at all), and the
// result is run through VerifyHTTPExpectation against fixture
// gateway evidence (the "gateway policy" half, since no live gateway
// exists in this phase). This is an integration test -- it imports
// cloudsink and testutil, which internal/webgwefficacy's own
// production code never does.
func TestDLPUploadScenario_SyntheticMarkerBlockedByFixtureGateway(t *testing.T) {
	testDB := testutil.NewTestDB(t)
	ctx := context.Background()

	token := "webgw-phase2a-dlp-test-token"
	_, err := testDB.Pool.Exec(ctx,
		`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
		token, "webgw-phase2a-run", "T1567", time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("insert dlp_sink_tokens: %v", err)
	}

	server := httptest.NewServer(cloudsink.Routes(testDB.Pool))
	defer server.Close()

	syntheticMarker := strings.NewReader("BAS-SYNTHETIC-DLP-MARKER-0000111122223333-NOT-REAL-DATA")
	req, err := http.NewRequest(http.MethodPut, server.URL+"/s3/bas-test-bucket/"+token+".dat", syntheticMarker)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status = %d, want 200", resp.StatusCode)
	}

	var receiptCount int
	if err := testDB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM dlp_sink_receipts WHERE token = $1`, token,
	).Scan(&receiptCount); err != nil {
		t.Fatalf("query dlp_sink_receipts: %v", err)
	}
	if receiptCount == 0 {
		t.Fatalf("got 0 receipts for token %q, want at least 1 -- the upload attempt must actually reach cloudsink for this scenario to be meaningful", token)
	}
	observation := HTTPObservation{
		RequestURL:   server.URL + "/s3/bas-test-bucket/" + token + ".dat",
		ClientResult: "upload-received-by-destination",
		Timestamp:    time.Now(),
	}

	now := time.Now()
	exp := HTTPExpectation{
		RequestURL:     "https://cloud-storage.example/upload",
		ExpectedAction: ExpectedBlock,
		ControlProduct: "cloudflare-gateway",
		Note:           "synthetic DLP marker upload -- destination-side receipt confirms the attempt would have succeeded had no gateway DLP policy existed",
	}
	gatewayProvider := NewFixtureGatewayProvider([]GatewayEvidence{
		{RequestURL: exp.RequestURL, Action: "block", PolicyRule: "dlp-financial-data", Timestamp: now, Source: SourceFixture},
	})
	result := VerifyHTTPExpectation(exp, observation, gatewayProvider, TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)})

	if result.Prevention.Verdict != VerdictPass {
		t.Errorf("Prevention.Verdict = %q, want %q -- fixture gateway evidence shows the DLP policy blocked this request shape", result.Prevention.Verdict, VerdictPass)
	}
}
