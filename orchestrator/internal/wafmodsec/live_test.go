package wafmodsec

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// TestLive_RealWAFCatalogVectors_AgainstLiveModSecurityLab drives real HTTP
// traffic from 4 real wafcatalog vectors -- one per family, chosen because
// each uses only the PayloadLocation forms BuildRequest implements today
// ("" and "query:<param>") -- at the live ModSecurity + OWASP CRS lab
// defined in lab/wafmodsec/docker-compose.yml, and asserts the REAL verdict
// wafval.EvaluateClaim derives from the REAL response. This is the live
// counterpart to bridge_test.go's synthetic-body tests: it proves the whole
// chain (modsecwaf.Client -> wafmodsec.BuildCollectionResults ->
// wafval.EvaluateClaim) against a genuine running WAF engine, not a fixture.
//
// Skipped unless WAF_MODSEC_LAB_URL is set (e.g. http://localhost:8888),
// because it needs `docker compose up -d` run first in lab/wafmodsec/ --
// never run as part of the normal `go test ./...` suite. See
// lab/wafmodsec/README.md.
func TestLive_RealWAFCatalogVectors_AgainstLiveModSecurityLab(t *testing.T) {
	baseURL := os.Getenv("WAF_MODSEC_LAB_URL")
	if baseURL == "" {
		t.Skip("WAF_MODSEC_LAB_URL not set -- skipping live test; run `docker compose up -d` in lab/wafmodsec/ and set WAF_MODSEC_LAB_URL=http://localhost:8888 to run it")
	}

	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	byID := make(map[string]wafcatalog.AttackVector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	// One vector per family, each using only the "" / "query:<param>"
	// PayloadLocation forms this version's BuildRequest implements.
	ids := []string{"SQLI-001", "XSS-001", "PATHTRAV-001", "HTTPPARSE-002"}
	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	ctx := context.Background()

	for _, id := range ids {
		v, ok := byID[id]
		if !ok {
			t.Fatalf("vector %q not found in the real catalog", id)
		}
		t.Run(id+"/malicious", func(t *testing.T) {
			assertRealVerdict(t, client, ctx, v.Malicious, wafval.ClaimPrevention, wafval.VerdictBlocked, id+"-malicious")
		})
		if v.BenignCounterpart == nil {
			t.Fatalf("vector %q has no BenignCounterpart -- cannot drive its benign leg", id)
		}
		t.Run(id+"/benign", func(t *testing.T) {
			assertRealVerdict(t, client, ctx, *v.BenignCounterpart, wafval.ClaimFalsePositive, wafval.VerdictAllowed, id+"-benign")
		})
	}
}

func assertRealVerdict(t *testing.T, client *modsecwaf.Client, ctx context.Context, tmpl wafcatalog.RequestTemplate, claim wafval.ClaimType, want wafval.Verdict, requestID string) {
	t.Helper()
	resp, err := client.Send(ctx, tmpl)
	if err != nil {
		t.Fatalf("Send(%s %s): %v", tmpl.Method, tmpl.Path, err)
	}
	key := wafval.CorrelationKey{TestExecutionID: requestID, RequestID: requestID}
	results := BuildCollectionResults(resp, key, time.Now())
	result := wafval.EvaluateClaim(wafval.Expectation{Claim: claim}, results, key)
	if result.Verdict != want {
		t.Errorf("real HTTP status %d -> Verdict = %q, want %q (reason: %s, body: %s)",
			resp.StatusCode, result.Verdict, want, result.Reason, truncate(string(resp.Body), 200))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
