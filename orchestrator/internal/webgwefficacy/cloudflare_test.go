package webgwefficacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func cloudflareTestServer(t *testing.T, status int, body map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if body != nil {
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Fatalf("encode test response: %v", err)
			}
		}
	}))
}

func TestCloudflareGatewayPolicyProvider_SuccessfulRuleRead_ReturnsLiveEvidence(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{
		"success": true,
		"errors":  []any{},
		"result": map[string]any{
			"id":      "block-malware-category",
			"name":    "Block malware category",
			"action":  "block",
			"filters": []string{"http"},
			"traffic": `http.request.uri.category == "malware"`,
			"enabled": true,
		},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	records, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].PolicyRuleID != "block-malware-category" {
		t.Errorf("PolicyRuleID = %q, want %q", records[0].PolicyRuleID, "block-malware-category")
	}
	if !records[0].StillActive {
		t.Error("StillActive = false, want true -- the rule's enabled field was true")
	}
	if records[0].Source != SourceLive {
		t.Errorf("Source = %q, want %q -- this is the package's real live provider", records[0].Source, SourceLive)
	}
	if records[0].ObservedConfigHash == "" {
		t.Error("ObservedConfigHash is empty, want a real hash of the rule's configuration")
	}
}

func TestCloudflareGatewayPolicyProvider_RuleNotFound_ReturnsEmptyNotError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusNotFound, map[string]any{
		"success": false,
		"errors":  []any{map[string]any{"code": 1003, "message": "Not Found"}},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	records, err := provider.PolicyConfigEvidenceFor("deleted-rule", window)
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v, want nil -- a 404 is a legitimate negative result, not a collection failure", err)
	}
	if records != nil {
		t.Errorf("records = %v, want nil", records)
	}
}

func TestCloudflareGatewayPolicyProvider_SuccessFalseEnvelope_ReturnsDescriptiveError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{
		"success": false,
		"errors":  []any{map[string]any{"code": 9109, "message": "Invalid access token"}},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "bad-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	_, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err == nil {
		t.Fatal("PolicyConfigEvidenceFor: want an error for a success:false envelope, got nil")
	}
	if !strings.Contains(err.Error(), "Invalid access token") {
		t.Errorf("error = %q, want it to contain Cloudflare's own error message", err.Error())
	}
}

func TestCloudflareGatewayPolicyProvider_TransportError_ReturnsError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{"success": true, "result": map[string]any{}})
	server.Close() // closed before use -- every request now fails at the transport level

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}

	_, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err == nil {
		t.Fatal("PolicyConfigEvidenceFor: want an error when the server is unreachable, got nil -- a network outage must never look like \"nothing found\"")
	}
}

func TestCloudflareGatewayPolicyProvider_EvidenceOutsideWindow_ReturnsEmptyNotError(t *testing.T) {
	server := cloudflareTestServer(t, http.StatusOK, map[string]any{
		"success": true,
		"errors":  []any{},
		"result": map[string]any{
			"id":      "block-malware-category",
			"action":  "block",
			"filters": []string{"http"},
			"traffic": `http.request.uri.category == "malware"`,
			"enabled": true,
		},
	})
	defer server.Close()

	provider := NewCloudflareGatewayPolicyProvider(http.DefaultClient, server.URL, "test-account", "test-token")
	past := time.Now().Add(-24 * time.Hour)
	window := TimeWindow{Start: past.Add(-time.Minute), End: past.Add(time.Minute)} // a window that does not cover "now"

	records, err := provider.PolicyConfigEvidenceFor("block-malware-category", window)
	if err != nil {
		t.Fatalf("PolicyConfigEvidenceFor: %v", err)
	}
	if records != nil {
		t.Errorf("records = %v, want nil -- a live snapshot taken now is not valid evidence for a window that doesn't cover now", records)
	}
}

func TestNewCloudflareGatewayPolicyProviderFromEnv_MissingAccountID_Errors(t *testing.T) {
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "some-token")

	_, err := NewCloudflareGatewayPolicyProviderFromEnv()
	if err == nil {
		t.Fatal("NewCloudflareGatewayPolicyProviderFromEnv: want an error when CLOUDFLARE_ACCOUNT_ID is unset, got nil")
	}
}

func TestNewCloudflareGatewayPolicyProviderFromEnv_MissingAPIToken_Errors(t *testing.T) {
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "some-account")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")

	_, err := NewCloudflareGatewayPolicyProviderFromEnv()
	if err == nil {
		t.Fatal("NewCloudflareGatewayPolicyProviderFromEnv: want an error when CLOUDFLARE_API_TOKEN is unset, got nil")
	}
}

func TestCloudflareGatewayPolicyProvider_RealAPI_SkipsWithoutCredentials(t *testing.T) {
	provider, err := NewCloudflareGatewayPolicyProviderFromEnv()
	if err != nil {
		t.Skipf("skipping real Cloudflare API integration test: %v (set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN to run it for real)", err)
	}

	now := time.Now()
	window := TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	ruleID := os.Getenv("CLOUDFLARE_TEST_GATEWAY_RULE_ID")
	if ruleID == "" {
		t.Skip("CLOUDFLARE_ACCOUNT_ID/CLOUDFLARE_API_TOKEN are set but CLOUDFLARE_TEST_GATEWAY_RULE_ID is not -- skipping the real call")
	}

	if _, err := provider.PolicyConfigEvidenceFor(ruleID, window); err != nil {
		t.Fatalf("real Cloudflare Gateway rules API call failed: %v", err)
	}
}
