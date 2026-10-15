package webgwefficacy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// CloudflareGatewayPolicyProvider implements PolicyConfigEvidenceProvider
// (drift.go) against Cloudflare's real, documented Zero Trust Gateway
// rules API -- https://developers.cloudflare.com/api/operations/zero-trust-gateway-rules-create-zero-trust-gateway-rule.
// It is deliberately not a GatewayEvidenceProvider: per the architecture
// spec's Phase 2b amendment, per-request attack-resistance evidence is
// confirmed unavailable on the free tier (Logpush for Zero Trust Gateway
// logs is Enterprise-only; Log Explorer has no free tier or trial at any
// plan level). This provider proves live POLICY-CONFIGURATION
// correctness only -- whether a rule's real, currently-configured action
// matches what was declared -- which the free-tier gateway/rules API
// does support.
type CloudflareGatewayPolicyProvider struct {
	httpClient *http.Client
	baseURL    string
	accountID  string
	apiToken   string
}

// NewCloudflareGatewayPolicyProvider takes an explicit HTTP client and
// base URL so tests can inject an httptest server in place of
// Cloudflare's real API host.
func NewCloudflareGatewayPolicyProvider(httpClient *http.Client, baseURL, accountID, apiToken string) *CloudflareGatewayPolicyProvider {
	return &CloudflareGatewayPolicyProvider{
		httpClient: httpClient,
		baseURL:    baseURL,
		accountID:  accountID,
		apiToken:   apiToken,
	}
}

// NewCloudflareGatewayPolicyProviderFromEnv reads real Cloudflare
// credentials from the environment. It errors cleanly when either is
// unset rather than silently constructing a provider that would send a
// malformed request to Cloudflare's live API.
func NewCloudflareGatewayPolicyProviderFromEnv() (*CloudflareGatewayPolicyProvider, error) {
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if accountID == "" {
		return nil, fmt.Errorf("CLOUDFLARE_ACCOUNT_ID is not set")
	}
	if apiToken == "" {
		return nil, fmt.Errorf("CLOUDFLARE_API_TOKEN is not set")
	}
	return NewCloudflareGatewayPolicyProvider(http.DefaultClient, "https://api.cloudflare.com/client/v4", accountID, apiToken), nil
}

// cloudflareAPIError mirrors one entry of Cloudflare's documented
// envelope error array.
type cloudflareAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cloudflareGatewayRule mirrors the fields of Cloudflare's documented
// GatewayRule result schema this provider actually uses.
type cloudflareGatewayRule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Action  string   `json:"action"`
	Filters []string `json:"filters"`
	Traffic string   `json:"traffic"`
	Enabled bool     `json:"enabled"`
}

// cloudflareGatewayRuleEnvelope mirrors Cloudflare's own documented API
// v4 response envelope (success/errors/result) for a single Gateway
// rule.
type cloudflareGatewayRuleEnvelope struct {
	Success bool                  `json:"success"`
	Errors  []cloudflareAPIError  `json:"errors"`
	Result  cloudflareGatewayRule `json:"result"`
}

// configHashFor computes a deterministic hash over the fields of a
// Cloudflare Gateway rule that constitute its enforced behavior --
// action, filters, and the traffic-matching expression. Name,
// description, and ID are deliberately excluded: they don't change what
// the rule does.
func configHashFor(rule cloudflareGatewayRule) string {
	canonical := fmt.Sprintf("action=%s|filters=%s|traffic=%s", rule.Action, strings.Join(rule.Filters, ","), rule.Traffic)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// PolicyConfigEvidenceFor calls Cloudflare's real gateway/rules API for
// the given rule ID. An HTTP transport error or a 2xx response whose
// envelope reports success:false both return a genuine error --
// collection failed. An HTTP 404, or evidence whose timestamp falls
// outside window, both return (nil, nil) -- a legitimate "nothing here",
// never an error, matching FixturePolicyConfigProvider's own semantics.
func (p *CloudflareGatewayPolicyProvider) PolicyConfigEvidenceFor(policyRuleID string, window TimeWindow) ([]PolicyConfigEvidence, error) {
	url := fmt.Sprintf("%s/accounts/%s/gateway/rules/%s", p.baseURL, p.accountID, policyRuleID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build Cloudflare Gateway rule request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call Cloudflare Gateway rules API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	var envelope cloudflareGatewayRuleEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode Cloudflare Gateway rule response: %w", err)
	}
	if !envelope.Success {
		reason := "unknown error"
		if len(envelope.Errors) > 0 {
			reason = envelope.Errors[0].Message
		}
		return nil, fmt.Errorf("Cloudflare Gateway rules API returned an error: %s", reason)
	}

	now := time.Now()
	if !inWindow(now, window) {
		return nil, nil
	}

	return []PolicyConfigEvidence{
		{
			PolicyRuleID:       policyRuleID,
			ObservedConfigHash: configHashFor(envelope.Result),
			StillActive:        envelope.Result.Enabled,
			Timestamp:          now,
			Source:             SourceLive,
		},
	}, nil
}
