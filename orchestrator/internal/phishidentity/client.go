// Package phishidentity is Phishing BAS Mastery's own Microsoft Graph
// identity adapter, for PH-ID-002 (OAuth consent abuse) today and
// PH-ID-003/004/005 (device-code phishing, MFA fatigue, session-theft
// defense) once their own Graph endpoints are wired. It is a standalone
// client -- deliberately NOT internal/cloudgraph's AzureDiscoveryClient,
// which belongs to the separately-held Cloud BAS initiative and whose
// resource/role-assignment discovery has no overlap with these
// identity-security checks. Reuses internal/platform/msauth.EntraTokenSource,
// the same shared Entra client-credentials token fetcher
// Sentinel/Defender/cloudgraph already use.
//
// Lab-gated boundary: httptest-proven only (see client_test.go) -- real
// OAuth token exchange, HTTP request, and JSON parsing against a
// mock server, the same discipline emailgwefficacy's own
// DefenderMailEvidenceProvider maturity proof uses. Per the Azure Real
// Discovery Integration project's own precedent, a real tenant call will
// likely hit the same tenant-permission blocker (no subscription, no
// admin-consented app role) -- code-ready-pending-tenant-access, never
// claimed live-validated without it.
package phishidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)

// Config holds the connection settings for one Entra tenant.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// Client is a Microsoft Graph identity-security API client. BaseURL is
// exported so tests can point it at an httptest.Server, matching
// internal/vendors/defender.Client's own precedent exactly.
type Client struct {
	BaseURL string // defaults to https://graph.microsoft.com/v1.0

	tokens     *msauth.EntraTokenSource
	httpClient *http.Client
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL: "https://graph.microsoft.com/v1.0",
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// TokenURL exposes the token source's overridable URL for tests.
func (c *Client) TokenURL() *string { return &c.tokens.TokenURL }

// OAuthConsentGrant is one normalized oauth2PermissionGrants record --
// Microsoft Graph's own representation of a delegated or app-only
// permission grant to a service principal (an OAuth "application").
type OAuthConsentGrant struct {
	ID          string
	ClientID    string // the service principal (app) object ID the grant is FOR
	ConsentType string // "AllPrincipals" (tenant-wide admin consent) | "Principal" (single-user consent)
	Scope       string // space-delimited list of granted OAuth scopes
	PrincipalID string // empty when ConsentType is AllPrincipals
}

// riskyScopes are OAuth scopes that, if ever granted to an attacker-
// controlled application, give it standing access to mailbox content,
// files, or directory write -- phishing.txt's own PH-ID-002 objective:
// "Validate consent restrictions and risky application detection."
// Deliberately conservative and reviewable as a flat list, not a
// pattern-matched heuristic, so a false "not risky" never hides behind
// an overbroad regex.
var riskyScopes = map[string]bool{
	"Mail.Read":                 true,
	"Mail.ReadWrite":            true,
	"Mail.Send":                 true,
	"MailboxSettings.ReadWrite": true,
	"Files.ReadWrite.All":       true,
	"Files.Read.All":            true,
	"Directory.ReadWrite.All":   true,
	"Directory.Read.All":        true,
	"User.ReadWrite.All":        true,
	"Sites.ReadWrite.All":       true,
}

// RiskyScopes returns the subset of g.Scope's space-delimited scopes that
// are in the conservative risky-scope list above.
func (g OAuthConsentGrant) RiskyScopes() []string {
	var risky []string
	for _, s := range strings.Fields(g.Scope) {
		if riskyScopes[s] {
			risky = append(risky, s)
		}
	}
	return risky
}

// IsTenantWideAndRisky reports whether g grants tenant-wide admin consent
// (ConsentType == "AllPrincipals", binding every user in the tenant, not
// just the consenting one) AND includes at least one risky scope -- the
// specific combination PH-ID-002 exists to catch: an over-permissioned
// application no single user's own consent decision can undo.
func (g OAuthConsentGrant) IsTenantWideAndRisky() bool {
	return g.ConsentType == "AllPrincipals" && len(g.RiskyScopes()) > 0
}

type oauthConsentGrantPage struct {
	Value []struct {
		ID          string `json:"id"`
		ClientID    string `json:"clientId"`
		ConsentType string `json:"consentType"`
		Scope       string `json:"scope"`
		PrincipalID string `json:"principalId"`
	} `json:"value"`
}

// ListOAuthConsentGrants calls GET {BaseURL}/oauth2PermissionGrants and
// normalizes every record returned. It performs no pagination: Graph
// returns oauth2PermissionGrants as a single page for any tenant small
// enough for a BAS test run; a tenant with enough grants to paginate is a
// known limitation, not yet handled.
func (c *Client) ListOAuthConsentGrants(ctx context.Context) ([]OAuthConsentGrant, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/oauth2PermissionGrants", nil)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	var page oauthConsentGrantPage
	decodeErr := json.NewDecoder(resp.Body).Decode(&page)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phishidentity: oauth2PermissionGrants returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}

	grants := make([]OAuthConsentGrant, 0, len(page.Value))
	for _, v := range page.Value {
		grants = append(grants, OAuthConsentGrant{
			ID: v.ID, ClientID: v.ClientID, ConsentType: v.ConsentType, Scope: v.Scope, PrincipalID: v.PrincipalID,
		})
	}
	return grants, nil
}
