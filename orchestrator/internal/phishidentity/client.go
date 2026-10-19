// Package phishidentity is Phishing BAS Mastery's own Microsoft Graph
// adapter -- identity-security checks (PH-ID-002 OAuth consent abuse
// today; PH-ID-003/004/005 once their own endpoints are wired) and
// collaboration-lure delivery (PH-CHN-002 sharing invitations,
// PH-CHN-004 calendar invites), sharing one Client/token source because
// both are real Graph v1.0 calls against the same tenant, not because
// they are conceptually one capability. It is a standalone client --
// deliberately NOT internal/cloudgraph's AzureDiscoveryClient,
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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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

	// VerificationPollAttempts/VerificationPollInterval govern
	// RevokeAndVerifySignInSessions' post-revocation re-read loop --
	// exported so tests can shrink the interval to avoid real sleeps.
	// Zero means "use the default" (3 attempts, 2s apart).
	VerificationPollAttempts int
	VerificationPollInterval time.Duration

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
	return c.listOAuthConsentGrants(ctx, c.BaseURL+"/oauth2PermissionGrants")
}

// ListOAuthConsentGrantsForClients lists only the grants whose clientId is one of
// clientIDs. The narrowing happens in the Graph query itself, via $filter. An
// empty or malformed client list is refused, so this never becomes a
// tenant-wide listing by accident. Scope is still bounded by Graph permissions.
// Those are reviewed separately, and PH-ID-002 stays unavailable until they are.
func (c *Client) ListOAuthConsentGrantsForClients(ctx context.Context, clientIDs []string) ([]OAuthConsentGrant, error) {
	if len(clientIDs) == 0 {
		return nil, errors.New("phishidentity: no client IDs given; refusing an unscoped grant listing")
	}
	clauses := make([]string, 0, len(clientIDs))
	for _, id := range clientIDs {
		if !clientGUIDRe.MatchString(id) {
			return nil, fmt.Errorf("phishidentity: %q is not an application (client) ID", id)
		}
		clauses = append(clauses, "clientId eq '"+id+"'")
	}
	filter := strings.Join(clauses, " or ")
	return c.listOAuthConsentGrants(ctx, c.BaseURL+"/oauth2PermissionGrants?$filter="+url.QueryEscape(filter))
}

var clientGUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// listOAuthConsentGrants reads every page of the listing. A partial first page is
// never returned as the whole answer, and a listing that runs past maxGraphPages
// is an error.
func (c *Client) listOAuthConsentGrants(ctx context.Context, reqURL string) ([]OAuthConsentGrant, error) {
	grants := []OAuthConsentGrant{}
	err := c.getGraphPages(ctx, reqURL, func(body []byte) error {
		var page oauthConsentGrantPage
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("phishidentity: decoding response: %w", err)
		}
		for _, v := range page.Value {
			grants = append(grants, OAuthConsentGrant{
				ID: v.ID, ClientID: v.ClientID, ConsentType: v.ConsentType, Scope: v.Scope, PrincipalID: v.PrincipalID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return grants, nil
}

// RevokeSignInSessions calls the real, stable Graph v1.0 action
// POST {BaseURL}/users/{userID}/revokeSignInSessions -- PH-ID-002's own
// containment counterpart (PH-IR-002, identity containment): invalidates
// every refresh token currently issued to the user, forcing
// re-authentication everywhere. A 2xx response proves only that Graph
// ACCEPTED the request, never that containment is independently
// confirmed -- same discipline internal/rwevidence.ContainmentObserver
// already establishes for endpoint isolation: dispatch acceptance and
// verified postcondition are never conflated. Callers that need the
// verified claim use a separate observer (see phishbridge's own identity
// containment bridge), not this method's return value alone.
func (c *Client) RevokeSignInSessions(ctx context.Context, userID string) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/users/"+userID+"/revokeSignInSessions", nil)
	if err != nil {
		return fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("phishidentity: revokeSignInSessions returned status %d", resp.StatusCode)
	}
	return nil
}

// SignInSessionsValidFromDateTime calls the real, stable Graph v1.0
// GET {BaseURL}/users/{userID}?$select=signInSessionsValidFromDateTime
// -- the independent postcondition check RevokeAndVerifySignInSessions
// uses to confirm a revocation actually took effect, rather than
// trusting RevokeSignInSessions' own 2xx response.
func (c *Client) SignInSessionsValidFromDateTime(ctx context.Context, userID string) (time.Time, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/users/"+userID+"?$select=signInSessionsValidFromDateTime", nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		SignInSessionsValidFromDateTime string `json:"signInSessionsValidFromDateTime"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("phishidentity: reading signInSessionsValidFromDateTime returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return time.Time{}, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}
	if body.SignInSessionsValidFromDateTime == "" {
		return time.Time{}, fmt.Errorf("phishidentity: signInSessionsValidFromDateTime missing from response")
	}
	t, err := time.Parse(time.RFC3339, body.SignInSessionsValidFromDateTime)
	if err != nil {
		return time.Time{}, fmt.Errorf("phishidentity: parsing signInSessionsValidFromDateTime %q: %w", body.SignInSessionsValidFromDateTime, err)
	}
	return t, nil
}

// RevocationVerification is the outcome of independently confirming a
// RevokeSignInSessions dispatch -- never collapsed into a boolean,
// because "the re-read failed" and "the re-read succeeded but nothing
// changed" are different findings with different remediation.
type RevocationVerification string

const (
	// RevocationVerified means signInSessionsValidFromDateTime
	// independently advanced past the pre-revocation baseline. This is
	// strong evidence the revocation marker changed server-side -- it
	// does NOT prove every already-issued access token became
	// unusable immediately (short-lived access tokens already in a
	// client's possession can remain valid until their own natural
	// expiry; only refresh-token-based reauthentication is guaranteed
	// blocked). That distinction must be preserved wherever this
	// verdict is surfaced, never flattened into "fully contained."
	RevocationVerified RevocationVerification = "verified"
	// RevocationNotVerified means the re-read(s) succeeded but the
	// marker never advanced within the poll budget -- a real negative
	// finding, not an error.
	RevocationNotVerified RevocationVerification = "not_verified"
	// RevocationUnknown means the dispatch itself failed, the baseline
	// could not be read, or every post-revocation re-read errored
	// (permissions, throttling, a transient fault) -- inconclusive,
	// and never read as success.
	RevocationUnknown RevocationVerification = "unknown"
)

// RevocationResult is RevokeAndVerifySignInSessions' own evidence
// record: the pre/post timestamps it actually observed, plus the
// verification verdict derived from comparing them -- never just the
// dispatch's own 2xx/non-2xx status.
type RevocationResult struct {
	DispatchErr  error
	Baseline     time.Time
	After        time.Time
	Verification RevocationVerification
	Detail       string
}

// RevokeAndVerifySignInSessions closes PH-IR-002's own documented gap
// (phishbridge.FromIdentityContainment previously had no real
// verification observer, mirroring rwevidence.ContainmentObserver's own
// same limitation): it captures a pre-revocation baseline, dispatches
// RevokeSignInSessions, then independently re-reads
// signInSessionsValidFromDateTime and compares -- a successful POST
// alone is never read as containment. Propagation delay is handled by
// polling up to VerificationPollAttempts times (default 3, 2s apart)
// until the marker advances; a read that keeps failing throughout
// (permissions, throttling, a transient fault) grades Unknown, never a
// false positive OR a false negative.
func (c *Client) RevokeAndVerifySignInSessions(ctx context.Context, userID string) RevocationResult {
	baseline, err := c.SignInSessionsValidFromDateTime(ctx, userID)
	if err != nil {
		return RevocationResult{Verification: RevocationUnknown, Detail: "could not read pre-revocation baseline: " + err.Error()}
	}

	if err := c.RevokeSignInSessions(ctx, userID); err != nil {
		return RevocationResult{DispatchErr: err, Baseline: baseline, Verification: RevocationUnknown, Detail: "dispatch rejected: " + err.Error()}
	}

	attempts := c.VerificationPollAttempts
	if attempts <= 0 {
		attempts = 3
	}
	interval := c.VerificationPollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}

	var after time.Time
	var readErr error
	for i := 0; i < attempts; i++ {
		after, readErr = c.SignInSessionsValidFromDateTime(ctx, userID)
		if readErr == nil && after.After(baseline) {
			return RevocationResult{
				Baseline: baseline, After: after, Verification: RevocationVerified,
				Detail: fmt.Sprintf("signInSessionsValidFromDateTime advanced from %s to %s", baseline.Format(time.RFC3339), after.Format(time.RFC3339)),
			}
		}
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				return RevocationResult{Baseline: baseline, Verification: RevocationUnknown, Detail: "context canceled while polling for verification"}
			case <-time.After(interval):
			}
		}
	}
	if readErr != nil {
		return RevocationResult{Baseline: baseline, Verification: RevocationUnknown, Detail: "could not read post-revocation marker: " + readErr.Error()}
	}
	return RevocationResult{
		Baseline: baseline, After: after, Verification: RevocationNotVerified,
		Detail: fmt.Sprintf("signInSessionsValidFromDateTime did not advance after %d read(s) -- revocation not independently confirmed", attempts),
	}
}
