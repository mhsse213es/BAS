package phishidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ConditionalAccessPolicy is one normalized conditionalAccessPolicies
// record -- CONFIGURATION state only (does a policy exist, is it
// enabled), never proof that it fired for any specific sign-in. That
// distinction matters enough to this package's own design that the
// configuration half (this type, ConditionalAccessPolicies) and the
// enforcement half (AppliedConditionalAccessPolicy,
// SignInsByAuthenticationProtocol below) are deliberately separate
// Graph calls against separate endpoints, never merged into one
// claim.
type ConditionalAccessPolicy struct {
	ID          string
	DisplayName string
	State       string // "enabled" | "disabled" | "enabledForReportingButNotEnforced"
}

type conditionalAccessPolicyPage struct {
	Value []struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		State       string `json:"state"`
	} `json:"value"`
}

// ConditionalAccessPolicies calls
// GET {BaseURL}/identity/conditionalAccess/policies and normalizes
// every record returned. Configuration evidence only -- see this
// package's own PH-ID-003 bridge for why a caller must never treat an
// "enabled" policy here as proof it actually blocked anything.
// Performs no pagination, the same documented limitation
// ListOAuthConsentGrants carries for oauth2PermissionGrants.
func (c *Client) ConditionalAccessPolicies(ctx context.Context) ([]ConditionalAccessPolicy, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/identity/conditionalAccess/policies", nil)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	var page conditionalAccessPolicyPage
	decodeErr := json.NewDecoder(resp.Body).Decode(&page)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phishidentity: conditionalAccess/policies returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}

	policies := make([]ConditionalAccessPolicy, 0, len(page.Value))
	for _, v := range page.Value {
		policies = append(policies, ConditionalAccessPolicy{ID: v.ID, DisplayName: v.DisplayName, State: v.State})
	}
	return policies, nil
}

// AppliedConditionalAccessPolicy is one policy's own per-sign-in
// enforcement outcome -- Microsoft Graph's real
// appliedConditionalAccessPolicy resource. Result's documented values
// (v1.0): success, failure, notApplied, notEnabled, unknown,
// unknownFutureValue. notApplied means the policy's own conditions
// didn't match this specific sign-in -- never collapsed into
// "failure" or treated as evidence the control is broken.
type AppliedConditionalAccessPolicy struct {
	DisplayName string
	Result      string
}

// SignInEvent is one normalized signIn audit log record -- real
// per-attempt ENFORCEMENT evidence, Microsoft Graph's own signIn
// resource (GET /auditLogs/signIns). AuthenticationProtocol's
// documented values include "deviceCode" (v1.0) among others;
// AppliedConditionalAccessPolicies requires the caller's app
// registration hold additional Conditional-Access-read permission
// beyond a plain sign-in-log read, per Microsoft's own documentation
// -- an empty slice here can mean either "no CA policy touched this
// sign-in" or "this app isn't permissioned to see that detail," and
// this package never tells the two apart without that caveat stated.
type SignInEvent struct {
	ID                               string
	AuthenticationProtocol           string
	CreatedDateTime                  time.Time
	AppliedConditionalAccessPolicies []AppliedConditionalAccessPolicy
}

type signInEventPage struct {
	Value []struct {
		ID                               string    `json:"id"`
		AuthenticationProtocol           string    `json:"authenticationProtocol"`
		CreatedDateTime                  time.Time `json:"createdDateTime"`
		AppliedConditionalAccessPolicies []struct {
			DisplayName string `json:"displayName"`
			Result      string `json:"result"`
		} `json:"appliedConditionalAccessPolicies"`
	} `json:"value"`
}

// SignInsByAuthenticationProtocol calls
// GET {BaseURL}/auditLogs/signIns?$filter=authenticationProtocol eq '<protocol>'
// and normalizes every record returned. Server-side $filter support
// for authenticationProtocol specifically is not confirmed by
// Microsoft's own published filterable-properties list (only
// conditionalAccessStatus is explicitly documented as $filter-eq-
// capable) -- this method defensively re-filters the returned page
// client-side on AuthenticationProtocol as well, the same client-side-
// fallback discipline internal/vendors/sentinelone already uses for
// its own unconfirmed server-side filters, so a tenant that ignores
// the server-side filter parameter never silently returns the wrong
// protocol's events.
func (c *Client) SignInsByAuthenticationProtocol(ctx context.Context, protocol string) ([]SignInEvent, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: acquiring token: %w", err)
	}
	filter := fmt.Sprintf("authenticationProtocol eq '%s'", protocol)
	reqURL := c.BaseURL + "/auditLogs/signIns?$filter=" + url.QueryEscape(filter)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("phishidentity: request: %w", err)
	}
	defer resp.Body.Close()

	var page signInEventPage
	decodeErr := json.NewDecoder(resp.Body).Decode(&page)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("phishidentity: auditLogs/signIns returned status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("phishidentity: decoding response: %w", decodeErr)
	}

	events := make([]SignInEvent, 0, len(page.Value))
	for _, v := range page.Value {
		if v.AuthenticationProtocol != protocol {
			continue // defensive client-side re-filter, see doc comment above
		}
		var applied []AppliedConditionalAccessPolicy
		for _, p := range v.AppliedConditionalAccessPolicies {
			applied = append(applied, AppliedConditionalAccessPolicy{DisplayName: p.DisplayName, Result: p.Result})
		}
		events = append(events, SignInEvent{
			ID: v.ID, AuthenticationProtocol: v.AuthenticationProtocol,
			CreatedDateTime: v.CreatedDateTime, AppliedConditionalAccessPolicies: applied,
		})
	}
	return events, nil
}

// DeviceCodeEnforcement is the 3-way outcome PH-ID-003's bridge grades
// against -- deliberately never a plain bool, mirroring
// RevocationVerification's own discipline: a policy existing in
// ConditionalAccessPolicies is not proof it enforced anything, and an
// empty sign-in list is not proof nothing happened, it may just mean
// nothing was observed in this window.
type DeviceCodeEnforcement string

const (
	// DeviceCodeBlocked: at least one deviceCode sign-in was observed
	// and at least one of ITS OWN appliedConditionalAccessPolicies
	// entries reports Result == "failure" (the policy actually denied
	// the attempt), not merely that a matching policy exists in
	// configuration.
	DeviceCodeBlocked DeviceCodeEnforcement = "blocked"
	// DeviceCodeAllowed: at least one deviceCode sign-in was observed,
	// and none of its applied policies reported failure -- a genuine
	// observed negative (the attempt succeeded or hit no blocking
	// policy), not an absence-of-evidence case.
	DeviceCodeAllowed DeviceCodeEnforcement = "allowed"
	// DeviceCodeUnknown: no deviceCode sign-in evidence exists in this
	// window (or the signIns call itself failed) -- absence of
	// evidence, never read as either outcome.
	DeviceCodeUnknown DeviceCodeEnforcement = "unknown"
)

// EvaluateDeviceCodeEnforcement inspects signIns (the real, per-
// attempt evidence from SignInsByAuthenticationProtocol) and returns
// the enforcement outcome. It never consults
// ConditionalAccessPolicies' own configuration list -- a caller
// wanting to ALSO report "and yes, a policy named X exists for this"
// fetches and reports that separately, never substituting it for this
// function's own per-attempt verdict.
func EvaluateDeviceCodeEnforcement(signIns []SignInEvent) (DeviceCodeEnforcement, string) {
	if len(signIns) == 0 {
		return DeviceCodeUnknown, "no deviceCode sign-in attempts observed in this window"
	}
	for _, s := range signIns {
		for _, p := range s.AppliedConditionalAccessPolicies {
			if p.Result == "failure" {
				return DeviceCodeBlocked, fmt.Sprintf("sign-in %s: policy %q reported result=failure", s.ID, p.DisplayName)
			}
		}
	}
	return DeviceCodeAllowed, fmt.Sprintf("%d deviceCode sign-in(s) observed, none blocked by an applied Conditional Access policy", len(signIns))
}
