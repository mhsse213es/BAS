package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishscope"
)

const goodClientGUID = "8f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"

// scopedConsentFake satisfies OAuthConsentGrantLister for capability tests.
type scopedConsentFake struct{}

func (scopedConsentFake) ListOAuthConsentGrants(context.Context) ([]phishidentity.OAuthConsentGrant, error) {
	return nil, nil
}
func (scopedConsentFake) ListOAuthConsentGrantsForClients(context.Context, []string) ([]phishidentity.OAuthConsentGrant, error) {
	return nil, nil
}

// PH-ID-002 must not be available while the installation has no client allowlist.
func TestPhishingCapability_EmptyClientAllowlistIsUnavailable(t *testing.T) {
	env := poolOnly()
	env.OAuthConsentLister = scopedConsentFake{}
	c := phishingCapabilityFor(env, "PH-ID-002", false)
	if c.Status != CapUnavailable || c.Reason != reasonOAuthClientAllowlistNotConfigured {
		t.Errorf("status=%q reason=%q, want unavailable/%s", c.Status, c.Reason, reasonOAuthClientAllowlistNotConfigured)
	}
}

// PH-ID-003 must not be available while the installation has no user allowlist.
func TestPhishingCapability_EmptyUserAllowlistIsUnavailable(t *testing.T) {
	env := poolOnly()
	env.DeviceCodeSignIns = fakeDeviceCodeSignIns{}
	c := phishingCapabilityFor(env, "PH-ID-003", false)
	if c.Status != CapUnavailable || c.Reason != reasonUserAllowlistNotConfigured {
		t.Errorf("status=%q reason=%q, want unavailable/%s", c.Status, c.Reason, reasonUserAllowlistNotConfigured)
	}
}

// A malformed allowlist fails closed with its own reason, never as "unconfigured".
func TestPhishingCapability_InvalidAllowlistFailsClosed(t *testing.T) {
	env := poolOnly()
	env.OAuthConsentLister = scopedConsentFake{}
	env.IdentityScopeErr = "phishscope: client entry \"*\" is not an application (client) ID"
	c := phishingCapabilityFor(env, "PH-ID-002", false)
	if c.Status != CapUnavailable || c.Reason != reasonIdentityAllowlistInvalid {
		t.Errorf("status=%q reason=%q, want unavailable/%s", c.Status, c.Reason, reasonIdentityAllowlistInvalid)
	}
}

// A complete allowlist with a wired client still leaves PH-ID-002 unavailable: its
// Graph permission and filtered query are not yet reviewed. Configuration alone
// never enables a scenario.
func TestPhishingCapability_AllowlistAloneDoesNotEnableOAuthScenario(t *testing.T) {
	env := poolOnly()
	env.OAuthConsentLister = scopedConsentFake{}
	env.IdentityScope = phishscope.Scope{ClientIDs: []string{goodClientGUID}}
	c := phishingCapabilityFor(env, "PH-ID-002", false)
	if c.Status != CapUnavailable || c.Reason != reasonGraphPermissionReviewPending {
		t.Errorf("status=%q reason=%q, want unavailable/%s", c.Status, c.Reason, reasonGraphPermissionReviewPending)
	}
}

// countingConsentFake records every listing call, scoped or not.
type countingConsentFake struct {
	unscoped, scoped int
	scopedIDs        []string
}

func (f *countingConsentFake) ListOAuthConsentGrants(context.Context) ([]phishidentity.OAuthConsentGrant, error) {
	f.unscoped++
	return nil, nil
}
func (f *countingConsentFake) ListOAuthConsentGrantsForClients(_ context.Context, ids []string) ([]phishidentity.OAuthConsentGrant, error) {
	f.scoped++
	f.scopedIDs = ids
	return nil, nil
}

// countingSignInFake records every sign-in call, scoped or not.
type countingSignInFake struct {
	unscoped, scoped int
	scopedUsers      []string
}

func (f *countingSignInFake) SignInsByAuthenticationProtocol(context.Context, string) ([]phishidentity.SignInEvent, error) {
	f.unscoped++
	return nil, nil
}
func (f *countingSignInFake) SignInsForUsersByProtocol(_ context.Context, _ string, users []string) ([]phishidentity.SignInEvent, error) {
	f.scoped++
	f.scopedUsers = users
	return nil, nil
}

const otherClientGUID = "66666666-7777-4888-8999-aaaaaaaaaaaa"

// PH-ID-002: an out-of-scope, missing, or empty target is refused before any call.
func TestExecutePHID002_RefusesBeforeAnyGraphCall(t *testing.T) {
	cases := map[string]struct {
		allowed []string
		params  map[string]any
	}{
		"empty allowlist": {nil, map[string]any{"clientIds": []any{goodClientGUID}}},
		"missing targets": {[]string{goodClientGUID}, map[string]any{}},
		"out of scope":    {[]string{goodClientGUID}, map[string]any{"clientIds": []any{otherClientGUID}}},
		"one of two out":  {[]string{goodClientGUID}, map[string]any{"clientIds": []any{goodClientGUID, otherClientGUID}}},
		"wildcard target": {[]string{goodClientGUID}, map[string]any{"clientIds": []any{"*"}}},
	}
	for name, c := range cases {
		fake := &countingConsentFake{}
		env := PhishingRunExecutorEnv{OAuthConsentLister: fake, IdentityScope: phishscope.Scope{ClientIDs: c.allowed}}
		_, err := executePHID002(context.Background(), env, "run-1", c.params)
		if err == nil {
			t.Errorf("%s: executor accepted the request", name)
		}
		if fake.unscoped+fake.scoped != 0 {
			t.Errorf("%s: %d Graph call(s) made; want 0", name, fake.unscoped+fake.scoped)
		}
	}
}

// PH-ID-002: an in-scope target reaches only the scoped query, with exactly that target.
func TestExecutePHID002_InScopeUsesOnlyTheScopedQuery(t *testing.T) {
	fake := &countingConsentFake{}
	env := PhishingRunExecutorEnv{OAuthConsentLister: fake, IdentityScope: phishscope.Scope{ClientIDs: []string{goodClientGUID}}}
	if _, err := executePHID002(context.Background(), env, "run-1", map[string]any{"clientIds": []any{goodClientGUID}}); err != nil {
		t.Fatalf("executePHID002: %v", err)
	}
	if fake.unscoped != 0 {
		t.Errorf("unscoped listing called %d time(s); the tenant-wide query must not run", fake.unscoped)
	}
	if fake.scoped != 1 || len(fake.scopedIDs) != 1 || fake.scopedIDs[0] != goodClientGUID {
		t.Errorf("scoped call = %d with %v, want one call with [%s]", fake.scoped, fake.scopedIDs, goodClientGUID)
	}
}

// PH-ID-003: the same refusal rules, applied to user targets.
func TestExecutePHID003_RefusesBeforeAnyGraphCall(t *testing.T) {
	cases := map[string]struct {
		allowed []string
		params  map[string]any
	}{
		"empty allowlist": {nil, map[string]any{"userIds": []any{"alice@contoso.example"}}},
		"missing targets": {[]string{"alice@contoso.example"}, map[string]any{}},
		"out of scope":    {[]string{"alice@contoso.example"}, map[string]any{"userIds": []any{"bob@contoso.example"}}},
		"one of two out":  {[]string{"alice@contoso.example"}, map[string]any{"userIds": []any{"alice@contoso.example", "bob@contoso.example"}}},
	}
	for name, c := range cases {
		fake := &countingSignInFake{}
		env := PhishingRunExecutorEnv{DeviceCodeSignIns: fake, IdentityScope: phishscope.Scope{Users: c.allowed}}
		if _, err := executePHID003(context.Background(), env, "run-1", c.params); err == nil {
			t.Errorf("%s: executor accepted the request", name)
		}
		if fake.unscoped+fake.scoped != 0 {
			t.Errorf("%s: %d Graph call(s) made; want 0", name, fake.unscoped+fake.scoped)
		}
	}
}

func TestExecutePHID003_InScopeUsesOnlyTheScopedQuery(t *testing.T) {
	fake := &countingSignInFake{}
	env := PhishingRunExecutorEnv{DeviceCodeSignIns: fake, IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}}
	if _, err := executePHID003(context.Background(), env, "run-1", map[string]any{"userIds": []any{"alice@contoso.example"}}); err != nil {
		t.Fatalf("executePHID003: %v", err)
	}
	if fake.unscoped != 0 {
		t.Errorf("tenant-wide sign-in query called %d time(s); it must not run", fake.unscoped)
	}
	if fake.scoped != 1 || len(fake.scopedUsers) != 1 || fake.scopedUsers[0] != "alice@contoso.example" {
		t.Errorf("scoped call = %d with %v, want one call for alice", fake.scoped, fake.scopedUsers)
	}
}

// The allowlist is read from the environment on each call. A change takes effect
// only when the container is recreated; this test checks the read, not a restart.
func TestPhishingRunEnv_ReadsEnvironmentOnEachCall(t *testing.T) {
	h := &Handler{}

	t.Setenv(EnvPhishOAuthClientIDs, goodClientGUID)
	if env := h.phishingRunEnv(); env.IdentityScopeErr != "" || !env.IdentityScope.ConfiguredClients() {
		t.Fatalf("valid allowlist not read: err=%q configured=%v", env.IdentityScopeErr, env.IdentityScope.ConfiguredClients())
	}

	t.Setenv(EnvPhishOAuthClientIDs, "*")
	if env := h.phishingRunEnv(); env.IdentityScopeErr == "" {
		t.Error("a malformed allowlist must be reported on the next read, not silently treated as valid")
	}

	t.Setenv(EnvPhishOAuthClientIDs, "")
	if env := h.phishingRunEnv(); env.IdentityScope.ConfiguredClients() {
		t.Error("a cleared allowlist must no longer be configured on the next read")
	}
}

// countingIdentityFake records every identity read, for PH-ID-004 and PH-ID-005.
type countingIdentityFake struct{ calls int }

func (f *countingIdentityFake) MFADenialEventsForUser(context.Context, string) ([]phishidentity.MFADenialEvent, error) {
	f.calls++
	return nil, nil
}
func (f *countingIdentityFake) RiskySignInsForUser(context.Context, string) ([]phishidentity.RiskySignInEvent, error) {
	f.calls++
	return nil, nil
}
func (f *countingIdentityFake) SignInSessionsValidFromDateTime(context.Context, string) (time.Time, error) {
	f.calls++
	return time.Time{}, nil
}

// PH-ID-004 and PH-ID-005: a user outside the allowlist is refused with zero reads.
func TestIdentityHeuristics_OutOfScopeUserRefusedBeforeAnyRead(t *testing.T) {
	params := map[string]any{"userId": "bob@contoso.example", "threshold": 5.0, "windowSeconds": 600.0}
	for name, run := range map[string]func(PhishingRunExecutorEnv) error{
		"PH-ID-004": func(env PhishingRunExecutorEnv) error {
			_, err := executePHID004(context.Background(), env, "run-1", params)
			return err
		},
		"PH-ID-005": func(env PhishingRunExecutorEnv) error {
			_, err := executePHID005(context.Background(), env, "run-1", params)
			return err
		},
	} {
		fake := &countingIdentityFake{}
		env := PhishingRunExecutorEnv{IdentityReader: fake, IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}}
		if err := run(env); err == nil {
			t.Errorf("%s: out-of-scope user accepted", name)
		}
		if fake.calls != 0 {
			t.Errorf("%s: %d identity read(s) made for an out-of-scope user; want 0", name, fake.calls)
		}
	}
}

// PH-ID-005 reads only for an in-scope user.
func TestIdentityHeuristics_InScopeUserReadsOnlyThatUser(t *testing.T) {
	fake := &countingIdentityFake{}
	env := PhishingRunExecutorEnv{IdentityReader: fake, IdentityScope: phishscope.Scope{Users: []string{"alice@contoso.example"}}}
	params := map[string]any{"userId": "alice@contoso.example", "windowSeconds": 600.0}
	if _, err := executePHID005(context.Background(), env, "run-1", params); err != nil {
		t.Fatalf("executePHID005: %v", err)
	}
	if fake.calls == 0 {
		t.Error("in-scope user made no identity reads")
	}
}
