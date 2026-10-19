package phishscope

import (
	"errors"
	"testing"
)

const goodGUID = "8f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"

func TestParseScope_EmptyMeansUnconfigured(t *testing.T) {
	s, err := ParseScope("", "")
	if err != nil {
		t.Fatalf("ParseScope empty: %v", err)
	}
	if s.ConfiguredUsers() || s.ConfiguredClients() {
		t.Error("an empty allowlist must report unconfigured for both kinds")
	}
}

func TestParseScope_AcceptsWellFormedEntries(t *testing.T) {
	s, err := ParseScope("alice@contoso.example, "+goodGUID, goodGUID)
	if err != nil {
		t.Fatalf("ParseScope: %v", err)
	}
	if len(s.Users) != 2 || len(s.ClientIDs) != 1 {
		t.Errorf("Users=%v ClientIDs=%v, want 2 users and 1 client", s.Users, s.ClientIDs)
	}
}

func TestParseScope_RejectsMalformedEntries(t *testing.T) {
	cases := map[string]struct{ users, clients string }{
		"client not a GUID": {clients: "not-a-guid"},
		"user with no @":    {users: "alice"},
		"user with space":   {users: "a b@contoso.example"},
		"wildcard user":     {users: "*"},
		"wildcard client":   {clients: "*"},
	}
	for name, c := range cases {
		if _, err := ParseScope(c.users, c.clients); err == nil {
			t.Errorf("%s: ParseScope accepted a malformed entry", name)
		}
	}
}

func TestValidateTargets_EmptyAllowlistRefusesEverything(t *testing.T) {
	err := ValidateTargets(nil, []string{"alice@contoso.example"})
	if !errors.Is(err, ErrTargetNotAllowlisted) {
		t.Errorf("err = %v, want ErrTargetNotAllowlisted (an empty allowlist permits nothing)", err)
	}
}

func TestValidateTargets_MissingOrMalformedRequestRefused(t *testing.T) {
	allowed := []string{"alice@contoso.example"}
	for name, req := range map[string][]string{
		"no targets":       nil,
		"empty string":     {""},
		"blank string":     {"   "},
		"wildcard":         {"*"},
		"one blank of two": {"alice@contoso.example", ""},
	} {
		err := ValidateTargets(allowed, req)
		if !errors.Is(err, ErrNoValidTargets) && !errors.Is(err, ErrTargetNotAllowlisted) {
			t.Errorf("%s: err = %v, want the request refused", name, err)
		}
	}
}

func TestValidateTargets_OutOfScopeRefused(t *testing.T) {
	err := ValidateTargets([]string{"alice@contoso.example"}, []string{"bob@contoso.example"})
	if !errors.Is(err, ErrTargetNotAllowlisted) {
		t.Errorf("err = %v, want ErrTargetNotAllowlisted", err)
	}
}

func TestValidateTargets_InScopeAccepted_CaseInsensitive(t *testing.T) {
	err := ValidateTargets([]string{"Alice@Contoso.example"}, []string{"alice@contoso.EXAMPLE"})
	if err != nil {
		t.Errorf("err = %v, want nil for an in-scope target", err)
	}
}

// Every requested target must be allowed. One out-of-scope target rejects the
// whole request, never a silent partial run.
func TestValidateTargets_AnyOutOfScopeRejectsWholeRequest(t *testing.T) {
	err := ValidateTargets(
		[]string{"alice@contoso.example", "carol@contoso.example"},
		[]string{"alice@contoso.example", "bob@contoso.example"},
	)
	if !errors.Is(err, ErrTargetNotAllowlisted) {
		t.Errorf("err = %v, want ErrTargetNotAllowlisted for the whole request", err)
	}
}
