package dbsim

import "testing"

func grantOptionPolicy() Policy {
	return Policy{Source: "ticket-9", Roles: map[string]RolePolicy{
		"app": {
			Allow: map[string][]string{"public.accounts": {"SELECT", "UPDATE"}},
		},
		"delegator": {
			Inherits:    []string{"app"},
			GrantOption: map[string][]string{"public.accounts": {"SELECT"}},
		},
	}}
}

func kinds(ds []Deviation) []DeviationKind {
	var out []DeviationKind
	for _, d := range ds {
		out = append(out, d.Kind)
	}
	return out
}

// A grant option the policy does not permit is reported as grant_option_excessive.
func TestDiffFlagsGrantOptionNotPermitted(t *testing.T) {
	ds := Diff(grantOptionPolicy(), []Grant{{Role: "app", Object: "public.accounts", Privilege: "UPDATE", GrantOption: true}})
	if len(ds) != 1 || ds[0].Kind != DeviationGrantOption {
		t.Fatalf("want one grant_option_excessive, got %v", kinds(ds))
	}
}

// A grant option the policy permits for that object and privilege is not a deviation.
func TestDiffAllowsPermittedGrantOption(t *testing.T) {
	ds := Diff(grantOptionPolicy(), []Grant{{Role: "delegator", Object: "public.accounts", Privilege: "SELECT", GrantOption: true}})
	if len(ds) != 0 {
		t.Fatalf("permitted grant option reported: %v", kinds(ds))
	}
}

// Without the grant option flag, an allowed grant is never a grant-option deviation.
func TestDiffPlainGrantIsNotGrantOptionDeviation(t *testing.T) {
	ds := Diff(grantOptionPolicy(), []Grant{{Role: "app", Object: "public.accounts", Privilege: "UPDATE"}})
	if len(ds) != 0 {
		t.Fatalf("plain allowed grant reported: %v", kinds(ds))
	}
}

// An excessive grant is reported as excessive, not also as a grant-option deviation.
func TestDiffExcessiveGrantStaysExcessive(t *testing.T) {
	ds := Diff(grantOptionPolicy(), []Grant{{Role: "app", Object: "public.other", Privilege: "DELETE", GrantOption: true}})
	if len(ds) != 1 || ds[0].Kind != DeviationExcessive {
		t.Fatalf("want one excessive_grant, got %v", kinds(ds))
	}
}
