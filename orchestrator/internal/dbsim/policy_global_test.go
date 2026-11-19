package dbsim

import "testing"

func globalPolicy() Policy {
	return Policy{Source: "ticket-5", Roles: map[string]RolePolicy{
		"app":    {Global: []string{"CONNECT"}},
		"ops":    {Inherits: []string{"app"}, Global: []string{"CREATEROLE"}},
		"reader": {},
	}}
}

// A cluster privilege no rule in the chain permits is global_grant_excessive.
func TestDiffGlobalFlagsUnpermittedPrivilege(t *testing.T) {
	ds := DiffGlobal(globalPolicy(), []GlobalGrant{{Role: "reader", Scope: "cluster", Privilege: "CREATEROLE"}})
	if len(ds) != 1 || ds[0].Kind != DeviationGlobal || ds[0].Object != "cluster" {
		t.Fatalf("want one global_grant_excessive, got %+v", ds)
	}
}

// A privilege permitted through an inherited role is not a deviation.
func TestDiffGlobalAllowsInheritedPrivilege(t *testing.T) {
	ds := DiffGlobal(globalPolicy(), []GlobalGrant{{Role: "ops", Scope: "database:dbsim", Privilege: "connect"}})
	if len(ds) != 0 {
		t.Fatalf("inherited privilege reported: %+v", ds)
	}
}

func TestDiffGlobalUnknownRoleIsReported(t *testing.T) {
	ds := DiffGlobal(globalPolicy(), []GlobalGrant{{Role: "stranger", Scope: "cluster", Privilege: "SUPERUSER"}})
	if len(ds) != 1 || ds[0].Kind != DeviationUnknownRole {
		t.Fatalf("want unknown_role, got %+v", ds)
	}
}

// A membership the account's policy does not declare is membership_excessive.
func TestDiffMembershipsFlagsUndeclaredParent(t *testing.T) {
	ds := DiffMemberships(globalPolicy(), []Membership{{Role: "ops", Member: "reader", Inherit: true}})
	if len(ds) != 1 || ds[0].Kind != DeviationMembership || ds[0].Object != "ops" {
		t.Fatalf("want one membership_excessive, got %+v", ds)
	}
}

// A membership the policy declares is not a deviation.
func TestDiffMembershipsAllowsDeclaredParent(t *testing.T) {
	ds := DiffMemberships(globalPolicy(), []Membership{{Role: "app", Member: "ops", Inherit: true}})
	if len(ds) != 0 {
		t.Fatalf("declared membership reported: %+v", ds)
	}
}

func TestReportGlobalCountsEveryPrivilegeExamined(t *testing.T) {
	r := ReportGlobal(globalPolicy(), []GlobalGrant{{Role: "app", Scope: "cluster", Privilege: "CONNECT"}, {Role: "reader", Scope: "cluster", Privilege: "SUPERUSER"}})
	if r.GrantsChecked != 2 || len(r.Deviations) != 1 || r.PolicySource != "ticket-5" {
		t.Fatalf("report: %+v", r)
	}
}

func TestIsPolicyDiffProbeCoversTheThreeGrantProbes(t *testing.T) {
	for _, id := range []string{ProbeReadGrants, ProbeReadGlobalPrivileges, ProbeReadMemberships} {
		if !IsPolicyDiffProbe(id) {
			t.Errorf("%s must be compared with policy", id)
		}
	}
	if IsPolicyDiffProbe("read_roles") {
		t.Error("read_roles must not be compared with policy")
	}
}
