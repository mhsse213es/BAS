package dbjobs

import (
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbrun"
)

func grantPolicy() dbsim.Policy {
	return dbsim.Policy{Source: "ticket-1", Roles: map[string]dbsim.RolePolicy{
		"app": {Allow: map[string][]string{"public.accounts": {"SELECT"}}},
	}}
}

func TestGrantDiffFor(t *testing.T) {
	readGrants := dbsim.DBProbeSpec{ProbeID: dbsim.ProbeReadGrants}
	clean := dbrun.AgentExec{DBProbe: &dbsim.DBProbeResult{Grants: []dbsim.DBProbeGrant{
		{Role: "app", Object: "public.accounts", Privilege: "SELECT"},
		{Role: "app", Object: "public.accounts", Privilege: "DELETE"},
	}}}
	s := &Service{GrantPolicy: func(dbsim.RunJob, dbsim.TargetRecord) (dbsim.Policy, bool) { return grantPolicy(), true }}

	d := s.grantDiffFor(dbsim.RunJob{}, dbsim.TargetRecord{}, clean, readGrants)
	if d == nil || d.GrantsChecked != 2 || len(d.Deviations) != 1 || d.Deviations[0].Privilege != "DELETE" {
		t.Fatalf("over-grant not reported as one deviation: %+v", d)
	}
	if got := s.grantDiffFor(dbsim.RunJob{}, dbsim.TargetRecord{}, clean, dbsim.DBProbeSpec{ProbeID: "read_roles"}); got != nil {
		t.Error("a non-grants probe must not be compared")
	}
	errored := dbrun.AgentExec{DBProbe: &dbsim.DBProbeResult{ErrorClass: "timeout"}}
	if got := s.grantDiffFor(dbsim.RunJob{}, dbsim.TargetRecord{}, errored, readGrants); got != nil {
		t.Error("an errored probe must not be compared")
	}
	noPolicy := &Service{}
	if got := noPolicy.grantDiffFor(dbsim.RunJob{}, dbsim.TargetRecord{}, clean, readGrants); got != nil {
		t.Error("no configured policy must not be compared")
	}
}

// The DB-02-05 and DB-02-06 probes are compared with policy through the same hook.
func TestGrantDiffForGlobalAndMembershipProbes(t *testing.T) {
	s := &Service{GrantPolicy: func(dbsim.RunJob, dbsim.TargetRecord) (dbsim.Policy, bool) {
		return dbsim.Policy{Source: "ticket-2", Roles: map[string]dbsim.RolePolicy{
			"app": {Global: []string{"CONNECT"}},
		}}, true
	}}
	ex := dbrun.AgentExec{DBProbe: &dbsim.DBProbeResult{
		GlobalGrants: []dbsim.DBProbeGlobalGrant{{Role: "app", Scope: "cluster", Privilege: "CREATEROLE"}},
		Memberships:  []dbsim.DBProbeMembership{{Role: "bas_dbsim_parent", Member: "app", Inherit: true}},
	}}
	g := s.grantDiffFor(dbsim.RunJob{}, dbsim.TargetRecord{}, ex, dbsim.DBProbeSpec{ProbeID: dbsim.ProbeReadGlobalPrivileges})
	if g == nil || g.GrantsChecked != 1 || len(g.Deviations) != 1 || g.Deviations[0].Kind != dbsim.DeviationGlobal {
		t.Fatalf("global probe diff: %+v", g)
	}
	m := s.grantDiffFor(dbsim.RunJob{}, dbsim.TargetRecord{}, ex, dbsim.DBProbeSpec{ProbeID: dbsim.ProbeReadMemberships})
	if m == nil || m.GrantsChecked != 1 || len(m.Deviations) != 1 || m.Deviations[0].Kind != dbsim.DeviationMembership {
		t.Fatalf("membership probe diff: %+v", m)
	}
}
