package adenv

import (
	"reflect"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
)

func TestFromGraph_MapsEveryDerivableCategory(t *testing.T) {
	col := attackpath.Collection{
		AgentID: "agent1", Hostname: "host1", Source: "sharphound",
		Nodes: []attackpath.Node{
			{ID: "DC01", Kind: attackpath.KindHost, Label: "DC01.CORP.LOCAL", Role: attackpath.RoleDC},
			{ID: "SRV01", Kind: attackpath.KindHost, Label: "SRV01.CORP.LOCAL", Role: attackpath.RoleServer},
			{ID: "WS01", Kind: attackpath.KindHost, Label: "WS01.CORP.LOCAL", Role: attackpath.RoleEndpoint},
			{ID: "SVCACCT", Kind: attackpath.KindUser, Label: "svc_sql@CORP.LOCAL", HasSPN: true},
			{ID: "NORMALUSER", Kind: attackpath.KindUser, Label: "NORMALUSER@CORP.LOCAL", DontRequirePreauth: true},
			{ID: "LEGACY01", Kind: attackpath.KindHost, Label: "LEGACY01.CORP.LOCAL", Role: attackpath.RoleEndpoint, UnconstrainedDelegation: true},
			{ID: "DAGROUP", Kind: attackpath.KindGroup, Label: "Domain Admins", HighValue: true},
		},
		Edges: []attackpath.Edge{
			// Two members of the same group -- must both survive.
			{From: "SVCACCT", To: "DAGROUP", Kind: attackpath.EdgeMemberOf},
			{From: "NORMALUSER", To: "DAGROUP", Kind: attackpath.EdgeMemberOf},
			// ACL abuse: NORMALUSER holds GenericWrite over SVCACCT.
			{From: "NORMALUSER", To: "SVCACCT", Kind: attackpath.EdgeGenericWrite},
			// Constrained delegation: SRV01 can delegate to the SPN on WS01.
			{From: "SRV01", To: "WS01", Kind: attackpath.EdgeAllowedToDelegate},
			// RBCD: SVCACCT is allowed to act on behalf of others toward SRV01.
			{From: "SVCACCT", To: "SRV01", Kind: attackpath.EdgeAllowedToAct},
		},
	}
	g := attackpath.BuildGraph(col)

	env := FromGraph(g)

	// Machines, bucketed by role.
	if len(env.Machines.DomainControllers) != 1 || env.Machines.DomainControllers[0].Hostname != "DC01.CORP.LOCAL" {
		t.Fatalf("expected 1 DC (DC01.CORP.LOCAL), got %+v", env.Machines.DomainControllers)
	}
	if len(env.Machines.Servers) != 1 || env.Machines.Servers[0].Hostname != "SRV01.CORP.LOCAL" {
		t.Fatalf("expected 1 server (SRV01.CORP.LOCAL), got %+v", env.Machines.Servers)
	}
	// WS01 and LEGACY01 are both RoleEndpoint -> both Workstations.
	if len(env.Machines.Workstations) != 2 {
		t.Fatalf("expected 2 workstations, got %+v", env.Machines.Workstations)
	}

	// Users: Name/SID mapped, Enabled/SPNs deliberately left at zero-value.
	svc := mustFindUser(t, env.Identity.Users, "SVCACCT")
	if svc.Name != "svc_sql@CORP.LOCAL" || svc.SID != "SVCACCT" {
		t.Fatalf("expected SVCACCT Name/SID mapped, got %+v", svc)
	}
	if svc.Enabled {
		t.Fatalf("expected Enabled to stay false (unknown, not verified-disabled) when attackpath has no enabled/disabled data, got %+v", svc)
	}
	if svc.SPNs != nil {
		t.Fatalf("expected SPNs to stay nil (HasSPN is a bool, not real SPN strings) even though HasSPN was true, got %+v", svc.SPNs)
	}

	// Groups: both members present, not just the last one seen.
	da := mustFindGroup(t, env.Identity.Groups, "DAGROUP")
	wantMembers := map[string]bool{"SVCACCT": true, "NORMALUSER": true}
	if len(da.Members) != 2 || !wantMembers[da.Members[0]] || !wantMembers[da.Members[1]] {
		t.Fatalf("expected DAGROUP to have both SVCACCT and NORMALUSER as members, got %+v", da.Members)
	}

	// PrivilegedAccounts from HighValue.
	if len(env.Identity.PrivilegedAccounts) != 1 || env.Identity.PrivilegedAccounts[0] != "DAGROUP" {
		t.Fatalf("expected PrivilegedAccounts == [DAGROUP], got %+v", env.Identity.PrivilegedAccounts)
	}

	// Delegation: all 3 sub-categories.
	if len(env.Delegation.Unconstrained) != 1 || env.Delegation.Unconstrained[0] != "LEGACY01" {
		t.Fatalf("expected Unconstrained == [LEGACY01], got %+v", env.Delegation.Unconstrained)
	}
	if len(env.Delegation.Constrained) != 1 || env.Delegation.Constrained[0].Principal != "SRV01" || len(env.Delegation.Constrained[0].Targets) != 1 || env.Delegation.Constrained[0].Targets[0] != "WS01" {
		t.Fatalf("expected Constrained == [{Principal:SRV01 Targets:[WS01]}], got %+v", env.Delegation.Constrained)
	}
	if len(env.Delegation.RBCD) != 1 || env.Delegation.RBCD[0].Target != "SRV01" || len(env.Delegation.RBCD[0].AllowedPrincipals) != 1 || env.Delegation.RBCD[0].AllowedPrincipals[0] != "SVCACCT" {
		t.Fatalf("expected RBCD == [{Target:SRV01 AllowedPrincipals:[SVCACCT]}], got %+v", env.Delegation.RBCD)
	}

	// Authorization: the ACL edge, with Right values matching exactly
	// (adenv.ACLRight and attackpath.EdgeKind share string values after
	// the AD-M03 fix).
	if len(env.Authorization.ACLs) != 1 {
		t.Fatalf("expected 1 ACL entry, got %+v", env.Authorization.ACLs)
	}
	acl := env.Authorization.ACLs[0]
	if acl.Principal != "NORMALUSER" || acl.Target != "SVCACCT" || acl.Right != ACLGenericWrite {
		t.Fatalf("expected {NORMALUSER SVCACCT GenericWrite}, got %+v", acl)
	}

	// Categories with zero source data anywhere in attackpath stay at the
	// Go zero-value, not approximated.
	zero := Environment{}
	if !reflect.DeepEqual(env.Forest, zero.Forest) {
		t.Fatalf("expected Forest to stay zero-value (attackpath has no domain/trust data), got %+v", env.Forest)
	}
	if !reflect.DeepEqual(env.Authentication, zero.Authentication) {
		t.Fatalf("expected Authentication to stay zero-value (SMB/WinRM/RDP edges are reachability, not hardening config), got %+v", env.Authentication)
	}
	if !reflect.DeepEqual(env.Policy, zero.Policy) {
		t.Fatalf("expected Policy to stay zero-value (no GPO/LAPS-policy data in attackpath), got %+v", env.Policy)
	}
	if !reflect.DeepEqual(env.PKI, zero.PKI) {
		t.Fatalf("expected PKI to stay zero-value (no ADCS data in attackpath), got %+v", env.PKI)
	}
}

func mustFindUser(t *testing.T, users []User, sid string) User {
	t.Helper()
	for _, u := range users {
		if u.SID == sid {
			return u
		}
	}
	t.Fatalf("no user with SID %q in %+v", sid, users)
	return User{}
}

func mustFindGroup(t *testing.T, groups []Group, sid string) Group {
	t.Helper()
	for _, g := range groups {
		if g.SID == sid {
			return g
		}
	}
	t.Fatalf("no group with SID %q in %+v", sid, groups)
	return Group{}
}
