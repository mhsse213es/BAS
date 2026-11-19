package dbsim

import (
	"sort"
	"strings"
)

// DB-02-05 (global privileges) and DB-02-06 (role memberships) policy diffs. Like Diff,
// these are read-only reports: no field carries a remediation or a runnable statement.
const (
	// DeviationGlobal: a cluster- or database-scope privilege that no own or inherited
	// Global rule permits.
	DeviationGlobal DeviationKind = "global_grant_excessive"
	// DeviationMembership: a role membership the account's policy does not declare in
	// Inherits (own only; the chain is not followed for memberships).
	DeviationMembership DeviationKind = "membership_excessive"
)

// GlobalGrant is one cluster- or database-scope privilege (read_global_privileges).
// Scope is "cluster" or "database:<name>".
type GlobalGrant struct {
	Role      string `json:"role"`
	Scope     string `json:"scope"`
	Privilege string `json:"privilege"`
}

// Membership is one role membership (read_memberships): Member holds Role.
type Membership struct {
	Role    string `json:"role"`
	Member  string `json:"member"`
	Inherit bool   `json:"inherit"`
}

// GlobalFromProbe converts a read_global_privileges result. Nothing is filtered.
func GlobalFromProbe(res DBProbeResult) []GlobalGrant {
	out := make([]GlobalGrant, 0, len(res.GlobalGrants))
	for _, g := range res.GlobalGrants {
		out = append(out, GlobalGrant{Role: g.Role, Scope: g.Scope, Privilege: g.Privilege})
	}
	return out
}

// MembershipsFromProbe converts a read_memberships result. Nothing is filtered.
func MembershipsFromProbe(res DBProbeResult) []Membership {
	out := make([]Membership, 0, len(res.Memberships))
	for _, m := range res.Memberships {
		out = append(out, Membership{Role: m.Role, Member: m.Member, Inherit: m.Inherit})
	}
	return out
}

// globalAllowed reports whether any role in the chain permits the privilege.
func globalAllowed(p Policy, chain []string, privilege string) bool {
	for _, r := range chain {
		for _, priv := range p.Roles[r].Global {
			if strings.EqualFold(strings.TrimSpace(priv), strings.TrimSpace(privilege)) {
				return true
			}
		}
	}
	return false
}

// DiffGlobal compares observed cluster and database privileges with the policy's Global rules.
func DiffGlobal(p Policy, actual []GlobalGrant) []Deviation {
	out := []Deviation{}
	for _, g := range actual {
		if _, known := p.Roles[g.Role]; !known {
			out = append(out, Deviation{Kind: DeviationUnknownRole, Role: g.Role, Object: g.Scope, Privilege: g.Privilege, PolicySource: p.Source})
			continue
		}
		if !globalAllowed(p, roleChain(p, g.Role), g.Privilege) {
			out = append(out, Deviation{Kind: DeviationGlobal, Role: g.Role, Object: g.Scope, Privilege: g.Privilege, PolicySource: p.Source})
		}
	}
	sortDeviations(out)
	return out
}

// DiffMemberships compares observed role memberships with the policy's Inherits lists.
func DiffMemberships(p Policy, actual []Membership) []Deviation {
	out := []Deviation{}
	for _, m := range actual {
		rp, known := p.Roles[m.Member]
		if !known {
			out = append(out, Deviation{Kind: DeviationUnknownRole, Role: m.Member, Object: m.Role, Privilege: "MEMBERSHIP", PolicySource: p.Source})
			continue
		}
		declared := false
		for _, in := range rp.Inherits {
			if in == m.Role {
				declared = true
				break
			}
		}
		if !declared {
			out = append(out, Deviation{Kind: DeviationMembership, Role: m.Member, Object: m.Role, Privilege: "MEMBERSHIP", PolicySource: p.Source})
		}
	}
	sortDeviations(out)
	return out
}

// ReportGlobal wraps DiffGlobal with the policy source and the number of privileges examined.
func ReportGlobal(p Policy, actual []GlobalGrant) DiffReport {
	return DiffReport{PolicySource: p.Source, GrantsChecked: len(actual), Deviations: DiffGlobal(p, actual)}
}

// ReportMemberships wraps DiffMemberships with the policy source and the number of memberships examined.
func ReportMemberships(p Policy, actual []Membership) DiffReport {
	return DiffReport{PolicySource: p.Source, GrantsChecked: len(actual), Deviations: DiffMemberships(p, actual)}
}

// IsPolicyDiffProbe reports whether a probe's result is compared with a stated policy.
func IsPolicyDiffProbe(probeID string) bool {
	return probeID == ProbeReadGrants || probeID == ProbeReadGlobalPrivileges || probeID == ProbeReadMemberships
}

func sortDeviations(out []Deviation) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		if a.Object != b.Object {
			return a.Object < b.Object
		}
		if a.Privilege != b.Privilege {
			return a.Privilege < b.Privilege
		}
		return a.Kind < b.Kind
	})
}
