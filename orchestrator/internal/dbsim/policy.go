package dbsim

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Grant is one privilege grant observed on a target. It mirrors the agent's
// grant record (agent/dbprobe.Grant) by JSON shape; the orchestrator never
// imports agent code.
type Grant struct {
	Role        string `json:"role"`
	Object      string `json:"object"`
	Privilege   string `json:"privilege"`
	GrantOption bool   `json:"grantOption,omitempty"`
}

// RolePolicy states what one role may and may not hold. Allow and Deny map an
// object to privileges. An object is an exact name, "*" (everything) or
// "schema.*" (everything in a schema); a privilege is a name or "ALL"/"*".
// Inherits names policy roles whose Allow and Deny also apply (transitively).
type RolePolicy struct {
	Inherits []string            `json:"inherits,omitempty"`
	Allow    map[string][]string `json:"allow,omitempty"`
	Deny     map[string][]string `json:"deny,omitempty"`
	// GrantOption lists the object -> privileges this role may hold WITH GRANT OPTION.
	// A grant option not covered here (own or inherited) is a grant_option_excessive deviation.
	GrantOption map[string][]string `json:"grantOption,omitempty"`
	// Global lists the cluster- and database-scope privileges this role may hold
	// (for example CREATEROLE, CREATE). Checked by DiffGlobal (DB-02-05).
	Global []string `json:"global,omitempty"`
}

// Policy is the intended grant model for a target. Source names where the
// policy came from (file, change ticket, lab fixture) and is carried into
// every Deviation and Report so a finding is traceable to its yardstick.
type Policy struct {
	Source string                `json:"source"`
	Roles  map[string]RolePolicy `json:"roles"`
}

type DeviationKind string

const (
	// DeviationExcessive: a grant that no allow (own or inherited) covers.
	DeviationExcessive DeviationKind = "excessive_grant"
	// DeviationDenied: a grant that an explicit deny (own or inherited) forbids.
	DeviationDenied DeviationKind = "denied_grant"
	// DeviationUnknownRole: a role holding grants that the policy does not mention.
	DeviationUnknownRole DeviationKind = "unknown_role"
	// DeviationGrantOption: an allowed grant held WITH GRANT OPTION that the policy does
	// not permit to be delegated (own or inherited GrantOption rules).
	DeviationGrantOption DeviationKind = "grant_option_excessive"
)

// Deviation is one observed grant that disagrees with the policy. It is a
// read-only report: it deliberately has no field that names or carries a
// remediation (revoke statement, command, action). Plain strings only; the
// test TestDiffNeverProducesRevokeAction pins that.
type Deviation struct {
	Kind         DeviationKind `json:"kind"`
	Role         string        `json:"role"`
	Object       string        `json:"object"`
	Privilege    string        `json:"privilege"`
	DeniedVia    string        `json:"deniedVia,omitempty"` // policy role that declared the matching deny
	PolicySource string        `json:"policySource"`
}

// DiffReport is the DB-02 output: the deviations plus the policy source and
// the number of grants examined, so a clean result is still attributable.
type DiffReport struct {
	PolicySource  string      `json:"policySource"`
	GrantsChecked int         `json:"grantsChecked"`
	Deviations    []Deviation `json:"deviations"`
}

// Report runs Diff and wraps the result with the policy source.
func Report(p Policy, actual []Grant) DiffReport {
	return DiffReport{PolicySource: p.Source, GrantsChecked: len(actual), Deviations: Diff(p, actual)}
}

// Diff compares observed grants with the policy. Order of evaluation per
// grant: unknown role, explicit deny (own or inherited), allow (own or
// inherited); anything left is excessive. The result is sorted by role,
// object, privilege, kind so it is deterministic. Diff never modifies its
// inputs and never produces anything executable.
func Diff(p Policy, actual []Grant) []Deviation {
	out := []Deviation{}
	for _, g := range actual {
		if _, known := p.Roles[g.Role]; !known {
			out = append(out, dev(p, DeviationUnknownRole, g, ""))
			continue
		}
		chain := roleChain(p, g.Role)
		if via, denied := deniedBy(p, chain, g); denied {
			out = append(out, dev(p, DeviationDenied, g, via))
			continue
		}
		if !allowed(p, chain, g) {
			out = append(out, dev(p, DeviationExcessive, g, ""))
		} else if g.GrantOption && !grantOptionAllowed(p, chain, g) {
			out = append(out, dev(p, DeviationGrantOption, g, ""))
		}
	}
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
	return out
}

func dev(p Policy, k DeviationKind, g Grant, via string) Deviation {
	return Deviation{Kind: k, Role: g.Role, Object: g.Object, Privilege: g.Privilege, DeniedVia: via, PolicySource: p.Source}
}

// roleChain returns the role and every role it inherits from, transitively,
// each once, in a stable order (the role first). Cycles and references to
// roles the policy does not define are tolerated.
func roleChain(p Policy, role string) []string {
	seen := map[string]bool{}
	var chain []string
	var walk func(string)
	walk = func(r string) {
		if seen[r] {
			return
		}
		seen[r] = true
		rp, ok := p.Roles[r]
		if !ok {
			return
		}
		chain = append(chain, r)
		parents := append([]string(nil), rp.Inherits...)
		sort.Strings(parents)
		for _, in := range parents {
			walk(in)
		}
	}
	walk(role)
	return chain
}

func deniedBy(p Policy, chain []string, g Grant) (string, bool) {
	for _, r := range chain {
		if matchesAny(p.Roles[r].Deny, g, true) {
			return r, true
		}
	}
	return "", false
}

func allowed(p Policy, chain []string, g Grant) bool {
	for _, r := range chain {
		if matchesAny(p.Roles[r].Allow, g, false) {
			return true
		}
	}
	return false
}

// grantOptionAllowed reports whether any role in the chain may delegate the grant.
func grantOptionAllowed(p Policy, chain []string, g Grant) bool {
	for _, r := range chain {
		if matchesAny(p.Roles[r].GrantOption, g, false) {
			return true
		}
	}
	return false
}

// matchesAny reports whether the object->privileges map covers the grant.
// For a deny (broad=true) a grant of ALL conflicts with any denied privilege on
// the object; for an allow it must be covered by an explicit ALL.
func matchesAny(m map[string][]string, g Grant, broad bool) bool {
	gp := strings.ToUpper(strings.TrimSpace(g.Privilege))
	for obj, privs := range m {
		if !objectMatches(obj, g.Object) {
			continue
		}
		for _, pr := range privs {
			up := strings.ToUpper(strings.TrimSpace(pr))
			if up == "ALL" || up == "*" || up == gp || (broad && gp == "ALL") {
				return true
			}
		}
	}
	return false
}

func objectMatches(pattern, object string) bool {
	if pattern == "*" || pattern == object {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(object, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// GrantsFromProbe converts the grants a read_grants probe returned into the Grant
// list Diff compares. It keeps every grant; nothing is filtered here.
func GrantsFromProbe(res DBProbeResult) []Grant {
	out := make([]Grant, 0, len(res.Grants))
	for _, g := range res.Grants {
		out = append(out, Grant{Role: g.Role, Object: g.Object, Privilege: g.Privilege, GrantOption: g.GrantOption})
	}
	return out
}

// PolicyFromJSON parses a policy file. The source must be named: a finding has to
// trace to the yardstick it was measured against, so an unnamed policy is refused.
func PolicyFromJSON(data []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("policy: %w", err)
	}
	if strings.TrimSpace(p.Source) == "" {
		return Policy{}, errors.New("policy: source is required")
	}
	if len(p.Roles) == 0 {
		return Policy{}, errors.New("policy: no roles defined")
	}
	return p, nil
}
