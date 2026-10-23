package cloudgraph

import (
	"slices"
	"sort"
	"strings"
)

// Scenario 4: wildcard RBAC. This is an analysis of configured permission. It reports rules whose verbs, resources
// or API groups are "*" and that are not limited by resourceNames. It reads only the inventory discovery already
// collected, so it makes no API call and writes nothing. A finding is a configuration result: it does not prove the
// access can be exercised.

// K8sWildcardFinding is one rule that grants a wildcard, with the identities bound to the role that holds it.
type K8sWildcardFinding struct {
	Role         string   // canonical role ID
	RoleKind     string   // "Role" or "ClusterRole"
	Rule         int      // index of the rule in the role's rules
	Verbs        []string // the rule's verbs, as collected
	Resources    []string // the rule's resources, as collected
	APIGroups    []string // the rule's API groups, as collected
	WildVerb     bool
	WildResource bool
	WildGroup    bool
	Subjects     []string // canonical IDs of identities bound to the role, sorted
	Bindings     []string // names of the bindings that grant the role, sorted
	// Complete is false when discovery was incomplete, so the subjects and bindings may be a partial picture.
	Complete bool
}

// K8sWildcardFindings reports every wildcard grant in the collected roles, sorted by role then rule.
func K8sWildcardFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sWildcardFinding {
	complete := rep != nil && rep.Complete
	roleIDs := make([]string, 0, len(inv.Roles))
	for id := range inv.Roles {
		roleIDs = append(roleIDs, id)
	}
	sort.Strings(roleIDs)

	var out []K8sWildcardFinding
	for _, roleID := range roleIDs {
		subjects, bindings := bindingsOfRole(inv, roleID)
		for i, r := range inv.Roles[roleID] {
			// A grant limited to named objects is not a wildcard grant over the resource.
			if len(r.ResourceNames) > 0 {
				continue
			}
			wv, wr, wg := hasWildcard(r.Verbs), hasWildcard(r.Resources), hasWildcard(r.APIGroups)
			if !wv && !wr && !wg {
				continue
			}
			out = append(out, K8sWildcardFinding{
				Role:         roleID,
				RoleKind:     roleKindOf(roleID),
				Rule:         i,
				Verbs:        r.Verbs,
				Resources:    r.Resources,
				APIGroups:    r.APIGroups,
				WildVerb:     wv,
				WildResource: wr,
				WildGroup:    wg,
				Subjects:     subjects,
				Bindings:     bindings,
				Complete:     complete,
			})
		}
	}
	return out
}

func hasWildcard(list []string) bool {
	return slices.Contains(list, "*")
}

// roleKindOf reads the kind from the canonical ID, which carries "/clusterrole/" for a ClusterRole.
func roleKindOf(roleID string) string {
	if strings.Contains(roleID, "/clusterrole/") {
		return "ClusterRole"
	}
	return "Role"
}

// bindingsOfRole returns the identities and binding names that grant the role, from the permission records
// discovery built from the bindings.
func bindingsOfRole(inv *K8sInventory, roleID string) (subjects, bindings []string) {
	seenS, seenB := map[string]bool{}, map[string]bool{}
	for _, p := range inv.Permissions {
		if p == nil || p.Target == nil || p.Source == nil || p.Target.CanonicalID != roleID {
			continue
		}
		if !seenS[p.Source.CanonicalID] {
			seenS[p.Source.CanonicalID] = true
			subjects = append(subjects, p.Source.CanonicalID)
		}
		if b := p.Attributes["binding"]; b != "" && !seenB[b] {
			seenB[b] = true
			bindings = append(bindings, b)
		}
	}
	sort.Strings(subjects)
	sort.Strings(bindings)
	return subjects, bindings
}
