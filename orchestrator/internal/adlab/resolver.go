// Package adlab is AD-M06's Lab Factory: deterministic synthetic AD
// environments, the first environment-backed adchain.ConditionResolver,
// and a harness that validates the adenv model + M04 predicates + the
// adchain planner end-to-end. Pure Go, no DB, no live AD. Depends one-way
// on adenv, adprimitive, and adchain.
package adlab

import (
	"strings"

	"github.com/audspect/bas/internal/adenv"
)

const aclRightPrefix = "acl_right_held:"

// EnvResolver answers adchain's Prerequisites.Conditions keys by reading an
// adenv.Environment relative to a fixed attacker foothold (the attacker
// principal plus its transitive group memberships). It satisfies
// adchain.ConditionResolver.
type EnvResolver struct {
	env        adenv.Environment
	controlled map[string]bool // attacker + every group it transitively belongs to
}

// NewEnvResolver precomputes the attacker's transitive principal set.
func NewEnvResolver(env adenv.Environment, attacker string) *EnvResolver {
	controlled := map[string]bool{attacker: true}
	// Fixed-point: keep adding any group whose Members includes a principal
	// already controlled, until a pass adds nothing. The map doubles as the
	// visited-set, so a membership cycle terminates.
	for {
		added := false
		for _, g := range env.Identity.Groups {
			if controlled[g.Name] {
				continue
			}
			for _, m := range g.Members {
				if controlled[m] {
					controlled[g.Name] = true
					added = true
					break
				}
			}
		}
		if !added {
			break
		}
	}
	return &EnvResolver{env: env, controlled: controlled}
}

// Resolve implements adchain.ConditionResolver. Unknown or malformed keys
// return false (fail-closed).
func (r *EnvResolver) Resolve(key string) bool {
	if right, ok := strings.CutPrefix(key, aclRightPrefix); ok {
		if right == "" {
			return false
		}
		return r.holdsACLRight(adenv.ACLRight(right))
	}
	switch key {
	case "esc1_vulnerable_template":
		return r.hasEnrollableVulnerableTemplate(adenv.IsESC1Vulnerable)
	case "esc2_vulnerable_template":
		return r.hasEnrollableVulnerableTemplate(adenv.IsESC2Vulnerable)
	case "esc3_vulnerable_template":
		return r.hasEnrollableVulnerableTemplate(adenv.IsESC3Vulnerable)
	case "esc4_template_write_access":
		return r.hasWritableTemplate()
	case "esc6_vulnerable_ca":
		return r.esc6Reachable()
	case "esc8_relayable_ca":
		return r.esc8Relayable()
	case "controls_unconstrained_delegation_principal":
		return r.controlsUnconstrainedDelegation()
	case "controls_constrained_delegation_principal":
		return r.controlsConstrainedDelegation()
	case "intra_forest_trust_abusable":
		return r.hasIntraForestTrustAbuse()
	case "cross_forest_trust_sid_filter_disabled":
		return r.hasCrossForestSIDAbuse()
	default:
		return false
	}
}

// hasIntraForestTrustAbuse is true when the forest contains a parent-child trust,
// across which SID-history injection needs no disabled protection.
func (r *EnvResolver) hasIntraForestTrustAbuse() bool {
	for _, tr := range r.env.Forest.Trusts {
		if adenv.IsIntraForestTrustAbusable(tr) {
			return true
		}
	}
	return false
}

// hasCrossForestSIDAbuse is true when the forest contains a cross-forest/external
// trust whose SID filtering has been disabled.
func (r *EnvResolver) hasCrossForestSIDAbuse() bool {
	for _, tr := range r.env.Forest.Trusts {
		if adenv.IsCrossForestSIDAbusable(tr) {
			return true
		}
	}
	return false
}

// controlsUnconstrainedDelegation is true when the attacker controls a principal
// configured for unconstrained delegation -- the position from which a coerced
// privileged authentication yields that principal's TGT.
func (r *EnvResolver) controlsUnconstrainedDelegation() bool {
	for _, p := range r.env.Delegation.Unconstrained {
		if r.controlled[p] {
			return true
		}
	}
	return false
}

// controlsConstrainedDelegation is true when the attacker controls a principal
// configured for constrained delegation -- the position from which S4U lets it
// obtain a service ticket to one of its configured targets as another user.
func (r *EnvResolver) controlsConstrainedDelegation() bool {
	for _, cd := range r.env.Delegation.Constrained {
		if r.controlled[cd.Principal] {
			return true
		}
	}
	return false
}

func (r *EnvResolver) templateByName(name string) (adenv.CertTemplate, bool) {
	for _, t := range r.env.PKI.Templates {
		if t.Name == name {
			return t, true
		}
	}
	return adenv.CertTemplate{}, false
}

// esc6Reachable is true when some CA carries the SAN policy flag AND publishes a
// template the attacker can enroll in that yields a client-auth certificate --
// enrollment then grants a cert for an arbitrary identity.
func (r *EnvResolver) esc6Reachable() bool {
	for _, ca := range r.env.PKI.CAs {
		if !adenv.IsESC6Vulnerable(ca) {
			continue
		}
		for _, name := range ca.PublishedTemplates {
			if t, ok := r.templateByName(name); ok && r.canEnroll(t) && adenv.HasClientAuthEKU(t) {
				return true
			}
		}
	}
	return false
}

// esc8Relayable is true when some CA exposes a web-enrollment endpoint without
// EPA. ESC8 relays a coerced principal's authentication, so it needs no
// attacker enrollment right -- only the relayable endpoint.
func (r *EnvResolver) esc8Relayable() bool {
	for _, ca := range r.env.PKI.CAs {
		if adenv.IsESC8Vulnerable(ca) {
			return true
		}
	}
	return false
}

func (r *EnvResolver) holdsACLRight(right adenv.ACLRight) bool {
	for _, ace := range r.env.Authorization.ACLs {
		if ace.Right == right && r.controlled[ace.Principal] {
			return true
		}
	}
	return false
}

func (r *EnvResolver) hasEnrollableVulnerableTemplate(vulnerable func(adenv.CertTemplate) bool) bool {
	for _, t := range r.env.PKI.Templates {
		if vulnerable(t) && r.canEnroll(t) {
			return true
		}
	}
	return false
}

func (r *EnvResolver) canEnroll(t adenv.CertTemplate) bool {
	for _, p := range t.EnrollmentRights {
		if r.controlled[p] {
			return true
		}
	}
	return false
}

func (r *EnvResolver) hasWritableTemplate() bool {
	for _, t := range r.env.PKI.Templates {
		for p := range r.controlled {
			if adenv.HasTemplateWriteAccess(t, p) {
				return true
			}
		}
	}
	return false
}
