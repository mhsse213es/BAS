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
	default:
		return false
	}
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
