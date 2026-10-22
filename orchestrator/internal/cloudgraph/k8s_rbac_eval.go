package cloudgraph

import "strings"

// Kubernetes RBAC evaluation of configured permissions (Phase 2).
//
// This answers one question: do the collected RBAC rules grant this request? That is a "configured
// permission" answer. It is not the API server's effective authorization decision, which also depends on
// other authorizers and on admission. It is also not proof that an attack path can be exercised.
//
// Matching follows the Kubernetes rules: RBAC is additive; "*" matches every verb or API group;
// "*" as a resource matches resources but not subresources, while "*/*" matches both; a resource
// name list restricts the grant and never matches a request that has no name.

// RBACDecision is the outcome of evaluating one request against the collected policy.
type RBACDecision string

const (
	// RBACGranted means a collected rule grants the request. More data cannot remove this grant.
	RBACGranted RBACDecision = "granted"
	// RBACNotGranted means no collected rule grants the request, and the policy is complete.
	RBACNotGranted RBACDecision = "not-granted"
	// RBACUnknown means no grant was found, but the policy is incomplete or a binding on the path
	// could not be resolved. Absence is then not evidence of denial.
	RBACUnknown RBACDecision = "unknown"
)

// RBACRule is one policy rule, as in rbac.authorization.k8s.io/v1.
type RBACRule struct {
	APIGroups       []string
	Resources       []string
	ResourceNames   []string
	Verbs           []string
	NonResourceURLs []string
}

// RBACRequest is one authorization question. A non-empty NonResourceURL makes it a non-resource request.
type RBACRequest struct {
	APIGroup       string // "" is the core group
	Resource       string // plural, with a subresource after "/", e.g. "pods/exec"
	Name           string // object name, empty for list and collection requests
	Verb           string
	NonResourceURL string
}

// EvaluateRBAC reports whether the rules grant the request. policyComplete is false when discovery was
// incomplete; unresolvedPaths counts bindings on the request's path that could not be resolved.
func EvaluateRBAC(rules []RBACRule, req RBACRequest, policyComplete bool, unresolvedPaths int) RBACDecision {
	for _, r := range rules {
		if ruleMatches(r, req) {
			return RBACGranted
		}
	}
	if !policyComplete || unresolvedPaths > 0 {
		return RBACUnknown
	}
	return RBACNotGranted
}

func ruleMatches(r RBACRule, req RBACRequest) bool {
	if !matchExactOrStar(r.Verbs, req.Verb) {
		return false
	}
	if req.NonResourceURL != "" {
		return matchURL(r.NonResourceURLs, req.NonResourceURL)
	}
	return matchExactOrStar(r.APIGroups, req.APIGroup) &&
		matchResource(r.Resources, req.Resource) &&
		matchResourceName(r.ResourceNames, req.Name)
}

// matchExactOrStar matches a verb or an API group. "*" matches anything, including the empty core group.
func matchExactOrStar(list []string, v string) bool {
	for _, e := range list {
		if e == "*" || e == v {
			return true
		}
	}
	return false
}

// matchResource matches a request resource ("pods" or "pods/exec") against rule entries.
func matchResource(list []string, res string) bool {
	for _, e := range list {
		switch {
		case e == "*/*":
			return true
		case e == "*":
			// Matches resources only, never subresources.
			if !strings.Contains(res, "/") {
				return true
			}
		case strings.HasPrefix(e, "*/"):
			// "*/exec" matches any resource's exec subresource.
			sub := e[2:]
			if i := strings.LastIndex(res, "/"); i >= 0 && res[i+1:] == sub {
				return true
			}
		case strings.HasSuffix(e, "/*"):
			// "pods/*" matches every subresource of pods, but not pods itself.
			prefix := strings.TrimSuffix(e, "/*")
			if strings.HasPrefix(res, prefix+"/") {
				return true
			}
		default:
			if e == res {
				return true
			}
		}
	}
	return false
}

// matchResourceName: no names means every name. With names, a request without a name never matches.
func matchResourceName(names []string, name string) bool {
	if len(names) == 0 {
		return true
	}
	if name == "" {
		return false
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// matchURL matches a non-resource URL. An entry may end in "*" to match a prefix.
func matchURL(list []string, url string) bool {
	for _, e := range list {
		switch {
		case e == "*":
			return true
		case strings.HasSuffix(e, "*"):
			if strings.HasPrefix(url, strings.TrimSuffix(e, "*")) {
				return true
			}
		default:
			if e == url {
				return true
			}
		}
	}
	return false
}
