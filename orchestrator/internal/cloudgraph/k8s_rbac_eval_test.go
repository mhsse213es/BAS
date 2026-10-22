package cloudgraph

import "testing"

// These cases follow the Kubernetes RBAC matching rules. Each one states the rule it checks.

func rbacReq(group, resource, name, verb string) RBACRequest {
	return RBACRequest{APIGroup: group, Resource: resource, Name: name, Verb: verb}
}

func TestRBACEval_ExactRuleGrantsOnlyItsVerbAndResource(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "pods", "web-1", "get"), true, 0); got != RBACGranted {
		t.Fatalf("get pods = %s, want granted", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("", "pods", "web-1", "delete"), true, 0); got != RBACNotGranted {
		t.Fatalf("delete pods = %s, want not-granted", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("", "secrets", "", "get"), true, 0); got != RBACNotGranted {
		t.Fatalf("get secrets = %s, want not-granted", got)
	}
}

func TestRBACEval_APIGroupMustMatch(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "deployments", "", "create"), true, 0); got != RBACNotGranted {
		t.Fatalf("core group must not match apps: %s", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("apps", "deployments", "", "create"), true, 0); got != RBACGranted {
		t.Fatalf("apps group should match: %s", got)
	}
}

func TestRBACEval_VerbWildcardMatchesEveryVerb(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}}
	for _, v := range []string{"get", "list", "create", "patch", "delete", "exec"} {
		if got := EvaluateRBAC(rules, rbacReq("", "pods", "", v), true, 0); got != RBACGranted {
			t.Fatalf("verb %s under * = %s, want granted", v, got)
		}
	}
}

func TestRBACEval_StarResourceDoesNotCoverSubresources(t *testing.T) {
	// Kubernetes: "*" matches resources but not subresources. "pods/exec" needs "pods/exec" or "*/*".
	rules := []RBACRule{{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"*"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "pods", "", "get"), true, 0); got != RBACGranted {
		t.Fatalf("* should match pods: %s", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("", "pods/exec", "", "create"), true, 0); got != RBACNotGranted {
		t.Fatalf("* must not match pods/exec: %s", got)
	}
}

func TestRBACEval_StarStarCoversSubresources(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{"*"}, Resources: []string{"*/*"}, Verbs: []string{"*"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "pods/exec", "", "create"), true, 0); got != RBACGranted {
		t.Fatalf("*/* should match pods/exec: %s", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("apps", "deployments", "", "get"), true, 0); got != RBACGranted {
		t.Fatalf("apiGroups * should match apps: %s", got)
	}
}

func TestRBACEval_SubresourceRules(t *testing.T) {
	exact := []RBACRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}}
	if got := EvaluateRBAC(exact, rbacReq("", "pods/exec", "", "create"), true, 0); got != RBACGranted {
		t.Fatalf("exact pods/exec: %s", got)
	}
	if got := EvaluateRBAC(exact, rbacReq("", "pods", "", "create"), true, 0); got != RBACNotGranted {
		t.Fatalf("pods/exec rule must not grant pods: %s", got)
	}
	starSub := []RBACRule{{APIGroups: []string{""}, Resources: []string{"pods/*"}, Verbs: []string{"get"}}}
	if got := EvaluateRBAC(starSub, rbacReq("", "pods/log", "", "get"), true, 0); got != RBACGranted {
		t.Fatalf("pods/* should match pods/log: %s", got)
	}
	if got := EvaluateRBAC(starSub, rbacReq("", "pods", "", "get"), true, 0); got != RBACNotGranted {
		t.Fatalf("pods/* must not match the pods resource itself: %s", got)
	}
	anySub := []RBACRule{{APIGroups: []string{""}, Resources: []string{"*/exec"}, Verbs: []string{"create"}}}
	if got := EvaluateRBAC(anySub, rbacReq("", "pods/exec", "", "create"), true, 0); got != RBACGranted {
		t.Fatalf("*/exec should match pods/exec: %s", got)
	}
	if got := EvaluateRBAC(anySub, rbacReq("", "pods/log", "", "create"), true, 0); got != RBACNotGranted {
		t.Fatalf("*/exec must not match pods/log: %s", got)
	}
}

func TestRBACEval_ResourceNamesRestrictTheGrant(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"app-db"}, Verbs: []string{"get"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "secrets", "app-db", "get"), true, 0); got != RBACGranted {
		t.Fatalf("named secret app-db: %s", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("", "secrets", "other", "get"), true, 0); got != RBACNotGranted {
		t.Fatalf("a different secret must not be granted: %s", got)
	}
	// A request with no name (a list or a collection call) never matches a name-restricted rule.
	if got := EvaluateRBAC(rules, rbacReq("", "secrets", "", "get"), true, 0); got != RBACNotGranted {
		t.Fatalf("a nameless request must not match a name-restricted rule: %s", got)
	}
}

func TestRBACEval_NoResourceNamesMeansEveryName(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "secrets", "anything", "get"), true, 0); got != RBACGranted {
		t.Fatalf("no resourceNames should cover any name: %s", got)
	}
}

func TestRBACEval_NonResourceURLs(t *testing.T) {
	rules := []RBACRule{{NonResourceURLs: []string{"/healthz", "/api*"}, Verbs: []string{"get"}}}
	if got := EvaluateRBAC(rules, RBACRequest{NonResourceURL: "/healthz", Verb: "get"}, true, 0); got != RBACGranted {
		t.Fatalf("exact non-resource URL: %s", got)
	}
	if got := EvaluateRBAC(rules, RBACRequest{NonResourceURL: "/api/v1/x", Verb: "get"}, true, 0); got != RBACGranted {
		t.Fatalf("trailing-star URL should match: %s", got)
	}
	if got := EvaluateRBAC(rules, RBACRequest{NonResourceURL: "/version", Verb: "get"}, true, 0); got != RBACNotGranted {
		t.Fatalf("unlisted URL: %s", got)
	}
	// A resource rule must not grant a non-resource URL, and a non-resource rule must not grant a resource.
	res := []RBACRule{{APIGroups: []string{"*"}, Resources: []string{"*/*"}, Verbs: []string{"*"}}}
	if got := EvaluateRBAC(res, RBACRequest{NonResourceURL: "/healthz", Verb: "get"}, true, 0); got != RBACNotGranted {
		t.Fatalf("a resource rule must not grant a non-resource URL: %s", got)
	}
}

func TestRBACEval_MultipleRulesAreAdditive(t *testing.T) {
	rules := []RBACRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
	}
	if got := EvaluateRBAC(rules, rbacReq("", "pods", "", "delete"), true, 0); got != RBACGranted {
		t.Fatalf("second rule should grant delete: %s", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("", "pods", "", "create"), true, 0); got != RBACNotGranted {
		t.Fatalf("no rule grants create: %s", got)
	}
}

// A grant that is found is a grant, even if discovery is incomplete: more data cannot remove it.
// Absence of a grant is only "not granted" when the collected policy is complete.
func TestRBACEval_IncompleteDiscoveryMakesAbsenceUnknown(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "pods", "", "get"), false, 0); got != RBACGranted {
		t.Fatalf("a found grant stays granted under incomplete discovery: %s", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("", "secrets", "", "get"), false, 0); got != RBACUnknown {
		t.Fatalf("absence under incomplete discovery must be unknown, not denied: %s", got)
	}
}

func TestRBACEval_UnresolvedBindingMakesAbsenceUnknown(t *testing.T) {
	rules := []RBACRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
	if got := EvaluateRBAC(rules, rbacReq("", "secrets", "", "get"), true, 1); got != RBACUnknown {
		t.Fatalf("an unresolved binding on the path must make absence unknown: %s", got)
	}
	if got := EvaluateRBAC(rules, rbacReq("", "pods", "", "get"), true, 1); got != RBACGranted {
		t.Fatalf("a grant is still granted with an unresolved binding elsewhere: %s", got)
	}
}

func TestRBACEval_NoRulesIsNotGrantedWhenComplete(t *testing.T) {
	if got := EvaluateRBAC(nil, rbacReq("", "pods", "", "get"), true, 0); got != RBACNotGranted {
		t.Fatalf("empty policy, complete: %s, want not-granted", got)
	}
	if got := EvaluateRBAC(nil, rbacReq("", "pods", "", "get"), false, 0); got != RBACUnknown {
		t.Fatalf("empty policy, incomplete: %s, want unknown", got)
	}
}
