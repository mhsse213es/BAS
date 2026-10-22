package cloudgraph

import "strings"

// Phase 2: analysis of the Kubernetes RBAC graph produced by Discover.
//
// Every result here is configured permission: what the collected RBAC policy grants. It is not the API
// server's effective authorization decision (other authorizers, admission and impersonation can change it),
// and it is not evidence that an attack path can be exercised. Validate against kubectl auth can-i in the lab.

// k8sClassConfigured labels every finding from this file, so no output reads as exploitability.
const k8sClassConfigured = "configured-permission"

// K8sAccessQuery asks what a subject is configured to be granted for one request in one namespace.
type K8sAccessQuery struct {
	Subject   string // canonical ID of a service account, user or group
	Namespace string // "" for a cluster-scoped request
	Request   RBACRequest
}

// K8sAccessResult carries the decision and the bindings behind it.
type K8sAccessResult struct {
	Decision   RBACDecision
	Evidence   []string // bindings whose role grants the request
	Unresolved []string // bindings that apply to the subject but whose role was not listed
}

// K8sSubjectGroups returns the subject plus the groups it is in implicitly. Every authenticated subject is
// in system:authenticated. Service accounts are also in system:serviceaccounts and their namespace's group.
func K8sSubjectGroups(cluster, subject string) []string {
	set := []string{subject, k8sCanonicalID(cluster, "", "group", "system:authenticated")}
	parts := strings.SplitN(subject, "/", 6)
	if len(parts) == 6 && parts[4] == "serviceaccount" {
		set = append(set,
			k8sCanonicalID(cluster, "", "group", "system:serviceaccounts"),
			k8sCanonicalID(cluster, "", "group", "system:serviceaccounts:"+parts[3]))
	}
	return set
}

// bindingApplies: a ClusterRoleBinding applies everywhere. A RoleBinding applies only inside its own
// namespace, even when it references a ClusterRole. A cluster-scoped request (reqNS "") is matched only
// by ClusterRoleBindings.
func bindingApplies(kind, bindingNS, reqNS string) bool {
	if kind == "ClusterRoleBinding" {
		return true
	}
	return reqNS != "" && bindingNS == reqNS
}

// AnalyseK8sAccess evaluates one request for one subject against the collected graph.
func AnalyseK8sAccess(inv *K8sInventory, rep *K8sDiscoveryReport, q K8sAccessQuery) K8sAccessResult {
	subjects := K8sSubjectGroups(rep.ClusterName, q.Subject)
	inSet := func(id string) bool {
		for _, s := range subjects {
			if s == id {
				return true
			}
		}
		return false
	}

	var rules []RBACRule
	var evidence []string
	for _, p := range inv.Permissions {
		if p.Source == nil || p.Target == nil || !inSet(p.Source.CanonicalID) {
			continue
		}
		if !bindingApplies(p.Attributes["bindingKind"], p.Attributes["namespace"], q.Namespace) {
			continue
		}
		role := inv.Roles[p.Target.CanonicalID]
		rules = append(rules, role...)
		if EvaluateRBAC(role, q.Request, true, 0) == RBACGranted {
			evidence = append(evidence, p.Attributes["binding"])
		}
	}

	var unresolved []string
	for _, u := range inv.Unresolved {
		if !bindingApplies(u.BindingKind, u.Namespace, q.Namespace) {
			continue
		}
		for _, id := range u.SubjectIDs {
			if inSet(id) {
				unresolved = append(unresolved, u.Binding)
				break
			}
		}
	}

	return K8sAccessResult{
		Decision:   EvaluateRBAC(rules, q.Request, rep.Complete, len(unresolved)),
		Evidence:   evidence,
		Unresolved: unresolved,
	}
}

// K8sPrivilegeFinding is one capability a workload's service account is configured to have.
type K8sPrivilegeFinding struct {
	Workload   string
	Subject    string
	Capability string
	Namespace  string
	Decision   RBACDecision
	Evidence   []string
	Class      string
}

// k8sPrivilegeCatalog lists the capabilities checked for every pod's service account. Name-restricted
// rules do not match these requests, because they carry no object name. That is deliberate: a broad
// capability is reported only when it is broad.
var k8sPrivilegeCatalog = []struct {
	Capability string
	Request    RBACRequest
}{
	{"list-secrets", RBACRequest{Resource: "secrets", Verb: "list"}},
	{"get-secrets", RBACRequest{Resource: "secrets", Verb: "get"}},
	{"create-pods", RBACRequest{Resource: "pods", Verb: "create"}},
	{"exec-into-pods", RBACRequest{Resource: "pods/exec", Verb: "create"}},
	{"create-rolebindings", RBACRequest{APIGroup: "rbac.authorization.k8s.io", Resource: "rolebindings", Verb: "create"}},
	{"escalate-roles", RBACRequest{APIGroup: "rbac.authorization.k8s.io", Resource: "roles", Verb: "escalate"}},
}

// K8sPrivilegeFindings reports, for each pod, the catalog capabilities its service account is granted or
// cannot be ruled out for. Unknown results are kept, since a missing answer must not look like a denial.
func K8sPrivilegeFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sPrivilegeFinding {
	var out []K8sPrivilegeFinding
	for _, r := range inv.Resources {
		if r.Kind != "k8s:pod" {
			continue
		}
		ns := r.Attributes["namespace"]
		subject := k8sCanonicalID(rep.ClusterName, ns, "serviceaccount", r.Attributes["serviceAccount"])
		for _, c := range k8sPrivilegeCatalog {
			res := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: subject, Namespace: ns, Request: c.Request})
			if res.Decision == RBACNotGranted {
				continue
			}
			out = append(out, K8sPrivilegeFinding{
				Workload:   r.CanonicalID,
				Subject:    subject,
				Capability: c.Capability,
				Namespace:  ns,
				Decision:   res.Decision,
				Evidence:   res.Evidence,
				Class:      k8sClassConfigured,
			})
		}
	}
	return out
}
