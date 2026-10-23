package cloudgraph

import "sort"

// Scenario 8: service-account token exposure. A pod that mounts its ServiceAccount token exposes that credential to
// the workload. The effective setting is the pod's automountServiceAccountToken if it sets one, otherwise its
// ServiceAccount's, otherwise the platform default, which mounts the token. This reports each pod that mounts a
// token. A mount is marked unneeded when the account holds no bindings: the token then grants nothing, so the mount
// serves no purpose. A mount with bindings is reported but not called unneeded, since the workload may use the API.
// It reads only the discovered inventory and writes nothing. It is configured state, not proof of misuse.

// K8sTokenExposureFinding is one pod that mounts its ServiceAccount token.
type K8sTokenExposureFinding struct {
	Workload  string   // canonical pod ID
	Namespace string   // pod namespace
	Subject   string   // canonical ServiceAccount ID the token belongs to
	Bindings  []string // binding names that grant the account anything, sorted
	// Unneeded is true when the account holds no bindings, so the mounted token grants nothing.
	Unneeded bool
	// Complete is false when discovery was incomplete, so the bindings may be a partial picture.
	Complete bool
}

// K8sTokenExposureFindings returns every pod that mounts a ServiceAccount token, sorted by pod ID.
func K8sTokenExposureFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sTokenExposureFinding {
	complete := rep != nil && rep.Complete
	cluster := ""
	if rep != nil {
		cluster = rep.ClusterName
	}

	saAutomount := map[string]string{}
	for _, id := range inv.Identities {
		if id.Kind == "k8s:serviceaccount" {
			saAutomount[id.CanonicalID] = id.Attributes["automountToken"]
		}
	}

	var out []K8sTokenExposureFinding
	for _, r := range inv.Resources {
		if r.Kind != "k8s:pod" {
			continue
		}
		ns := r.Attributes["namespace"]
		subject := k8sCanonicalID(cluster, ns, "serviceaccount", r.Attributes["serviceAccount"])
		if effectiveAutomount(r.Attributes["automountToken"], saAutomount[subject]) == "false" {
			continue
		}
		bindings := subjectBindingNames(inv, subject)
		out = append(out, K8sTokenExposureFinding{
			Workload:  r.CanonicalID,
			Namespace: ns,
			Subject:   subject,
			Bindings:  bindings,
			Unneeded:  len(bindings) == 0,
			Complete:  complete,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Workload < out[j].Workload })
	return out
}

// effectiveAutomount returns the setting that applies: the pod's if it sets one, else the account's, else the
// platform default ("true", which mounts the token).
func effectiveAutomount(podSetting, accountSetting string) string {
	if podSetting == "true" || podSetting == "false" {
		return podSetting
	}
	if accountSetting == "true" || accountSetting == "false" {
		return accountSetting
	}
	return "true"
}

// subjectBindingNames returns the sorted, de-duplicated binding names that grant the subject anything.
func subjectBindingNames(inv *K8sInventory, subject string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range inv.Permissions {
		if p == nil || p.Source == nil || p.Source.CanonicalID != subject {
			continue
		}
		if b := p.Attributes["binding"]; b != "" && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	sort.Strings(out)
	return out
}
