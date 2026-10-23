package cloudgraph

import (
	"sort"
	"strings"
)

// Scenario 7: dangerous pod configuration. This reports pods whose spec shares a host namespace (PID, IPC or
// network), runs a privileged container, or mounts a hostPath volume. Each is a setting that lets the workload reach
// beyond its own container. It reads only the pod settings discovery recorded, so it makes no API call and writes
// nothing. It is configured state, not proof that the workload can be used to escape.

// K8sPodConfigFinding is one pod with at least one dangerous setting.
type K8sPodConfigFinding struct {
	Workload  string   // canonical pod ID
	Namespace string   // pod namespace
	Reasons   []string // dangerous settings, sorted
	// Complete is false when discovery was incomplete, so the pod may be missing from the picture.
	Complete bool
}

// K8sPodConfigFindings returns every pod with a dangerous setting, sorted by pod ID.
func K8sPodConfigFindings(inv *K8sInventory, rep *K8sDiscoveryReport) []K8sPodConfigFinding {
	complete := rep != nil && rep.Complete
	var out []K8sPodConfigFinding
	for _, r := range inv.Resources {
		if r.Kind != "k8s:pod" {
			continue
		}
		var reasons []string
		for _, host := range []struct{ attr, label string }{
			{"hostPID", "hostPID"}, {"hostIPC", "hostIPC"}, {"hostNetwork", "hostNetwork"},
		} {
			if r.Attributes[host.attr] == "true" {
				reasons = append(reasons, host.label)
			}
		}
		for _, c := range splitList(r.Attributes["privilegedContainers"]) {
			reasons = append(reasons, "privileged container: "+c)
		}
		for _, p := range splitList(r.Attributes["hostPaths"]) {
			reasons = append(reasons, "hostPath: "+p)
		}
		if len(reasons) == 0 {
			continue
		}
		sort.Strings(reasons)
		out = append(out, K8sPodConfigFinding{
			Workload:  r.CanonicalID,
			Namespace: r.Attributes["namespace"],
			Reasons:   reasons,
			Complete:  complete,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Workload < out[j].Workload })
	return out
}

// splitList splits a comma-joined attribute, returning nothing for an empty value.
func splitList(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}
