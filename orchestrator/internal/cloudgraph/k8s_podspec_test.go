package cloudgraph

import (
	"testing"
)

const podSpecFixture = `{"items":[` +
	`{"metadata":{"name":"risky","namespace":"default"},"spec":{"serviceAccountName":"web","hostPID":true,"hostNetwork":true,` +
	`"containers":[{"name":"c1","securityContext":{"privileged":true}},{"name":"c2"}],` +
	`"volumes":[{"name":"host","hostPath":{"path":"/var/run"}},{"name":"cfg"}]}},` +
	`{"metadata":{"name":"plain","namespace":"default"},"spec":{"serviceAccountName":"web","automountServiceAccountToken":false,` +
	`"containers":[{"name":"c1"}]}}` +
	`]}`

func podAttrs(t *testing.T, inv *K8sInventory, name string) map[string]string {
	t.Helper()
	for _, r := range inv.Resources {
		if r.Kind == "k8s:pod" && r.DisplayName == name {
			return r.Attributes
		}
	}
	t.Fatalf("pod %s not in inventory", name)
	return nil
}

// TestPodSpec_RecordsSecurityFields checks discovery keeps host namespaces, privileged containers, hostPath volumes
// and the token-automount setting as pod attributes.
func TestPodSpec_RecordsSecurityFields(t *testing.T) {
	inv, _ := analysisFor(t, map[string]string{"/api/v1/pods": podSpecFixture})
	risky := podAttrs(t, inv, "risky")
	want := map[string]string{
		"hostPID":              "true",
		"hostIPC":              "false",
		"hostNetwork":          "true",
		"privilegedContainers": "c1",
		"hostPaths":            "/var/run",
		"automountToken":       "unset",
	}
	for k, v := range want {
		if risky[k] != v {
			t.Fatalf("risky[%s] = %q, want %q (attrs %v)", k, risky[k], v, risky)
		}
	}
	plain := podAttrs(t, inv, "plain")
	if plain["automountToken"] != "false" || plain["hostNetwork"] != "false" || plain["privilegedContainers"] != "" {
		t.Fatalf("plain attrs = %v, want no host access and automountToken false", plain)
	}
}
