package cloudgraph

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestK8sAccess_LiveLab_MatchesKubectlAuthCanI compares the configured-permission analysis with the API
// server's own answer (kubectl auth can-i --as) across a matrix of lab subjects and requests. The lab policy
// is complete (discovery reports no gaps), so every analysed decision must be granted or not-granted, and
// each must agree with the server. Disagreements are reported as they are, not tuned away.
//
// Requires the KUBE_LAB_* variables from k8s_discovery_lab_test.go, and a kubectl with an admin context
// (KUBE_LAB_KUBECTL_CONTEXT, default kind-bas-lab) for impersonation.
func TestK8sAccess_LiveLab_MatchesKubectlAuthCanI(t *testing.T) {
	api := os.Getenv("KUBE_LAB_API")
	tokenFile := os.Getenv("KUBE_LAB_TOKEN_FILE")
	caFile := os.Getenv("KUBE_LAB_CA_FILE")
	if api == "" || tokenFile == "" || caFile == "" {
		t.Skip("lab not configured")
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not on PATH")
	}
	kctx := os.Getenv("KUBE_LAB_KUBECTL_CONTEXT")
	if kctx == "" {
		kctx = "kind-bas-lab"
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewK8sDiscoveryClient(K8sDiscoveryConfig{ClusterName: labClusterName(), APIServer: api, Token: strings.TrimSpace(string(tokenBytes)), CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	inv, rep, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Complete {
		t.Fatalf("the lab policy must be complete for this comparison; gaps=%v", rep.Gaps)
	}

	type subject struct{ canonical, asUser string }
	subjects := []subject{
		{"k8s://" + labClusterName() + "/default/serviceaccount/web", "system:serviceaccount:default:web"},
		{"k8s://" + labClusterName() + "/kube-system/serviceaccount/bas-discovery", "system:serviceaccount:kube-system:bas-discovery"},
	}
	type request struct{ verb, resource, ns string }
	requests := []request{
		{"get", "pods", "default"},
		{"list", "pods", "default"},
		{"create", "pods", "default"},
		{"delete", "pods", "default"},
		{"get", "secrets", "default"},
		{"create", "pods/exec", "default"},
		{"create", "rolebindings", "default"},
		{"get", "configmaps", "default"},
		{"list", "namespaces", ""},
		{"get", "clusterroles", ""},
		{"list", "secrets", "kube-system"},
		{"get", "pods", "kube-system"},
		{"bind", "clusterroles", ""},
	}
	rbacResources := map[string]bool{"roles": true, "clusterroles": true, "rolebindings": true, "clusterrolebindings": true}

	mismatches := 0
	for _, s := range subjects {
		for _, r := range requests {
			group := ""
			if rbacResources[r.resource] {
				group = "rbac.authorization.k8s.io"
			}
			res := AnalyseK8sAccess(inv, rep, K8sAccessQuery{
				Subject:   s.canonical,
				Namespace: r.ns,
				Request:   RBACRequest{APIGroup: group, Resource: r.resource, Verb: r.verb},
			})

			args := []string{"--context", kctx, "auth", "can-i", r.verb, r.resource, "--as", s.asUser}
			if r.ns != "" {
				args = append(args, "-n", r.ns)
			}
			// can-i exits non-zero when the answer is "no"; the printed answer is what matters.
			out, _ := exec.Command("kubectl", args...).Output()
			answer := strings.TrimSpace(string(out))

			want := ""
			switch res.Decision {
			case RBACGranted:
				want = "yes"
			case RBACNotGranted:
				want = "no"
			case RBACUnknown:
				t.Errorf("%s %s/%s ns=%q: analysis is unknown on a complete lab policy (unresolved=%v)", s.asUser, r.verb, r.resource, r.ns, res.Unresolved)
				continue
			}
			if answer != want {
				mismatches++
				t.Errorf("%s %s %s ns=%q: analysis=%s, API server=%q (evidence=%v)", s.asUser, r.verb, r.resource, r.ns, res.Decision, answer, res.Evidence)
				continue
			}
			t.Logf("agree: %s %s %s ns=%q -> %s", s.asUser, r.verb, r.resource, r.ns, answer)
		}
	}
	if mismatches == 0 {
		t.Logf("all %d comparisons agree with the API server", len(subjects)*len(requests))
	}
}
