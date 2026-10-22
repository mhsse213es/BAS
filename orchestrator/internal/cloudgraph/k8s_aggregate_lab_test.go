package cloudgraph

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// labAggregateManifest creates a disposable aggregation source, an aggregating ClusterRole whose rules the
// controller fills in, and a ClusterRoleBinding of that role to the lab service account web. Every object is
// named bas-agg-* and labelled as a lab fixture; the test deletes them afterwards.
const labAggregateManifest = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bas-agg-source
  labels:
    rbac.audspect.test/aggregate-to-probe: "true"
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bas-agg-probe
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        rbac.audspect.test/aggregate-to-probe: "true"
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bas-agg-probe-web
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: bas-agg-probe
subjects:
  - kind: ServiceAccount
    name: web
    namespace: default
`

// TestK8sAccess_LiveLab_AggregatedClusterRole checks that discovery sees rules the controller added to an
// aggregating ClusterRole, and that the analysis and the API server agree on a grant that comes only from
// aggregation. It needs admin access (kubectl with KUBE_LAB_KUBECTL_CONTEXT) to create its disposable objects.
func TestK8sAccess_LiveLab_AggregatedClusterRole(t *testing.T) {
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
	kubectl := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command("kubectl", append([]string{"--context", kctx}, args...)...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	if out, err := kubectl(labAggregateManifest, "apply", "-f", "-"); err != nil {
		t.Fatalf("creating the disposable objects failed: %v: %s", err, out)
	}
	defer func() {
		_, _ = kubectl("", "delete", "clusterrolebinding", "bas-agg-probe-web", "--ignore-not-found")
		_, _ = kubectl("", "delete", "clusterrole", "bas-agg-probe", "bas-agg-source", "--ignore-not-found")
	}()

	// The aggregation controller fills in the rules asynchronously; wait for them.
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, _ := kubectl("", "get", "clusterrole", "bas-agg-probe", "-o", "jsonpath={.rules[*].verbs}")
		if strings.Contains(out, "get") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the aggregating ClusterRole never received the source rules (last value %q)", out)
		}
		time.Sleep(time.Second)
	}

	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewK8sDiscoveryClient(K8sDiscoveryConfig{ClusterName: "kind-bas-lab", APIServer: api, Token: strings.TrimSpace(string(tokenBytes)), CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	inv, rep, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Complete {
		t.Fatalf("the lab policy must be complete; gaps=%v", rep.Gaps)
	}

	probe := findRes(inv.Resources, "k8s://kind-bas-lab/_cluster/clusterrole/bas-agg-probe")
	if probe == nil {
		t.Fatal("the aggregating ClusterRole is missing from discovery")
	}
	if !strings.Contains(probe.Attributes["rules"], `"configmaps"`) {
		t.Fatalf("discovery did not record the aggregated rules: %s", probe.Attributes["rules"])
	}

	req := RBACRequest{Resource: "configmaps", Verb: "get"}
	res := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: "k8s://kind-bas-lab/default/serviceaccount/web", Request: req})
	if res.Decision != RBACGranted || len(res.Evidence) != 1 || res.Evidence[0] != "bas-agg-probe-web" {
		t.Fatalf("analysis = %+v, want granted via bas-agg-probe-web", res)
	}
	answer, _ := kubectl("", "auth", "can-i", "get", "configmaps", "--as", "system:serviceaccount:default:web")
	if strings.TrimSpace(answer) != "yes" {
		t.Fatalf("the API server answered %q for the aggregated grant, want yes", answer)
	}
}
