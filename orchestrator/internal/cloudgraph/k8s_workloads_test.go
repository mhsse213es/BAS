package cloudgraph

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

const testWeb = "k8s://kind-bas-lab/default/deployment/web"

func TestK8sWorkloads_PodResolvesThroughReplicaSetToDeployment(t *testing.T) {
	inv, rep := analysisFor(t, nil)
	if !rep.Complete {
		t.Fatalf("fixture discovery should be complete, gaps=%v", rep.Gaps)
	}
	pod := findRes(inv.Resources, testWebPod)
	if pod == nil {
		t.Fatal("pod missing")
	}
	if got := pod.Attributes["workload"]; got != testWeb {
		t.Fatalf("pod workload = %q, want %q", got, testWeb)
	}
	if got := pod.Attributes["workloadKind"]; got != "k8s:deployment" {
		t.Fatalf("workloadKind = %q, want k8s:deployment", got)
	}
	if findRes(inv.Resources, testWeb) == nil {
		t.Fatal("the Deployment must be in the inventory as a resource")
	}
}

func TestK8sWorkloads_UnlistedOwnerIsAGapNotAWorkload(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/apps/v1/replicasets": `{"items":[]}`,
	})
	if rep.Complete {
		t.Fatal("a pod whose ReplicaSet was not listed must make discovery incomplete")
	}
	if !containsGap(rep.Gaps, "web-7d") {
		t.Fatalf("gaps %v do not name the unlisted owner web-7d", rep.Gaps)
	}
	if got := findRes(inv.Resources, testWebPod).Attributes["workload"]; got != "" {
		t.Fatalf("an unresolved pod must not be assigned a workload, got %q", got)
	}
}

func TestK8sWorkloads_StandalonePodIsItsOwnWorkload(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/api/v1/pods": `{"items":[{"metadata":{"name":"solo","namespace":"default"},"spec":{"serviceAccountName":"web"}}]}`,
	})
	if !rep.Complete {
		t.Fatalf("gaps=%v", rep.Gaps)
	}
	solo := "k8s://kind-bas-lab/default/pod/solo"
	pod := findRes(inv.Resources, solo)
	if pod == nil || pod.Attributes["workload"] != solo || pod.Attributes["workloadKind"] != "k8s:pod" {
		t.Fatalf("a pod with no owner must be its own workload; got %+v", pod)
	}
}

func TestK8sPrivilegeFindings_CarryTheWorkload(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/rbac.authorization.k8s.io/v1/roles": `{"items":[{"metadata":{"name":"reader","namespace":"default"},"rules":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]}]}`,
	})
	var found bool
	for _, f := range K8sPrivilegeFindings(inv, rep) {
		if f.Capability == "get-secrets" {
			found = true
			if f.Owner != testWeb {
				t.Fatalf("finding owner = %q, want the Deployment %q", f.Owner, testWeb)
			}
			if !strings.HasPrefix(f.Workload, "k8s://kind-bas-lab/default/pod/") {
				t.Fatalf("finding workload should be the pod, got %q", f.Workload)
			}
		}
	}
	if !found {
		t.Fatal("expected a get-secrets finding")
	}
}

// Static pods (control-plane components) are owned by their Node, which is not a workload. They must be
// their own workload and must not produce a gap.
func TestK8sWorkloads_StaticPodOwnedByNodeIsStandalone(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/api/v1/pods": `{"items":[{"metadata":{"name":"etcd-x","namespace":"default","ownerReferences":[{"kind":"Node","name":"bas-lab-control-plane"}]},"spec":{"serviceAccountName":"web"}}]}`,
	})
	if !rep.Complete {
		t.Fatalf("a Node-owned static pod must not make discovery incomplete; gaps=%v", rep.Gaps)
	}
	pod := "k8s://kind-bas-lab/default/pod/etcd-x"
	if got := findRes(inv.Resources, pod).Attributes["workload"]; got != pod {
		t.Fatalf("static pod workload = %q, want itself", got)
	}
}

// K3s's Helm controller owns pods through HelmChart custom resources. A HelmChart owner that was listed
// resolves to that HelmChart, and a cluster without the CRD (404) is complete, not a gap.
func TestK8sWorkloads_HelmChartOwnedPodResolvesToHelmChart(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/helm.cattle.io/v1/helmcharts": `{"items":[{"metadata":{"name":"traefik","namespace":"kube-system"}}]}`,
		"/api/v1/pods":                       `{"items":[{"metadata":{"name":"helm-install-traefik-x","namespace":"kube-system","ownerReferences":[{"kind":"HelmChart","name":"traefik"}]},"spec":{"serviceAccountName":"web"}}]}`,
	})
	if !rep.Complete {
		t.Fatalf("gaps=%v", rep.Gaps)
	}
	pod := findRes(inv.Resources, "k8s://kind-bas-lab/kube-system/pod/helm-install-traefik-x")
	if pod == nil || pod.Attributes["workload"] != "k8s://kind-bas-lab/kube-system/helmchart/traefik" {
		t.Fatalf("pod workload = %+v, want the HelmChart", pod)
	}
}

func TestK8sWorkloads_MissingHelmChartCRDIsNotAGap(t *testing.T) {
	// The fixture serves no helmcharts route, so the list returns 404: the CRD is not installed.
	_, rep := analysisFor(t, nil)
	if !rep.Complete {
		t.Fatalf("a cluster without the HelmChart CRD must not be incomplete; gaps=%v", rep.Gaps)
	}
}

// An unlisted Deployment makes the pod's workload unknown. The gap is reported, no workload is assigned, and
// access that depends on the incomplete policy is unknown, not denied.
func TestK8sWorkloads_UnlistedDeploymentLeavesChainUnresolved(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{
		"/apis/apps/v1/deployments": `{"items":[]}`,
	})
	if rep.Complete {
		t.Fatal("a ReplicaSet owned by an unlisted Deployment must make discovery incomplete")
	}
	if !containsGap(rep.Gaps, "owner Deployment web was not listed") {
		t.Fatalf("gaps %v do not name the unlisted Deployment", rep.Gaps)
	}
	if got := findRes(inv.Resources, testWebPod).Attributes["workload"]; got != "" {
		t.Fatalf("an unresolved chain must not yield a workload, got %q", got)
	}
	// The Deployment's absence hides nothing we can claim. Access the policy does not show is unknown.
	got := AnalyseK8sAccess(inv, rep, K8sAccessQuery{Subject: testWebSA, Namespace: "default", Request: RBACRequest{Resource: "secrets", Verb: "get"}})
	if got.Decision != RBACUnknown {
		t.Fatalf("access under an incomplete chain = %s, want unknown", got.Decision)
	}
}

// A chain deeper than the four hops discovery follows is reported as a gap, never as a workload.
func TestK8sWorkloads_OwnerChainTooDeepIsAGap(t *testing.T) {
	// r1 -> r2 -> r3 -> r4 -> r5 -> (no owner): five hops from the pod, one more than the limit.
	inv, rep := analysisFor(t, map[string]string{
		"/apis/apps/v1/replicasets": `{"items":[` +
			`{"metadata":{"name":"web-7d","namespace":"default","ownerReferences":[{"kind":"ReplicaSet","name":"r2"}]}},` +
			`{"metadata":{"name":"r2","namespace":"default","ownerReferences":[{"kind":"ReplicaSet","name":"r3"}]}},` +
			`{"metadata":{"name":"r3","namespace":"default","ownerReferences":[{"kind":"ReplicaSet","name":"r4"}]}},` +
			`{"metadata":{"name":"r4","namespace":"default","ownerReferences":[{"kind":"ReplicaSet","name":"r5"}]}},` +
			`{"metadata":{"name":"r5","namespace":"default"}}]}`,
		"/apis/apps/v1/deployments": `{"items":[]}`,
	})
	if rep.Complete {
		t.Fatal("an owner chain deeper than the limit must make discovery incomplete")
	}
	if !containsGap(rep.Gaps, "deeper than 4 levels") {
		t.Fatalf("gaps %v do not report the depth limit", rep.Gaps)
	}
	if got := findRes(inv.Resources, testWebPod).Attributes["workload"]; got != "" {
		t.Fatalf("a chain too deep to resolve must not yield a workload, got %q", got)
	}
}

// A forbidden workload list (here Deployments) is a gap, and the report names the list, so the reason is visible.
func TestK8sWorkloads_ForbiddenWorkloadListIsReported(t *testing.T) {
	serve := serveRoutes(nil)
	srv, _ := newK8sTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *k8sRecorder) {
		if r.URL.Path == "/apis/apps/v1/deployments" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		serve(w, r, rec)
	})
	_, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete {
		t.Fatal("a forbidden Deployment list must make discovery incomplete")
	}
	if !containsGap(rep.Gaps, "forbidden: /apis/apps/v1/deployments") {
		t.Fatalf("gaps %v do not name the forbidden list", rep.Gaps)
	}
}
