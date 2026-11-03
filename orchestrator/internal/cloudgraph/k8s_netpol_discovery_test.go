package cloudgraph

import (
	"context"
	"net/http"
	"testing"
)

const netpolPath = "/apis/networking.k8s.io/v1/networkpolicies"

// Discovery records NetworkPolicy objects and the pod and namespace labels the analysis needs.
func TestK8sDiscovery_CollectsNetworkPoliciesAndLabels(t *testing.T) {
	srv, _ := newK8sTestServer(t, serveRoutes(map[string]string{
		netpolPath:           `{"items":[{"metadata":{"name":"default-deny","namespace":"default"},"spec":{"podSelector":{},"policyTypes":["Ingress"]}}]}`,
		"/api/v1/pods":       `{"items":[{"metadata":{"name":"web-1","namespace":"default","labels":{"app":"web"}},"spec":{"serviceAccountName":"web"}}]}`,
		"/api/v1/namespaces": `{"items":[{"metadata":{"name":"default","labels":{"name":"default"}}}]}`,
	}))
	inv, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Complete {
		t.Fatalf("gaps=%v", rep.Gaps)
	}
	if !inv.NetworkPoliciesListed || len(inv.NetworkPolicies) != 1 || inv.NetworkPolicies[0].Name != "default-deny" {
		t.Fatalf("policies not collected: listed=%v policies=%+v", inv.NetworkPoliciesListed, inv.NetworkPolicies)
	}
	if got := inv.NetworkPolicies[0]; !got.selectsIngress() || len(got.Ingress) != 0 {
		t.Errorf("default-deny parsed wrong: %+v", got)
	}
	pod := findPodResource(inv, "web-1")
	if pod == nil || pod.Attributes["label.app"] != "web" {
		t.Errorf("pod labels not recorded: %+v", pod)
	}
	ns := findNamespaceResource(inv, "default")
	if ns == nil || ns.Attributes["label.name"] != "default" {
		t.Errorf("namespace labels not recorded: %+v", ns)
	}
}

// A forbidden NetworkPolicy list is a gap. It must never read as "no policies".
func TestK8sDiscovery_ForbiddenNetworkPolicyListIsNotListed(t *testing.T) {
	base := serveRoutes(nil)
	srv, _ := newK8sTestServer(t, func(w http.ResponseWriter, r *http.Request, rec *k8sRecorder) {
		if r.URL.Path == netpolPath {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		base(w, r, rec)
	})
	inv, rep, err := k8sClient(t, srv, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete {
		t.Error("a forbidden policy list must make discovery incomplete")
	}
	if inv.NetworkPoliciesListed {
		t.Error("a forbidden policy list must not be recorded as listed")
	}
	res, err := EvaluateK8sBoundaries(inv, rep, []K8sBoundary{
		boundary("default", map[string]string{"app": "web"}, "default", map[string]string{"app": "web"}, 80, "block"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Configured != NetpolConfiguredUnknown {
		t.Errorf("configured = %s, want UNKNOWN when the policy list is forbidden", res[0].Configured)
	}
}

func findPodResource(inv *K8sInventory, name string) *CloudResource {
	for _, r := range inv.Resources {
		if r.Kind == "k8s:pod" && r.DisplayName == name {
			return r
		}
	}
	return nil
}

func findNamespaceResource(inv *K8sInventory, name string) *CloudResource {
	for _, r := range inv.Resources {
		if r.Kind == "k8s:namespace" && r.DisplayName == name {
			return r
		}
	}
	return nil
}
