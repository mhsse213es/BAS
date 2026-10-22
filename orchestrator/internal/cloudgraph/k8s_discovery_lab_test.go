package cloudgraph

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestK8sDiscovery_LiveLab runs discovery against a real cluster. It is skipped unless the lab is
// configured, so the normal test run never needs a cluster:
//
//	KUBE_LAB_API      https URL of the API server (e.g. https://127.0.0.1:61567)
//	KUBE_LAB_TOKEN_FILE  file holding a read-only service account token (never print it)
//	KUBE_LAB_CA_FILE  file holding the cluster CA certificate (PEM)
//
// The lab cluster is kind-bas-lab. The read-only account is kube-system/bas-discovery.
func TestK8sDiscovery_LiveLab(t *testing.T) {
	api := os.Getenv("KUBE_LAB_API")
	tokenFile := os.Getenv("KUBE_LAB_TOKEN_FILE")
	caFile := os.Getenv("KUBE_LAB_CA_FILE")
	if api == "" || tokenFile == "" || caFile == "" {
		t.Skip("set KUBE_LAB_API, KUBE_LAB_TOKEN_FILE and KUBE_LAB_CA_FILE to run against the lab cluster")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	c, err := NewK8sDiscoveryClient(K8sDiscoveryConfig{
		ClusterName: "kind-bas-lab",
		APIServer:   api,
		Token:       token,
		CAPEM:       ca,
	})
	if err != nil {
		t.Fatal(err)
	}

	inv, rep, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	t.Logf("counts=%v complete=%v gaps=%v", rep.Counts, rep.Complete, rep.Gaps)
	if !rep.Complete {
		t.Fatalf("the lab inventory must be complete with the read-only account; gaps=%v", rep.Gaps)
	}
	for _, id := range []string{
		"k8s://kind-bas-lab/default/pod/web-1",
		"k8s://kind-bas-lab/default/role/reader",
		"k8s://kind-bas-lab/_cluster/clusterrole/cluster-admin",
	} {
		if findRes(inv.Resources, id) == nil {
			t.Fatalf("lab object missing from inventory: %s", id)
		}
	}
	if findIdent(inv.Identities, "k8s://kind-bas-lab/default/serviceaccount/web") == nil {
		t.Fatal("lab service account web missing from inventory")
	}
	found := false
	for _, p := range inv.Permissions {
		if p.Source != nil && p.Source.CanonicalID == "k8s://kind-bas-lab/default/serviceaccount/web" && p.Target != nil && p.Target.CanonicalID == "k8s://kind-bas-lab/default/role/reader" {
			found = true
		}
	}
	if !found {
		t.Fatal("the web -> reader binding is missing from the permissions")
	}
}

// TestK8sDiscovery_LiveLab_ReadOnlyCredentialCannotWrite proves the credential itself cannot change the
// cluster: a create request with the same token must be refused.
func TestK8sDiscovery_LiveLab_ReadOnlyCredentialCannotWrite(t *testing.T) {
	api := os.Getenv("KUBE_LAB_API")
	tokenFile := os.Getenv("KUBE_LAB_TOKEN_FILE")
	caFile := os.Getenv("KUBE_LAB_CA_FILE")
	if api == "" || tokenFile == "" || caFile == "" {
		t.Skip("lab not configured")
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
	body := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"should-not-exist","namespace":"default"},"spec":{"containers":[{"name":"x","image":"registry.k8s.io/pause:3.9"}]}}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.cfg.APIServer+"/api/v1/namespaces/default/pods", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("create with the read-only credential returned HTTP %d, want 403", resp.StatusCode)
	}
}
