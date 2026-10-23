package cloudgraph

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestK8sAnalysis_LiveLab runs the full read-only analysis against the lab cluster and checks it completes. It is
// skipped unless the lab is configured (the same variables as TestK8sDiscovery_LiveLab). It logs counts only, never
// the token.
func TestK8sAnalysis_LiveLab(t *testing.T) {
	api := os.Getenv("KUBE_LAB_API")
	tokenFile := os.Getenv("KUBE_LAB_TOKEN_FILE")
	caFile := os.Getenv("KUBE_LAB_CA_FILE")
	if api == "" || tokenFile == "" || caFile == "" {
		t.Skip("set KUBE_LAB_API, KUBE_LAB_TOKEN_FILE and KUBE_LAB_CA_FILE to run against the lab cluster")
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunK8sAnalysis(context.Background(), K8sDiscoveryConfig{
		ClusterName: labClusterName(),
		APIServer:   api,
		Token:       strings.TrimSpace(string(token)),
		CAPEM:       ca,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Logf("discovery reported gaps: %v", res.Gaps)
	}
	t.Logf("lab analysis: complete=%v wildcards=%d breadth=%d crossNamespace=%d workloadCreation=%d escalation=%d attackPaths=%d podConfig=%d tokenExposure=%d",
		res.Complete, len(res.Wildcards), len(res.Breadth), len(res.CrossNamespace), len(res.WorkloadCreation),
		len(res.Escalation), len(res.AttackPaths), len(res.PodConfig), len(res.TokenExposure))
}
