package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/cloudgraph"
)

// k8sDiscoveryRunner runs the read-only Kubernetes analysis. It reads the token file on every run, so a rotated token
// takes effect without restarting the server. The token is never logged.
type k8sDiscoveryRunner struct {
	server  string
	cluster string
	tokenFn string
	caFn    string
}

func (r k8sDiscoveryRunner) Run(ctx context.Context) (cloudgraph.K8sAnalysis, error) {
	token, err := os.ReadFile(r.tokenFn)
	if err != nil {
		return cloudgraph.K8sAnalysis{}, err
	}
	ca, err := os.ReadFile(r.caFn)
	if err != nil {
		return cloudgraph.K8sAnalysis{}, err
	}
	return cloudgraph.RunK8sAnalysis(ctx, cloudgraph.K8sDiscoveryConfig{
		ClusterName: r.cluster,
		APIServer:   r.server,
		Token:       strings.TrimSpace(string(token)),
		CAPEM:       ca,
	})
}

// buildK8sAnalysisRunner returns the discovery runner, or nil (feature off) when any setting is missing.
func buildK8sAnalysisRunner() api.K8sAnalysisRunner {
	server := strings.TrimSpace(os.Getenv("KUBE_DISCOVERY_API"))
	if server == "" {
		return nil
	}
	cluster := strings.TrimSpace(os.Getenv("KUBE_DISCOVERY_CLUSTER"))
	tokenFn := strings.TrimSpace(os.Getenv("KUBE_DISCOVERY_TOKEN_FILE"))
	caFn := strings.TrimSpace(os.Getenv("KUBE_DISCOVERY_CA_FILE"))
	if cluster == "" || tokenFn == "" || caFn == "" {
		log.Printf("[k8s-discovery] disabled: KUBE_DISCOVERY_CLUSTER, KUBE_DISCOVERY_TOKEN_FILE and KUBE_DISCOVERY_CA_FILE are all required")
		return nil
	}
	if _, err := os.Stat(tokenFn); err != nil {
		log.Printf("[k8s-discovery] disabled: cannot read KUBE_DISCOVERY_TOKEN_FILE: %v", err)
		return nil
	}
	log.Printf("[k8s-discovery] read-only analysis enabled for cluster %q", cluster)
	return k8sDiscoveryRunner{server: server, cluster: cluster, tokenFn: tokenFn, caFn: caFn}
}
