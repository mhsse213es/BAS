package cloudgraph

import (
	"context"
	"time"
)

// K8sAnalysis is one read-only report over a discovered cluster: every configured-permission and configured-state
// analysis, plus the discovery completeness. Every field is configured state. None of it proves that an attack works.
type K8sAnalysis struct {
	Cluster    string         `json:"cluster"`
	ObservedAt time.Time      `json:"observedAt"`
	Complete   bool           `json:"complete"`
	Gaps       []string       `json:"gaps"`
	Counts     map[string]int `json:"counts"`

	Wildcards        []K8sWildcardFinding         `json:"wildcards"`
	Breadth          []K8sServiceAccountBreadth   `json:"breadth"`
	CrossNamespace   []K8sCrossNamespaceFinding   `json:"crossNamespace"`
	WorkloadCreation []K8sWorkloadCreationFinding `json:"workloadCreation"`
	Escalation       []K8sEscalationFinding       `json:"escalation"`
	AttackPaths      []K8sAttackPath              `json:"attackPaths"`
	PodConfig        []K8sPodConfigFinding        `json:"podConfig"`
	TokenExposure    []K8sTokenExposureFinding    `json:"tokenExposure"`
}

// BuildK8sAnalysis runs every analysis over one discovered inventory.
func BuildK8sAnalysis(inv *K8sInventory, rep *K8sDiscoveryReport) K8sAnalysis {
	return K8sAnalysis{
		Cluster:          rep.ClusterName,
		ObservedAt:       rep.ObservedAt,
		Complete:         rep.Complete,
		Gaps:             nonNil(rep.Gaps),
		Counts:           rep.Counts,
		Wildcards:        K8sWildcardFindings(inv, rep),
		Breadth:          K8sServiceAccountBreadthFindings(inv, rep),
		CrossNamespace:   K8sCrossNamespaceFindings(inv, rep),
		WorkloadCreation: K8sWorkloadCreationFindings(inv, rep),
		Escalation:       K8sEscalationFindings(inv, rep),
		AttackPaths:      K8sAttackPaths(inv, rep),
		PodConfig:        K8sPodConfigFindings(inv, rep),
		TokenExposure:    K8sTokenExposureFindings(inv, rep),
	}
}

// RunK8sAnalysis discovers the cluster read-only and builds the report. The token is supplied per call, so a caller
// can rotate it without restarting.
func RunK8sAnalysis(ctx context.Context, cfg K8sDiscoveryConfig) (K8sAnalysis, error) {
	c, err := NewK8sDiscoveryClient(cfg)
	if err != nil {
		return K8sAnalysis{}, err
	}
	inv, rep, err := c.Discover(ctx)
	if err != nil {
		return K8sAnalysis{}, err
	}
	return BuildK8sAnalysis(inv, rep), nil
}

// nonNil returns an empty slice rather than nil, so JSON shows [] instead of null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
