package cloudgraph

import (
	"encoding/json"
	"testing"
)

// TestK8sAnalysis_BuildsEveryAnalysisAndSerialises checks one report carries the cluster, the discovery completeness,
// and every analysis, and that it marshals to JSON without error.
func TestK8sAnalysis_BuildsEveryAnalysisAndSerialises(t *testing.T) {
	inv, rep := analysisFor(t, nil)
	got := BuildK8sAnalysis(inv, rep)
	if got.Cluster != rep.ClusterName || got.Cluster == "" {
		t.Fatalf("cluster = %q, want %q", got.Cluster, rep.ClusterName)
	}
	if got.Complete != rep.Complete {
		t.Fatalf("complete = %v, want %v", got.Complete, rep.Complete)
	}
	if got.Counts == nil || got.Counts["pods"] == 0 {
		t.Fatalf("counts = %v, want pod counts from discovery", got.Counts)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("report does not marshal: %v", err)
	}
}
