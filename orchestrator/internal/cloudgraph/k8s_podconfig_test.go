package cloudgraph

import (
	"slices"
	"testing"
)

func podConfigFor(got []K8sPodConfigFinding, workload string) (K8sPodConfigFinding, bool) {
	for _, f := range got {
		if f.Workload == "k8s://kind-bas-lab/default/pod/"+workload {
			return f, true
		}
	}
	return K8sPodConfigFinding{}, false
}

// TestPodConfig_ReportsEachDangerousSetting checks each host namespace, privileged container and hostPath volume is
// reported as its own reason.
func TestPodConfig_ReportsEachDangerousSetting(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{"/api/v1/pods": podSpecFixture})
	f, ok := podConfigFor(K8sPodConfigFindings(inv, rep), "risky")
	if !ok {
		t.Fatal("risky pod was not reported")
	}
	for _, want := range []string{"hostPID", "hostNetwork", "privileged container: c1", "hostPath: /var/run"} {
		if !slices.Contains(f.Reasons, want) {
			t.Fatalf("reasons = %v, want %q", f.Reasons, want)
		}
	}
	if slices.Contains(f.Reasons, "hostIPC") {
		t.Fatalf("hostIPC is not set on the pod but was reported: %v", f.Reasons)
	}
}

// TestPodConfig_PlainPodIsNotReported checks a pod with no dangerous setting produces no finding.
func TestPodConfig_PlainPodIsNotReported(t *testing.T) {
	inv, rep := analysisFor(t, map[string]string{"/api/v1/pods": podSpecFixture})
	if _, ok := podConfigFor(K8sPodConfigFindings(inv, rep), "plain"); ok {
		t.Fatal("a pod with no host access or privileged container must not be reported")
	}
}
