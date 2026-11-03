package cloudgraph

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type netpolTestPod struct {
	ns, name string
	labels   map[string]string
}

// netpolInventory builds an inventory from real NetworkPolicy JSON, so the parser is exercised too.
func netpolInventory(t *testing.T, policies []string, namespaces map[string]map[string]string, pods []netpolTestPod) (*K8sInventory, *K8sDiscoveryReport) {
	t.Helper()
	var raw []json.RawMessage
	for _, p := range policies {
		raw = append(raw, json.RawMessage(p))
	}
	parsed, gaps := parseK8sNetworkPolicies(raw)
	if len(gaps) > 0 {
		t.Fatalf("fixture policies did not parse: %v", gaps)
	}
	inv := &K8sInventory{NetworkPolicies: parsed, NetworkPoliciesListed: true}
	for name, labels := range namespaces {
		attrs := map[string]string{}
		for k, v := range labels {
			attrs["label."+k] = v
		}
		inv.Resources = append(inv.Resources, &CloudResource{Kind: "k8s:namespace", DisplayName: name, Attributes: attrs})
	}
	for _, p := range pods {
		attrs := map[string]string{"namespace": p.ns}
		for k, v := range p.labels {
			attrs["label."+k] = v
		}
		inv.Resources = append(inv.Resources, &CloudResource{Kind: "k8s:pod", DisplayName: p.name, Attributes: attrs})
	}
	rep := &K8sDiscoveryReport{Complete: true, ObservedAt: time.Now()}
	return inv, rep
}

func netpolLab(t *testing.T) (*K8sInventory, *K8sDiscoveryReport) {
	t.Helper()
	return netpolInventory(t, nil,
		map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}, "cache": {"name": "cache"}},
		[]netpolTestPod{
			{ns: "app", name: "web-0", labels: map[string]string{"app": "web"}},
			{ns: "db", name: "db-0", labels: map[string]string{"app": "db"}},
		})
}

func boundary(fromNS string, fromLabels map[string]string, toNS string, toLabels map[string]string, port int, expect string) K8sBoundary {
	return K8sBoundary{
		From:   K8sWorkloadSelector{Namespace: fromNS, PodLabels: fromLabels},
		To:     K8sWorkloadSelector{Namespace: toNS, PodLabels: toLabels},
		Port:   port,
		Expect: expect,
	}
}

var webLabels = map[string]string{"app": "web"}
var dbLabels = map[string]string{"app": "db"}

// evalOne runs one boundary and fails the test on error.
func evalOne(t *testing.T, inv *K8sInventory, rep *K8sDiscoveryReport, b K8sBoundary) K8sBoundaryResult {
	t.Helper()
	res, err := EvaluateK8sBoundaries(inv, rep, []K8sBoundary{b})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return res[0]
}

const allowWebToDB = `{"metadata":{"name":"allow-web","namespace":"db"},"spec":{"podSelector":{"matchLabels":{"app":"db"}},
	"policyTypes":["Ingress"],"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"name":"app"}},"podSelector":{"matchLabels":{"app":"web"}}}],
	"ports":[{"port":5432,"protocol":"TCP"}]}]}}`

const defaultDenyDB = `{"metadata":{"name":"default-deny","namespace":"db"},"spec":{"podSelector":{},"policyTypes":["Ingress"]}}`

func TestNetpol_NoPolicySelectsDestinationIsOpen(t *testing.T) {
	inv, rep := netpolLab(t)
	allow := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "allow"))
	if allow.Configured != NetpolConfiguredAllows || !allow.Matches {
		t.Fatalf("open ingress should configure ALLOWS and match expect allow: %+v", allow)
	}
	block := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "block"))
	if block.Configured != NetpolConfiguredAllows || block.Matches {
		t.Fatalf("open ingress must mismatch expect block, a gap: %+v", block)
	}
}

func TestNetpol_AllowPolicyPermitsSourceAndPort(t *testing.T) {
	inv, rep := netpolInventory(t, []string{allowWebToDB}, map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}},
		[]netpolTestPod{{ns: "app", name: "web-0", labels: webLabels}, {ns: "db", name: "db-0", labels: dbLabels}})
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "allow"))
	if res.Configured != NetpolConfiguredAllows || !res.Matches {
		t.Fatalf("permitted flow: %+v", res)
	}
	if len(res.IngressPolicies) != 1 || res.IngressPolicies[0] != "allow-web" {
		t.Errorf("ingress policies = %v, want [allow-web]", res.IngressPolicies)
	}
}

func TestNetpol_SamePolicyDifferentPortIsBlocked(t *testing.T) {
	inv, rep := netpolInventory(t, []string{allowWebToDB}, map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}},
		[]netpolTestPod{{ns: "app", name: "web-0", labels: webLabels}, {ns: "db", name: "db-0", labels: dbLabels}})
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 3306, "block"))
	if res.Configured != NetpolConfiguredBlocks || !res.Matches {
		t.Fatalf("port not permitted must block: %+v", res)
	}
}

func TestNetpol_DefaultDenyBlocks(t *testing.T) {
	inv, rep := netpolInventory(t, []string{defaultDenyDB}, map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}},
		[]netpolTestPod{{ns: "app", name: "web-0", labels: webLabels}, {ns: "db", name: "db-0", labels: dbLabels}})
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "block"))
	if res.Configured != NetpolConfiguredBlocks || !res.Matches {
		t.Fatalf("default deny: %+v", res)
	}
}

// The source's egress rules deny the destination even though the destination's ingress allows it.
func TestNetpol_EgressDenialOverridesIngressAllow(t *testing.T) {
	egressToCacheOnly := `{"metadata":{"name":"egress-cache-only","namespace":"app"},"spec":{"podSelector":{},"policyTypes":["Egress"],
		"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"name":"cache"}}}]}]}}`
	inv, rep := netpolInventory(t, []string{allowWebToDB, egressToCacheOnly},
		map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}, "cache": {"name": "cache"}},
		[]netpolTestPod{{ns: "app", name: "web-0", labels: webLabels}, {ns: "db", name: "db-0", labels: dbLabels}})
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "block"))
	if res.Configured != NetpolConfiguredBlocks || !res.Matches {
		t.Fatalf("egress must deny even when ingress allows: %+v", res)
	}
	if len(res.EgressPolicies) != 0 || len(res.IngressPolicies) != 1 {
		t.Errorf("policies: ingress=%v egress=%v", res.IngressPolicies, res.EgressPolicies)
	}
}

func TestNetpol_IPBlockPeerIsUnknown(t *testing.T) {
	ipBlock := `{"metadata":{"name":"from-cidr","namespace":"db"},"spec":{"podSelector":{},"ingress":[{"from":[{"ipBlock":{"cidr":"10.0.0.0/8"}}]}]}}`
	inv, rep := netpolInventory(t, []string{ipBlock}, map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}},
		[]netpolTestPod{{ns: "app", name: "web-0", labels: webLabels}, {ns: "db", name: "db-0", labels: dbLabels}})
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "allow"))
	if res.Configured != NetpolConfiguredUnknown || res.Matches {
		t.Fatalf("ipBlock peer must be UNKNOWN, not allowed: %+v", res)
	}
}

func TestNetpol_NamedPortIsUnknown(t *testing.T) {
	named := `{"metadata":{"name":"named","namespace":"db"},"spec":{"podSelector":{},"policyTypes":["Ingress"],
		"ingress":[{"ports":[{"port":"postgres"}]}]}}`
	inv, rep := netpolInventory(t, []string{named}, map[string]map[string]string{"db": {"name": "db"}},
		[]netpolTestPod{{ns: "db", name: "db-0", labels: dbLabels}, {ns: "db", name: "db-1", labels: dbLabels}})
	res := evalOne(t, inv, rep, boundary("db", dbLabels, "db", dbLabels, 5432, "allow"))
	if res.Configured != NetpolConfiguredUnknown {
		t.Fatalf("named port cannot be resolved here, want UNKNOWN: %+v", res)
	}
}

// A policy-selected pod that is reached only through a podSelector-only peer is scoped to the policy's namespace.
func TestNetpol_PodSelectorPeerIsScopedToPolicyNamespace(t *testing.T) {
	sameNS := `{"metadata":{"name":"same-ns","namespace":"db"},"spec":{"podSelector":{"matchLabels":{"app":"db"}},"policyTypes":["Ingress"],
		"ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"web"}}}]}]}}`
	inv, rep := netpolInventory(t, []string{sameNS}, map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}},
		[]netpolTestPod{{ns: "app", name: "web-0", labels: webLabels}, {ns: "db", name: "db-0", labels: dbLabels}})
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "block"))
	if res.Configured != NetpolConfiguredBlocks {
		t.Fatalf("a web pod in another namespace must not match a podSelector-only peer: %+v", res)
	}
}

func TestNetpol_ExternalSourceAgainstPodPeerIsBlocked(t *testing.T) {
	inv, rep := netpolInventory(t, []string{allowWebToDB}, map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}},
		[]netpolTestPod{{ns: "db", name: "db-0", labels: dbLabels}})
	ext := K8sBoundary{From: K8sWorkloadSelector{External: true}, To: K8sWorkloadSelector{Namespace: "db", PodLabels: dbLabels}, Port: 5432, Expect: "block"}
	res := evalOne(t, inv, rep, ext)
	if res.Configured != NetpolConfiguredBlocks || !res.Matches {
		t.Fatalf("external source must not satisfy a pod-selector peer: %+v", res)
	}
}

// Two pods match the source selector, and only one carries the label the policy requires. The pairs disagree,
// so the answer is UNKNOWN rather than either side.
func TestNetpol_DisagreeingPodsAreUnknown(t *testing.T) {
	front := `{"metadata":{"name":"front-only","namespace":"db"},"spec":{"podSelector":{"matchLabels":{"app":"db"}},"policyTypes":["Ingress"],
		"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"name":"app"}},"podSelector":{"matchLabels":{"tier":"front"}}}]}]}}`
	inv, rep := netpolInventory(t, []string{front}, map[string]map[string]string{"app": {"name": "app"}, "db": {"name": "db"}},
		[]netpolTestPod{
			{ns: "app", name: "web-a", labels: map[string]string{"app": "web", "tier": "front"}},
			{ns: "app", name: "web-b", labels: map[string]string{"app": "web"}},
			{ns: "db", name: "db-0", labels: dbLabels},
		})
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "allow"))
	if res.Configured != NetpolConfiguredUnknown {
		t.Fatalf("differing pod outcomes must be UNKNOWN: %+v", res)
	}
}

func TestNetpol_IncompletePolicyListIsUnknownEverywhere(t *testing.T) {
	inv, rep := netpolLab(t)
	inv.NetworkPoliciesListed = false
	res := evalOne(t, inv, rep, boundary("app", webLabels, "db", dbLabels, 5432, "allow"))
	if res.Configured != NetpolConfiguredUnknown {
		t.Fatalf("an incomplete NetworkPolicy list must not read as no policy: %+v", res)
	}
}

func TestNetpol_IncompleteDiscoveryMarksEveryResult(t *testing.T) {
	inv, rep := netpolLab(t)
	rep.Complete = false
	rep.Gaps = []string{"/api/v1/pods: stopped after 200 pages"}
	res, err := EvaluateK8sBoundaries(inv, rep, []K8sBoundary{
		boundary("app", webLabels, "db", dbLabels, 5432, "allow"),
		boundary("app", webLabels, "db", dbLabels, 3306, "block"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Complete {
			t.Errorf("result marked complete from incomplete discovery: %+v", r)
		}
	}
}

func TestNetpol_UnresolvableSelectorsAreUnknown(t *testing.T) {
	inv, rep := netpolLab(t)
	res := evalOne(t, inv, rep, boundary("app", map[string]string{"app": "absent"}, "db", dbLabels, 5432, "allow"))
	if res.Configured != NetpolConfiguredUnknown || !strings.Contains(strings.Join(res.Reasons, " "), "no collected pod") {
		t.Fatalf("a selector that matches no collected pod must be UNKNOWN with a reason: %+v", res)
	}
}

func TestNetpol_InvalidExpectationsRejectedBeforeEvaluation(t *testing.T) {
	inv, rep := netpolLab(t)
	bad := []K8sBoundary{
		boundary("app", webLabels, "db", dbLabels, 5432, "maybe"),
		boundary("app", webLabels, "db", dbLabels, 0, "allow"),
		boundary("app", webLabels, "db", dbLabels, 5432, "allow"),
	}
	bad[2].Protocol = "ICMP"
	for i, b := range bad {
		if _, err := EvaluateK8sBoundaries(inv, rep, []K8sBoundary{b}); err == nil {
			t.Errorf("case %d accepted an invalid expectation", i)
		}
	}
	external := K8sBoundary{From: K8sWorkloadSelector{Namespace: "app"}, To: K8sWorkloadSelector{External: true}, Port: 443, Expect: "block"}
	if _, err := EvaluateK8sBoundaries(inv, rep, []K8sBoundary{external}); err == nil {
		t.Error("an external destination must be rejected")
	}
}

func TestNetpol_UnsupportedSelectorOperatorIsAGap(t *testing.T) {
	bad := `{"metadata":{"name":"odd","namespace":"db"},"spec":{"podSelector":{"matchExpressions":[{"key":"app","operator":"Equals","values":["db"]}]}}}`
	_, gaps := parseK8sNetworkPolicies([]json.RawMessage{json.RawMessage(bad)})
	if len(gaps) == 0 {
		t.Fatal("an unknown selector operator must be reported as a gap, not skipped silently")
	}
}
