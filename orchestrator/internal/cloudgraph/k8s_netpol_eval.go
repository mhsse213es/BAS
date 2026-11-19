package cloudgraph

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Scenario 9: network-policy boundary analysis. For each boundary the owner expects to be
// allowed or blocked, this reports what the collected NetworkPolicy objects configure. It makes
// no connection, writes nothing, and never judges what traffic should be allowed.
//
// Answers are tri-state internally. "maybe" is the honest answer whenever the inputs cannot
// settle the question (an ipBlock peer, a named port, an unresolved selector). A maybe is
// reported as UNKNOWN, never as blocked or allowed.

const (
	NetpolConfiguredBlocks  = "CONFIGURED_BLOCKS"
	NetpolConfiguredAllows  = "CONFIGURED_ALLOWS"
	NetpolConfiguredUnknown = "UNKNOWN"
)

type netpolTri int

const (
	triNo netpolTri = iota
	triMaybe
	triYes
)

func triAnd(a, b netpolTri) netpolTri {
	if a < b {
		return a
	}
	return b
}

func triOr(a, b netpolTri) netpolTri {
	if a > b {
		return a
	}
	return b
}

// K8sWorkloadSelector names a flow end: an external source, or pods in a namespace whose labels
// contain every key/value in PodLabels.
type K8sWorkloadSelector struct {
	External  bool
	Namespace string
	PodLabels map[string]string
}

// K8sBoundary is one owner expectation. Port is required; Protocol defaults to TCP.
type K8sBoundary struct {
	Name     string
	From     K8sWorkloadSelector
	To       K8sWorkloadSelector
	Port     int
	Protocol string
	Expect   string // "allow" or "block"
}

// K8sBoundaryResult is the analysis of one boundary.
type K8sBoundaryResult struct {
	Name            string   `json:"name"`
	From            string   `json:"from"`
	To              string   `json:"to"`
	Port            int      `json:"port"`
	Protocol        string   `json:"protocol"`
	Expect          string   `json:"expect"`
	Configured      string   `json:"configured"`
	Matches         bool     `json:"matches"`
	IngressPolicies []string `json:"ingressPolicies"`
	EgressPolicies  []string `json:"egressPolicies"`
	Reasons         []string `json:"reasons"`
	// Complete is false when discovery was incomplete. An incomplete NetworkPolicy list makes
	// Configured UNKNOWN for every boundary.
	Complete bool `json:"complete"`
}

type netpolPod struct {
	name      string
	namespace string
	labels    map[string]string
}

type netpolEndpoint struct {
	external  bool
	namespace string
	labels    map[string]string
	nsLabels  map[string]string
	nsKnown   bool
}

// EvaluateK8sBoundaries evaluates each boundary against the inventory. It returns an error for
// an invalid expectation, and evaluates nothing in that case.
func EvaluateK8sBoundaries(inv *K8sInventory, rep *K8sDiscoveryReport, boundaries []K8sBoundary) ([]K8sBoundaryResult, error) {
	if inv == nil {
		return nil, errors.New("network-policy analysis: no inventory")
	}
	for i, b := range boundaries {
		if err := validateBoundary(b); err != nil {
			return nil, fmt.Errorf("boundary %d: %w", i+1, err)
		}
	}
	complete := rep != nil && rep.Complete && inv.NetworkPoliciesListed

	pods, nsLabels := indexK8sPodsAndNamespaces(inv)
	out := make([]K8sBoundaryResult, 0, len(boundaries))
	for _, b := range boundaries {
		out = append(out, evaluateBoundary(inv, b, pods, nsLabels, complete))
	}
	return out, nil
}

func validateBoundary(b K8sBoundary) error {
	if b.Expect != "allow" && b.Expect != "block" {
		return fmt.Errorf("expect must be \"allow\" or \"block\", got %q", b.Expect)
	}
	if b.To.External {
		return errors.New("the destination cannot be external")
	}
	if b.To.Namespace == "" {
		return errors.New("the destination needs a namespace")
	}
	if !b.From.External && b.From.Namespace == "" {
		return errors.New("the source needs a namespace or must be external")
	}
	if b.Port < 1 || b.Port > 65535 {
		return fmt.Errorf("port %d is out of range", b.Port)
	}
	switch protocolOf(b.Protocol) {
	case "TCP", "UDP", "SCTP":
	default:
		return fmt.Errorf("protocol %q is not TCP, UDP or SCTP", b.Protocol)
	}
	return nil
}

func protocolOf(p string) string {
	if p == "" {
		return "TCP"
	}
	return strings.ToUpper(p)
}

func indexK8sPodsAndNamespaces(inv *K8sInventory) ([]netpolPod, map[string]map[string]string) {
	var pods []netpolPod
	nsLabels := map[string]map[string]string{}
	for _, r := range inv.Resources {
		switch r.Kind {
		case "k8s:pod":
			pods = append(pods, netpolPod{name: r.DisplayName, namespace: r.Attributes["namespace"], labels: labelsFromAttrs(r.Attributes)})
		case "k8s:namespace":
			nsLabels[r.DisplayName] = labelsFromAttrs(r.Attributes)
		}
	}
	return pods, nsLabels
}

// resolvePods returns the collected pods a flow end names.
func resolvePods(pods []netpolPod, sel K8sWorkloadSelector) []netpolPod {
	var out []netpolPod
	for _, p := range pods {
		if p.namespace != sel.Namespace {
			continue
		}
		match := true
		for k, v := range sel.PodLabels {
			if got, ok := p.labels[k]; !ok || got != v {
				match = false
				break
			}
		}
		if match {
			out = append(out, p)
		}
	}
	return out
}

func evaluateBoundary(inv *K8sInventory, b K8sBoundary, pods []netpolPod, nsLabels map[string]map[string]string, complete bool) K8sBoundaryResult {
	res := K8sBoundaryResult{
		Name: b.Name,
		From: describeEnd(b.From), To: describeEnd(b.To), Port: b.Port, Protocol: protocolOf(b.Protocol),
		Expect: b.Expect, Complete: complete,
	}
	if !inv.NetworkPoliciesListed {
		res.Configured = NetpolConfiguredUnknown
		res.Reasons = []string{"the NetworkPolicy list is incomplete; no boundary can be settled"}
		return res
	}

	toPods := resolvePods(pods, b.To)
	if len(toPods) == 0 {
		res.Configured = NetpolConfiguredUnknown
		res.Reasons = []string{fmt.Sprintf("no collected pod matches the destination %s", res.To)}
		return res
	}
	var fromEnds []netpolEndpoint
	if b.From.External {
		fromEnds = []netpolEndpoint{{external: true}}
	} else {
		fromPods := resolvePods(pods, b.From)
		if len(fromPods) == 0 {
			res.Configured = NetpolConfiguredUnknown
			res.Reasons = []string{fmt.Sprintf("no collected pod matches the source %s", res.From)}
			return res
		}
		for _, p := range fromPods {
			fromEnds = append(fromEnds, endpointOf(p, nsLabels))
		}
	}

	// Each source/destination pod pair is evaluated. If the pairs disagree, the boundary is unknown.
	var verdicts []pairVerdict
	for _, f := range fromEnds {
		for _, tp := range toPods {
			verdicts = append(verdicts, evaluatePair(inv, f, endpointOf(tp, nsLabels), b.Port, protocolOf(b.Protocol)))
		}
	}
	res.Configured, res.Reasons, res.IngressPolicies, res.EgressPolicies = combineVerdicts(verdicts)
	res.Matches = (b.Expect == "allow" && res.Configured == NetpolConfiguredAllows) ||
		(b.Expect == "block" && res.Configured == NetpolConfiguredBlocks)
	return res
}

type pairVerdict struct {
	configured string
	reasons    []string
	ingress    []string
	egress     []string
}

func combineVerdicts(vs []pairVerdict) (string, []string, []string, []string) {
	var ingress, egress, reasons []string
	first := vs[0].configured
	same := true
	for _, v := range vs {
		if v.configured != first {
			same = false
		}
		ingress = append(ingress, v.ingress...)
		egress = append(egress, v.egress...)
		reasons = append(reasons, v.reasons...)
	}
	configured := first
	if !same {
		configured = NetpolConfiguredUnknown
		reasons = append([]string{"the selectors resolve to pods whose policy outcomes differ"}, reasons...)
	}
	return configured, sortedUnique(reasons), sortedUnique(ingress), sortedUnique(egress)
}

func describeEnd(s K8sWorkloadSelector) string {
	if s.External {
		return "external"
	}
	keys := make([]string, 0, len(s.PodLabels))
	for k, v := range s.PodLabels {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return s.Namespace + "/*"
	}
	return s.Namespace + "/" + strings.Join(keys, ",")
}

func endpointOf(p netpolPod, nsLabels map[string]map[string]string) netpolEndpoint {
	nl, ok := nsLabels[p.namespace]
	return netpolEndpoint{namespace: p.namespace, labels: p.labels, nsLabels: nl, nsKnown: ok}
}

// evaluatePair checks one flow from f to t on both sides. A denial on either side is definitive.
func evaluatePair(inv *K8sInventory, f, t netpolEndpoint, port int, proto string) pairVerdict {
	var v pairVerdict
	ingState, ingPolicies, ingReasons := evalSide(inv, "Ingress", t, f, port, proto)
	v.ingress = ingPolicies
	v.reasons = append(v.reasons, ingReasons...)

	egState := netpolTri(triYes)
	if !f.external {
		var egPolicies, egReasons []string
		egState, egPolicies, egReasons = evalSide(inv, "Egress", f, t, port, proto)
		v.egress = egPolicies
		v.reasons = append(v.reasons, egReasons...)
	}

	switch {
	case ingState == triNo || egState == triNo:
		v.configured = NetpolConfiguredBlocks
	case ingState == triMaybe || egState == triMaybe:
		v.configured = NetpolConfiguredUnknown
	default:
		v.configured = NetpolConfiguredAllows
	}
	return v
}

// evalSide decides one direction of a flow. For Ingress, the isolated endpoint is the destination
// and the peer is the source. For Egress, the isolated endpoint is the source and the peer is the
// destination.
func evalSide(inv *K8sInventory, dir string, isolated, peer netpolEndpoint, port int, proto string) (netpolTri, []string, []string) {
	var selecting []K8sNetworkPolicy
	for _, p := range inv.NetworkPolicies {
		if p.Namespace != isolated.namespace {
			continue
		}
		if dir == "Ingress" && !p.selectsIngress() {
			continue
		}
		if dir == "Egress" && !p.selectsEgress() {
			continue
		}
		if !p.PodSelector.Matches(isolated.labels) {
			continue
		}
		selecting = append(selecting, p)
	}
	if len(selecting) == 0 {
		return triYes, nil, []string{fmt.Sprintf("no %s policy selects %s; %s open", strings.ToLower(dir), isolated.label(), strings.ToLower(dir))}
	}

	best := triNo
	var allowing, names []string
	for _, p := range selecting {
		names = append(names, p.Name)
		rules := p.Ingress
		if dir == "Egress" {
			rules = p.Egress
		}
		policyBest := triNo
		for _, r := range rules {
			t := triAnd(peerTri(r.Peers, p.Namespace, peer), portTri(r.Ports, port, proto))
			policyBest = triOr(policyBest, t)
		}
		if policyBest == triYes {
			allowing = append(allowing, p.Name)
		}
		best = triOr(best, policyBest)
	}
	sort.Strings(names)
	switch best {
	case triYes:
		return triYes, allowing, []string{fmt.Sprintf("%s policy %s permits the flow", strings.ToLower(dir), strings.Join(sortedUnique(allowing), ", "))}
	case triMaybe:
		return triMaybe, nil, []string{fmt.Sprintf("%s policies %s cannot be settled from the collected inputs (ipBlock peer or named port)", strings.ToLower(dir), strings.Join(names, ", "))}
	default:
		return triNo, nil, []string{fmt.Sprintf("%s policies %s select %s and none permits the flow", strings.ToLower(dir), strings.Join(names, ", "), isolated.label())}
	}
}

func (e netpolEndpoint) label() string {
	if e.external {
		return "external source"
	}
	return "the " + e.namespace + " pod"
}

// peerTri decides whether a peer list admits the other endpoint. An empty list admits everything,
// external sources included. policyNS is the namespace the policy lives in, which a peer without a
// namespaceSelector is scoped to.
func peerTri(peers []K8sNetPolPeer, policyNS string, other netpolEndpoint) netpolTri {
	if len(peers) == 0 {
		return triYes
	}
	best := triNo
	for _, pr := range peers {
		best = triOr(best, onePeer(pr, policyNS, other))
	}
	return best
}

func onePeer(pr K8sNetPolPeer, policyNS string, other netpolEndpoint) netpolTri {
	if pr.IPBlock {
		// Pod IPs are not collected, so an ipBlock cannot be checked against this endpoint.
		return triMaybe
	}
	if other.external {
		// Pod and namespace selectors never match an external source.
		return triNo
	}
	nsT := triYes
	switch {
	case pr.NamespaceSelector != nil:
		if !other.nsKnown {
			nsT = triMaybe
		} else if !pr.NamespaceSelector.Matches(other.nsLabels) {
			nsT = triNo
		}
	case pr.PodSelector != nil:
		if other.namespace != policyNS {
			nsT = triNo
		}
	default:
		return triMaybe
	}
	podT := triYes
	if pr.PodSelector != nil && !pr.PodSelector.Matches(other.labels) {
		podT = triNo
	}
	return triAnd(nsT, podT)
}

// portTri decides whether a rule's ports admit the flow. An empty list admits every port.
func portTri(ports []K8sNetPolPort, port int, proto string) netpolTri {
	if len(ports) == 0 {
		return triYes
	}
	best := triNo
	for _, p := range ports {
		if protocolOf(p.Protocol) != proto {
			continue
		}
		var t netpolTri
		switch {
		case p.NamedPort != "":
			t = triMaybe
		case p.Port == nil:
			t = triYes
		default:
			hi := *p.Port
			if p.EndPort > hi {
				hi = p.EndPort
			}
			if port >= *p.Port && port <= hi {
				t = triYes
			} else {
				t = triNo
			}
		}
		best = triOr(best, t)
	}
	return best
}
