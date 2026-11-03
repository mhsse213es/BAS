package cloudgraph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Kubernetes NetworkPolicy types and parsing for the boundary analysis (scenario 9). The
// analysis is read-only: it parses NetworkPolicy objects that discovery listed and never
// contacts a pod. A policy object existing does not prove the CNI enforces it. Results are
// "configured", never "enforced".

// K8sSelector is a label selector. An empty selector matches every object in scope.
type K8sSelector struct {
	MatchLabels      map[string]string
	MatchExpressions []K8sSelectorExpr
}

// K8sSelectorExpr is one matchExpressions requirement.
type K8sSelectorExpr struct {
	Key      string
	Operator string // In, NotIn, Exists, DoesNotExist
	Values   []string
}

// K8sNetPolPeer is one from/to entry. A nil selector is absent from the object.
type K8sNetPolPeer struct {
	PodSelector       *K8sSelector
	NamespaceSelector *K8sSelector
	IPBlock           bool
}

// K8sNetPolPort is one ports entry. Port is nil when the entry names only a protocol.
type K8sNetPolPort struct {
	Protocol  string // "TCP" when unset
	Port      *int
	NamedPort string // set when the port is a name, which cannot be resolved here
	EndPort   int
}

// K8sNetPolRule is one ingress or egress rule. An empty Peers or Ports list matches all.
type K8sNetPolRule struct {
	Peers []K8sNetPolPeer
	Ports []K8sNetPolPort
}

// K8sNetworkPolicy is the part of a NetworkPolicy the analysis reads.
type K8sNetworkPolicy struct {
	Namespace   string
	Name        string
	PodSelector K8sSelector
	PolicyTypes []string // as written; empty when unset
	Ingress     []K8sNetPolRule
	Egress      []K8sNetPolRule
}

// selectsIngress reports whether the policy isolates ingress. When policyTypes is unset,
// Ingress is always selected.
func (p K8sNetworkPolicy) selectsIngress() bool {
	if len(p.PolicyTypes) == 0 {
		return true
	}
	return containsString(p.PolicyTypes, "Ingress")
}

// selectsEgress reports whether the policy isolates egress. When policyTypes is unset,
// Egress is selected only if the policy has egress rules.
func (p K8sNetworkPolicy) selectsEgress() bool {
	if len(p.PolicyTypes) == 0 {
		return len(p.Egress) > 0
	}
	return containsString(p.PolicyTypes, "Egress")
}

// Matches reports whether a label set satisfies the selector.
func (s K8sSelector) Matches(labels map[string]string) bool {
	for k, v := range s.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		got, present := labels[e.Key]
		switch e.Operator {
		case "In":
			if !present || !containsString(e.Values, got) {
				return false
			}
		case "NotIn":
			if present && containsString(e.Values, got) {
				return false
			}
		case "Exists":
			if !present {
				return false
			}
		case "DoesNotExist":
			if present {
				return false
			}
		}
	}
	return true
}

// k8sNetPolObject is the JSON shape of a NetworkPolicy list item.
type k8sNetPolObject struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		PodSelector k8sSelectorJSON  `json:"podSelector"`
		PolicyTypes []string         `json:"policyTypes"`
		Ingress     []k8sNetPolRuleJ `json:"ingress"`
		Egress      []k8sNetPolRuleJ `json:"egress"`
	} `json:"spec"`
}

type k8sSelectorJSON struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

type k8sNetPolRuleJ struct {
	From  []k8sNetPolPeerJ `json:"from"`
	To    []k8sNetPolPeerJ `json:"to"`
	Ports []k8sNetPolPortJ `json:"ports"`
}

type k8sNetPolPeerJ struct {
	PodSelector       *k8sSelectorJSON `json:"podSelector"`
	NamespaceSelector *k8sSelectorJSON `json:"namespaceSelector"`
	IPBlock           *struct {
		CIDR string `json:"cidr"`
	} `json:"ipBlock"`
}

type k8sNetPolPortJ struct {
	Protocol string          `json:"protocol"`
	Port     json.RawMessage `json:"port"`
	EndPort  int             `json:"endPort"`
}

// parseK8sNetworkPolicies converts listed NetworkPolicy objects. An object that cannot be read
// is returned as a gap rather than skipped, because a skipped policy could change the answer.
func parseK8sNetworkPolicies(items []json.RawMessage) ([]K8sNetworkPolicy, []string) {
	var out []K8sNetworkPolicy
	var gaps []string
	for _, item := range items {
		var o k8sNetPolObject
		if err := json.Unmarshal(item, &o); err != nil {
			gaps = append(gaps, "networkpolicies: an item could not be read")
			continue
		}
		p := K8sNetworkPolicy{Namespace: o.Metadata.Namespace, Name: o.Metadata.Name, PolicyTypes: o.Spec.PolicyTypes}
		sel, err := convertSelector(o.Spec.PodSelector)
		if err != nil {
			gaps = append(gaps, fmt.Sprintf("networkpolicies: %s/%s: %v", p.Namespace, p.Name, err))
			continue
		}
		p.PodSelector = sel
		ok := true
		for _, r := range o.Spec.Ingress {
			rule, err := convertRule(r.From, r.Ports)
			if err != nil {
				gaps = append(gaps, fmt.Sprintf("networkpolicies: %s/%s: %v", p.Namespace, p.Name, err))
				ok = false
				break
			}
			p.Ingress = append(p.Ingress, rule)
		}
		for _, r := range o.Spec.Egress {
			if !ok {
				break
			}
			rule, err := convertRule(r.To, r.Ports)
			if err != nil {
				gaps = append(gaps, fmt.Sprintf("networkpolicies: %s/%s: %v", p.Namespace, p.Name, err))
				ok = false
				break
			}
			p.Egress = append(p.Egress, rule)
		}
		if ok {
			out = append(out, p)
		}
	}
	return out, gaps
}

func convertRule(peers []k8sNetPolPeerJ, ports []k8sNetPolPortJ) (K8sNetPolRule, error) {
	var rule K8sNetPolRule
	for _, pj := range peers {
		peer := K8sNetPolPeer{IPBlock: pj.IPBlock != nil}
		if pj.PodSelector != nil {
			sel, err := convertSelector(*pj.PodSelector)
			if err != nil {
				return rule, err
			}
			peer.PodSelector = &sel
		}
		if pj.NamespaceSelector != nil {
			sel, err := convertSelector(*pj.NamespaceSelector)
			if err != nil {
				return rule, err
			}
			peer.NamespaceSelector = &sel
		}
		rule.Peers = append(rule.Peers, peer)
	}
	for _, pj := range ports {
		port := K8sNetPolPort{Protocol: pj.Protocol, EndPort: pj.EndPort}
		if port.Protocol == "" {
			port.Protocol = "TCP"
		}
		if len(pj.Port) > 0 && string(pj.Port) != "null" {
			var n int
			var name string
			if err := json.Unmarshal(pj.Port, &n); err == nil {
				port.Port = &n
			} else if err := json.Unmarshal(pj.Port, &name); err == nil {
				port.NamedPort = name
			} else {
				return rule, fmt.Errorf("port is neither a number nor a name")
			}
		}
		rule.Ports = append(rule.Ports, port)
	}
	return rule, nil
}

func convertSelector(j k8sSelectorJSON) (K8sSelector, error) {
	sel := K8sSelector{MatchLabels: j.MatchLabels}
	for _, e := range j.MatchExpressions {
		switch e.Operator {
		case "In", "NotIn", "Exists", "DoesNotExist":
		default:
			return sel, fmt.Errorf("unsupported selector operator %q", e.Operator)
		}
		sel.MatchExpressions = append(sel.MatchExpressions, K8sSelectorExpr{Key: e.Key, Operator: e.Operator, Values: e.Values})
	}
	return sel, nil
}

// sortedUnique returns the distinct values in sorted order.
func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// labelsFromAttrs reads the pod or namespace labels discovery recorded as "label.<key>" attributes.
func labelsFromAttrs(attrs map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range attrs {
		if strings.HasPrefix(k, "label.") {
			out[strings.TrimPrefix(k, "label.")] = v
		}
	}
	return out
}
