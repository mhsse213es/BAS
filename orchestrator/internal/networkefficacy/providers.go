package networkefficacy

import (
	"net"
	"strings"
	"time"
)

// Flow is the 4-tuple (plus source) a control-expectation check
// correlates evidence against.
type Flow struct {
	SourceCIDR, DestCIDR string
	Port                 int
	Protocol             string
}

// TimeWindow bounds the time range evidence must fall within to count
// as relevant to a check.
type TimeWindow struct {
	Start, End time.Time
}

// FirewallEvidenceProvider supplies firewall evidence for a flow and
// time window. A returned error means collection/parsing failed --
// distinct from a successful search that found nothing (nil error,
// empty slice).
type FirewallEvidenceProvider interface {
	FirewallEvidenceFor(flow Flow, window TimeWindow) ([]FirewallEvidence, error)
}

// IDSEvidenceProvider supplies IDS/IPS evidence for a flow and time
// window, with the same error-vs-empty-result distinction.
type IDSEvidenceProvider interface {
	IDSEvidenceFor(flow Flow, window TimeWindow) ([]IDSEvidence, error)
}

// matchesFlow reports whether a concrete source/dest IP, port, and
// protocol fall within flow's declared CIDRs/port/protocol. Protocol
// matching is case-insensitive; an empty flow.Protocol matches any
// protocol (the expectation did not constrain it).
func matchesFlow(sourceIP, destIP string, port int, protocol string, flow Flow) bool {
	if port != flow.Port {
		return false
	}
	if flow.Protocol != "" && !strings.EqualFold(protocol, flow.Protocol) {
		return false
	}
	if !cidrContains(flow.SourceCIDR, sourceIP) {
		return false
	}
	if !cidrContains(flow.DestCIDR, destIP) {
		return false
	}
	return true
}

// cidrContains duplicates the small CIDR-containment check already
// duplicated independently in internal/networktopology and
// internal/networkpolicy, per this codebase's established convention
// of not sharing this logic across domain packages.
func cidrContains(cidr, ip string) bool {
	if cidr == "" || ip == "" {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(parsedIP)
}

func inWindow(t time.Time, window TimeWindow) bool {
	return !t.Before(window.Start) && !t.After(window.End)
}

// SyntheticFirewallProvider wraps an in-memory slice of hand-built
// FirewallEvidence values -- no real OPNsense log-format parser exists
// yet (deferred per the spec §8).
type SyntheticFirewallProvider struct {
	events []FirewallEvidence
}

func NewSyntheticFirewallProvider(events []FirewallEvidence) *SyntheticFirewallProvider {
	return &SyntheticFirewallProvider{events: events}
}

func (p *SyntheticFirewallProvider) FirewallEvidenceFor(flow Flow, window TimeWindow) ([]FirewallEvidence, error) {
	var out []FirewallEvidence
	for _, e := range p.events {
		if !matchesFlow(e.SourceIP, e.DestIP, e.Port, e.Protocol, flow) {
			continue
		}
		if !inWindow(e.Timestamp, window) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
