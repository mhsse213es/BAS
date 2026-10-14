// Package networkpolicy models a vendor-agnostic, normalized firewall and
// segmentation policy, and evaluates it against candidate traffic queries
// to produce cloudgraph.PathState evidence. It never imports
// internal/networkgraph -- see internal/networkcorrelation for the one
// place policy evidence and reachability evidence are allowed to meet.
package networkpolicy

import "time"

// RuleAction is a rule's effect when it matches. ActionUnresolved exists
// specifically so a vendor construct this schema can't losslessly
// represent (NAT, stateful return traffic, address/service groups) can be
// represented honestly instead of forced into Allow or Deny.
type RuleAction string

const (
	ActionAllow      RuleAction = "allow"
	ActionDeny       RuleAction = "deny"
	ActionUnresolved RuleAction = "unresolved"
)

// Zone is a named network segment, resolved to one or more CIDRs.
type Zone struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// Rule is one normalized policy rule. Each side (source/dest) is either a
// zone reference (SourceZone/DestZone, resolved against the owning
// PolicyImport's Zones) or a direct CIDR (SourceCIDR/DestCIDR) -- never
// both for the same side.
type Rule struct {
	ID         string     `json:"id"`
	Order      int        `json:"order"`
	SourceZone string     `json:"sourceZone,omitempty"`
	SourceCIDR string     `json:"sourceCidr,omitempty"`
	DestZone   string     `json:"destZone,omitempty"`
	DestCIDR   string     `json:"destCidr,omitempty"`
	Protocol   string     `json:"protocol,omitempty"`
	PortRange  string     `json:"portRange,omitempty"`
	Action     RuleAction `json:"action"`
	// Note is required whenever Action == ActionUnresolved -- it is the
	// honest explanation for why this rule couldn't be losslessly
	// translated, carried into any PolicyEvaluation this rule decides.
	Note string `json:"note,omitempty"`
}

// DefaultPolicy is what applies when no rule matches a query.
type DefaultPolicy string

const (
	DefaultAllow DefaultPolicy = "allow"
	DefaultDeny  DefaultPolicy = "deny"
)

// PolicyImport is one auditable, versioned policy snapshot.
type PolicyImport struct {
	ID            string        `json:"id,omitempty"`
	SourceType    string        `json:"sourceType"`
	ImportedBy    string        `json:"importedBy,omitempty"`
	ImportedAt    time.Time     `json:"importedAt,omitempty"`
	ConfigVersion string        `json:"configVersion,omitempty"`
	DefaultPolicy DefaultPolicy `json:"defaultPolicy"`
	Zones         []Zone        `json:"zones"`
	Rules         []Rule        `json:"rules"`
	// Limitations is required to be non-empty whenever any Rule.Action ==
	// ActionUnresolved -- enforced at the API validation layer (Task 5),
	// not here (this package has no validation of its own).
	Limitations []string `json:"limitations,omitempty"`
}
