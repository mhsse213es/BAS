// Package cloudtopology models a vendor-agnostic, normalized cloud
// network topology (VPCs, subnets, security groups, route tables,
// peering) and evaluates/searches it to produce cloudgraph.PathState
// evidence. It never imports internal/cloudgraph's IAM-evaluation
// types beyond PathState/Provenance/AccountScope -- see
// docs/superpowers/specs/2026-10-14-network-bas-phase6a-cloud-topology-design.md
// §2-3 for why this schema is shared (unlike internal/networkpolicy
// and internal/networktopology, which stay deliberately independent).
package cloudtopology

import (
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

const (
	MaxSubnetsPerImport        = 500
	MaxRulesPerImport          = 5000
	MaxRoutesPerImport         = 5000
	MaxHopsPerPathQuery        = 10
	MaxCandidateRoutesPerQuery = 20

	// maxRouteSearchSteps is a defensive bound on total route-search
	// work, independent of the subnet/route caps above -- a dense
	// peering mesh within those caps could still cost more exploration
	// than the candidate-count cap alone would bound. Not a
	// caller-tunable safety knob.
	maxRouteSearchSteps = 20000
)

// GroupScope says how far a SecurityGroup's rules reach. A provider
// whose real attachment model this schema cannot represent faithfully
// (e.g. per-instance/per-ENI attachment) gets ScopeUnresolved, never a
// guessed Network or Subnet scope.
type GroupScope string

const (
	ScopeNetwork    GroupScope = "network"
	ScopeSubnet     GroupScope = "subnet"
	ScopeUnresolved GroupScope = "unresolved"
)

// RuleAction mirrors networkpolicy.RuleAction's three-value shape,
// including ActionUnresolved for a vendor construct (NAT, stateful
// return traffic, SG-to-SG group-reference rules) this schema cannot
// losslessly represent.
type RuleAction string

const (
	ActionAllow      RuleAction = "allow"
	ActionDeny       RuleAction = "deny"
	ActionUnresolved RuleAction = "unresolved"
)

const (
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"

	TargetLocal           = "local"
	TargetPeering         = "peering"
	TargetInternetGateway = "internet-gateway"
	TargetNATGateway      = "nat-gateway"
	TargetTransitGateway  = "transit-gateway"
	TargetUnknown         = "unknown"

	PeeringActive   = "active"
	PeeringPending  = "pending"
	PeeringRejected = "rejected"
	PeeringUnknown  = "unknown"
)

// CloudNetwork is a VPC/VNet-equivalent construct.
type CloudNetwork struct {
	CanonicalID  string                   `json:"canonicalId"`
	AccountScope *cloudgraph.AccountScope `json:"accountScope,omitempty"`
	CIDRBlocks   []string                 `json:"cidrBlocks"`
	DisplayName  string                   `json:"displayName,omitempty"`
}

// CloudSubnet belongs to exactly one CloudNetwork.
type CloudSubnet struct {
	CanonicalID string `json:"canonicalId"`
	NetworkID   string `json:"networkId"`
	CIDRBlock   string `json:"cidrBlock"`
	DisplayName string `json:"displayName,omitempty"`
}

// SecurityGroup is a named collection of rules, attached at the scope
// Scope declares.
type SecurityGroup struct {
	CanonicalID string     `json:"canonicalId"`
	NetworkID   string     `json:"networkId"`
	Scope       GroupScope `json:"scope"`
	SubnetID    string     `json:"subnetId,omitempty"` // set only when Scope == ScopeSubnet
}

// SecurityGroupRule is one normalized rule. Exactly one of CIDR or
// ReferencedGroupID is set -- a direct CIDR, or a reference to another
// security group (common in AWS/Azure SG-to-SG rules, which this
// schema cannot resolve group membership for -- see
// EvaluateSecurityGroupRules). Order is the rule's evaluation
// priority, lower evaluated first -- AWS's allow-only, no-priority
// shape gets a synthetic ascending Order at import time, making it a
// degenerate case of the same model Azure NSGs use natively.
type SecurityGroupRule struct {
	ID                string     `json:"id"`
	GroupID           string     `json:"groupId"`
	Order             int        `json:"order"`
	Direction         string     `json:"direction"` // DirectionInbound | DirectionOutbound
	Action            RuleAction `json:"action"`
	Protocol          string     `json:"protocol,omitempty"`
	PortRange         string     `json:"portRange,omitempty"`
	CIDR              string     `json:"cidr,omitempty"`
	ReferencedGroupID string     `json:"referencedGroupId,omitempty"`
	// Note is required whenever Action == ActionUnresolved -- same
	// discipline as networkpolicy.Rule.Note.
	Note string `json:"note,omitempty"`
}

// RouteTableEntry is one route, associated to a subnet.
type RouteTableEntry struct {
	ID              string `json:"id"`
	SubnetID        string `json:"subnetId"`
	DestinationCIDR string `json:"destinationCidr"`
	Target          string `json:"target"`           // TargetLocal | TargetPeering | TargetInternetGateway | TargetNATGateway | TargetTransitGateway | TargetUnknown
	TargetRef       string `json:"targetRef,omitempty"` // e.g. PeeringConnection.CanonicalID when Target == TargetPeering
}

// PeeringConnection links two CloudNetworks, possibly cross-account.
// Only State == PeeringActive is ever treated as a usable route edge.
type PeeringConnection struct {
	CanonicalID string `json:"canonicalId"`
	NetworkAID  string `json:"networkAId"`
	NetworkBID  string `json:"networkBId"`
	State       string `json:"state"` // PeeringActive | PeeringPending | PeeringRejected | PeeringUnknown
}

// CloudTopologyImport is one auditable, versioned topology snapshot --
// the same shape discipline as networkpolicy.PolicyImport and
// networktopology.TopologyImport. Limitations is required to be
// non-empty whenever any SecurityGroup.Scope == ScopeUnresolved or any
// SecurityGroupRule.Action == ActionUnresolved, enforced at the API
// validation layer (Task 7), not here.
type CloudTopologyImport struct {
	ID            string              `json:"id,omitempty"`
	SourceType    string              `json:"sourceType"`
	ImportedBy    string              `json:"importedBy,omitempty"`
	ImportedAt    time.Time           `json:"importedAt,omitempty"`
	ConfigVersion string              `json:"configVersion,omitempty"`
	Networks      []CloudNetwork      `json:"networks"`
	Subnets       []CloudSubnet       `json:"subnets"`
	Groups        []SecurityGroup     `json:"groups"`
	Rules         []SecurityGroupRule `json:"rules"`
	Routes        []RouteTableEntry   `json:"routes"`
	Peerings      []PeeringConnection `json:"peerings"`
	Limitations   []string            `json:"limitations,omitempty"`
}
