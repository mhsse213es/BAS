package cloudgraph

import (
	"context"
	"fmt"
)

// DiscoveryReport is a flat, provider-neutral count summary of one discovery
// pass, stored with the run so an operator can see what the graph was built
// from. Keys are stable snake_case names; values are counts.
type DiscoveryReport map[string]int

// Discoverer produces the live inventory for one account scope. Each
// provider client implements it through an adapter below; the run executor
// depends only on this contract.
type Discoverer interface {
	Discover(ctx context.Context) (*DiscoveredGraph, DiscoveryReport, error)
}

func (s *DiscoveryStats) report() DiscoveryReport {
	return DiscoveryReport{
		"items_found":           s.ItemsFound,
		"unresolved_principals": s.UnresolvedPrincipals,
	}
}

func (s *AWSDiscoveryStats) report() DiscoveryReport {
	return DiscoveryReport{
		"items_found":            s.ItemsFound,
		"not_action_statements":  s.NotActionStatements,
		"conditional_allows":     s.ConditionalAllows,
		"wildcard_trust_skipped": s.WildcardTrustSkipped,
		"unresolved_trust":       s.UnresolvedTrust,
		"skipped_documents":      s.SkippedDocuments,
	}
}

func (s *GCPDiscoveryStats) report() DiscoveryReport {
	return DiscoveryReport{
		"items_found":              s.ItemsFound,
		"conditional_bindings":     s.ConditionalBindings,
		"unmapped_members":         s.UnmappedMembers,
		"unmapped_deny_principals": s.UnmappedDenyPrincipals,
		"deny_rules":               s.DenyRules,
	}
}

// awsDiscoverer adapts AWSDiscoveryClient to the Discoverer contract.
type awsDiscoverer struct{ client *AWSDiscoveryClient }

// AWSDiscoverer returns the Discoverer for an AWS client.
func AWSDiscoverer(c *AWSDiscoveryClient) Discoverer { return awsDiscoverer{client: c} }

func (d awsDiscoverer) Discover(ctx context.Context) (*DiscoveredGraph, DiscoveryReport, error) {
	graph, stats, err := d.client.Discover(ctx)
	if err != nil {
		return nil, nil, err
	}
	return graph, stats.report(), nil
}

// gcpDiscoverer adapts GCPDiscoveryClient to the Discoverer contract.
type gcpDiscoverer struct{ client *GCPDiscoveryClient }

// GCPDiscoverer returns the Discoverer for a GCP client.
func GCPDiscoverer(c *GCPDiscoveryClient) Discoverer { return gcpDiscoverer{client: c} }

func (d gcpDiscoverer) Discover(ctx context.Context) (*DiscoveredGraph, DiscoveryReport, error) {
	graph, stats, err := d.client.Discover(ctx)
	if err != nil {
		return nil, nil, err
	}
	return graph, stats.report(), nil
}

// azureDiscoverer runs the three Azure passes -- identities, resources, and
// role-derived permissions -- and joins them into one graph. Permissions need
// the identities and resources already discovered, so the order is fixed.
type azureDiscoverer struct{ client *AzureDiscoveryClient }

// AzureDiscoverer returns the Discoverer for an Azure client.
func AzureDiscoverer(c *AzureDiscoveryClient) Discoverer { return azureDiscoverer{client: c} }

func (d azureDiscoverer) Discover(ctx context.Context) (*DiscoveredGraph, DiscoveryReport, error) {
	identities, idStats, err := d.client.DiscoverIdentities(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: identities: %w", err)
	}
	resources, resStats, err := d.client.DiscoverResources(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: resources: %w", err)
	}
	permissions, permStats, err := d.client.DiscoverPermissions(ctx, identities, resources)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: permissions: %w", err)
	}
	graph := &DiscoveredGraph{
		Identities:        identities,
		Resources:         resources,
		Permissions:       permissions,
		Evaluations:       map[string]PathState{},
		AuditAvailability: map[string]string{},
	}
	report := DiscoveryReport{
		"identities":            idStats.ItemsFound,
		"resources":             resStats.ItemsFound,
		"permissions":           permStats.ItemsFound,
		"unresolved_principals": permStats.UnresolvedPrincipals,
	}
	return graph, report, nil
}
