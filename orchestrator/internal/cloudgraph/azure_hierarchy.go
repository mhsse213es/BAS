package cloudgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Management group inheritance. A role assignment or deny made at a management
// group applies to every subscription beneath it. Subscription-scoped discovery
// never sees those, so a subscription Owner granted at the group appears to
// have no access (under-reporting), and a deny at the group is invisible
// (over-reporting). This module reads the ancestor groups of the subscription
// and returns the assignments and denies that reach it.

// mgChild is one entry in the management group tree returned by
// GET managementGroups/{id}?$expand=children&$recurse=true. Children are
// management groups (type Microsoft.Management/managementGroups) or
// subscriptions (type /subscriptions).
type mgChild struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Children []mgChild `json:"children"`
}

type mgTree struct {
	ID         string `json:"id"`
	Properties struct {
		Children []mgChild `json:"children"`
	} `json:"properties"`
}

// maxMGDepth bounds the walk. Azure caps management group nesting well below
// this; reaching it means the response is not what we expect.
const maxMGDepth = 16

// ancestorManagementGroups returns the ARM IDs of the management groups above
// the subscription, from the tenant root group down to its immediate parent.
// The subscription must appear in the hierarchy this principal can read. If it
// does not, the function fails rather than returning an empty set, because an
// empty set would mean no inherited access was checked.
func (c *AzureDiscoveryClient) ancestorManagementGroups(ctx context.Context) ([]string, error) {
	if c.tenantID == "" {
		return nil, fmt.Errorf("azure discovery: tenant ID is required to read the management group hierarchy")
	}
	root := "/providers/Microsoft.Management/managementGroups/" + c.tenantID
	url := c.ARMBaseURL + root + "?api-version=2020-05-01&$expand=children&$recurse=true"
	var tree mgTree
	if err := c.fetchOne(ctx, url, c.armTokens, &tree); err != nil {
		return nil, fmt.Errorf("azure discovery: reading management group hierarchy (needs Reader on the tenant root management group): %w", err)
	}
	target := "/subscriptions/" + c.subscriptionID
	path, found := mgPathTo(tree.Properties.Children, target, []string{root}, 0)
	if !found {
		return nil, fmt.Errorf("azure discovery: subscription %s is not in the management group hierarchy visible to this principal; inherited access cannot be checked", c.subscriptionID)
	}
	return path, nil
}

// mgPathTo returns the management groups from the root to the immediate parent
// of target, where prefix is the path to the level being searched.
func mgPathTo(children []mgChild, target string, prefix []string, depth int) ([]string, bool) {
	if depth > maxMGDepth {
		return nil, false
	}
	for _, child := range children {
		if strings.EqualFold(child.ID, target) {
			return prefix, true
		}
		if child.Type == "Microsoft.Management/managementGroups" {
			next := append(append([]string{}, prefix...), child.ID)
			if path, ok := mgPathTo(child.Children, target, next, depth+1); ok {
				return path, true
			}
		}
	}
	return nil, false
}

// subscriptionScope returns the ARM scope of the discovered subscription.
func (c *AzureDiscoveryClient) subscriptionScope() string {
	return "/subscriptions/" + c.subscriptionID
}

// inheritedRoleAssignments returns the role assignments made exactly at each
// ancestor management group, rewritten to the subscription scope they reach. A
// list at a group's scope can also return assignments on other subscriptions
// beneath it, so only assignments whose scope is the group itself are kept.
func (c *AzureDiscoveryClient) inheritedRoleAssignments(ctx context.Context) ([]armRoleAssignment, error) {
	ancestors, err := c.ancestorManagementGroups(ctx)
	if err != nil {
		return nil, err
	}
	var out []armRoleAssignment
	for _, mg := range ancestors {
		url := c.ARMBaseURL + mg + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
		pages, err := c.fetchAllPages(ctx, url, c.armTokens)
		if err != nil {
			return nil, fmt.Errorf("azure discovery: listing role assignments at %s: %w", mg, err)
		}
		assignments, err := parseRoleAssignmentPages(pages)
		if err != nil {
			return nil, err
		}
		for _, a := range assignments {
			if !strings.EqualFold(a.Properties.Scope, mg) {
				continue
			}
			a.Properties.Scope = c.subscriptionScope()
			a.InheritedFrom = mg
			out = append(out, a)
		}
	}
	return out, nil
}

// inheritedDenyPages returns deny assignments made exactly at each ancestor
// management group, rewritten to the subscription scope they reach. A deny marked
// doNotApplyToChildScopes applies only at its own group, not to this
// subscription, so it is dropped here rather than applied.
func (c *AzureDiscoveryClient) inheritedDenyPages(ctx context.Context) ([]json.RawMessage, error) {
	ancestors, err := c.ancestorManagementGroups(ctx)
	if err != nil {
		return nil, err
	}
	var out []json.RawMessage
	for _, mg := range ancestors {
		url := c.ARMBaseURL + mg + "/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01"
		pages, err := c.fetchAllPages(ctx, url, c.armTokens)
		if err != nil {
			return nil, fmt.Errorf("azure discovery: listing deny assignments at %s: %w", mg, err)
		}
		for _, raw := range pages {
			var d armDenyAssignment
			if err := json.Unmarshal(raw, &d); err != nil {
				return nil, fmt.Errorf("azure discovery: parsing deny assignment at %s: %w", mg, err)
			}
			if !strings.EqualFold(d.Properties.Scope, mg) || d.Properties.DoNotApplyToChildScopes {
				continue
			}
			d.Properties.Scope = c.subscriptionScope()
			b, err := json.Marshal(d)
			if err != nil {
				return nil, fmt.Errorf("azure discovery: re-encoding inherited deny: %w", err)
			}
			out = append(out, b)
		}
	}
	return out, nil
}

// DiscoverPermissionsWithInheritance is DiscoverPermissions plus the role
// assignments that reach the subscription from its ancestor management groups.
// Discovery uses this form; DiscoverPermissions alone does not see inherited
// grants.
func (c *AzureDiscoveryClient) DiscoverPermissionsWithInheritance(ctx context.Context, identities []*CloudIdentity, resources []*CloudResource) ([]*CloudPermission, *DiscoveryStats, error) {
	inherited, err := c.inheritedRoleAssignments(ctx)
	if err != nil {
		return nil, nil, err
	}
	return c.discoverPermissionsFrom(ctx, identities, resources, inherited)
}

// DiscoverDenyAssignmentsWithInheritance is DiscoverDenyAssignments plus the
// denies made at ancestor management groups that reach the subscription.
func (c *AzureDiscoveryClient) DiscoverDenyAssignmentsWithInheritance(ctx context.Context) ([]*ScopeDenial, *AzureDenyStats, error) {
	inherited, err := c.inheritedDenyPages(ctx)
	if err != nil {
		return nil, nil, err
	}
	return c.discoverDenyAssignmentsFrom(ctx, inherited)
}
