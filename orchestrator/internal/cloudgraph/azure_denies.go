package cloudgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// azureEveryonePrincipal is the object ID Azure uses for a deny assignment that
// applies to all principals.
const azureEveryonePrincipal = "00000000-0000-0000-0000-000000000000"

// armDenyAssignment is one ARM deny assignment. Its permissions share the role
// definition shape, so the same per-block rules apply.
type armDenyAssignment struct {
	Properties struct {
		Scope                   string `json:"scope"`
		DoNotApplyToChildScopes bool   `json:"doNotApplyToChildScopes"`
		Permissions             []struct {
			Actions        []string `json:"actions"`
			NotActions     []string `json:"notActions"`
			DataActions    []string `json:"dataActions"`
			NotDataActions []string `json:"notDataActions"`
		} `json:"permissions"`
		Principals []struct {
			ID string `json:"id"`
		} `json:"principals"`
		ExcludePrincipals []struct {
			ID string `json:"id"`
		} `json:"excludePrincipals"`
	} `json:"properties"`
}

// ScopeDenial is one permission block of an Azure deny assignment, reduced to
// what evaluation needs. It is kept in the DiscoveredGraph so a scenario can
// apply it to the resource it actually targets, not only to the scope of the
// edge that granted the access.
type ScopeDenial struct {
	PrincipalIDs []string        `json:"principalIds"` // object IDs; azureEveryonePrincipal means all
	Scope        string          `json:"scope"`
	Actions      []string        `json:"actions"`
	NotActions   []string        `json:"notActions"`
	Exclude      map[string]bool `json:"exclude,omitempty"` // excluded object IDs
}

// AzureDenyStats counts deny assignments by how the pass handled them.
type AzureDenyStats struct {
	Found          int
	ExactScopeOnly int
}

// DiscoverDenyAssignments reads every deny assignment in the subscription and
// returns one ScopeDenial per permission block. Without this pass Azure's
// deny-overrides-allow rule is invisible and a discovered grant is reported as
// usable when a deny blocks it.
//
// A deny marked doNotApplyToChildScopes applies only at its exact scope. The
// evaluator's prefix coverage cannot express that, so such denies are counted
// as unmodelled rather than guessed. Ignoring them would hide a block;
// applying them to children would invent one.
func (c *AzureDiscoveryClient) DiscoverDenyAssignments(ctx context.Context) ([]*ScopeDenial, *AzureDenyStats, error) {
	return c.discoverDenyAssignmentsFrom(ctx, nil)
}

// discoverDenyAssignmentsFrom reads the subscription's deny assignments and
// appends extra pages (denies inherited from management groups).
func (c *AzureDiscoveryClient) discoverDenyAssignmentsFrom(ctx context.Context, extra []json.RawMessage) ([]*ScopeDenial, *AzureDenyStats, error) {
	url := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01", c.ARMBaseURL, c.subscriptionID)
	pages, err := c.fetchAllPages(ctx, url, c.armTokens)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: listing deny assignments: %w", err)
	}
	pages = append(pages, extra...)

	var denials []*ScopeDenial
	stats := &AzureDenyStats{}
	for _, raw := range pages {
		var d armDenyAssignment
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, nil, fmt.Errorf("azure discovery: parsing deny assignment: %w", err)
		}
		stats.Found++
		if d.Properties.DoNotApplyToChildScopes {
			stats.ExactScopeOnly++
			continue
		}

		var def armRoleDefinition
		def.Properties.Permissions = d.Properties.Permissions
		exclude := map[string]bool{}
		for _, ex := range d.Properties.ExcludePrincipals {
			exclude[ex.ID] = true
		}
		principals := make([]string, 0, len(d.Properties.Principals))
		for _, p := range d.Properties.Principals {
			principals = append(principals, p.ID)
		}
		for _, b := range roleBlocks(&def) {
			denials = append(denials, &ScopeDenial{
				PrincipalIDs: principals,
				Scope:        d.Properties.Scope,
				Actions:      b.granted,
				NotActions:   b.notActions,
				Exclude:      exclude,
			})
		}
	}
	return denials, stats, nil
}

// denialMatches reports whether one ScopeDenial applies to a principal's object
// ID, a resource, and an action. Exclusions and per-block notActions are
// honoured. Scope coverage uses the evaluator's own rule.
func denialMatches(d *ScopeDenial, oid, resource, action string) bool {
	if d.Exclude[oid] {
		return false
	}
	appliesToPrincipal := false
	for _, id := range d.PrincipalIDs {
		if id == azureEveryonePrincipal || id == oid {
			appliesToPrincipal = true
			break
		}
	}
	if !appliesToPrincipal {
		return false
	}
	if !scopeCovers(d.Scope, resource) {
		return false
	}
	return azureAnyPatternMatches(d.Actions, action) && !azureAnyPatternMatches(d.NotActions, action)
}

// firstDenialFor returns the first denial that applies, or false.
func firstDenialFor(denials []*ScopeDenial, oid, resource, action string) (*ScopeDenial, bool) {
	for _, d := range denials {
		if denialMatches(d, oid, resource, action) {
			return d, true
		}
	}
	return nil, false
}

// attachAzureDenies marks each permission edge a denial blocks, judged against
// the edge's own target. Scenario evaluation re-applies denials against the
// resource it targets, which is the stricter check. Returns the number of edges
// marked. The edge's action is written into deny_actions, so a wildcard deny
// matches the concrete action without the evaluator expanding wildcards.
func attachAzureDenies(permissions []*CloudPermission, denials []*ScopeDenial) int {
	marked := 0
	for _, p := range permissions {
		oid := azureObjectID(p.Source.CanonicalID)
		if oid == "" {
			continue
		}
		d, ok := firstDenialFor(denials, oid, p.Target.CanonicalID, p.Action)
		if !ok {
			continue
		}
		if p.Attributes == nil {
			p.Attributes = map[string]string{}
		}
		p.Attributes["deny_assignment"] = "true"
		p.Attributes["deny_scope"] = d.Scope
		p.Attributes["deny_actions"] = p.Action
		marked++
	}
	return marked
}

// azureObjectID extracts the principal object ID from an Azure canonical ID.
func azureObjectID(canonical string) string {
	switch {
	case strings.HasPrefix(canonical, "azure:user_"):
		return strings.TrimPrefix(canonical, "azure:user_")
	case strings.HasPrefix(canonical, "azure:sp_"):
		return strings.TrimPrefix(canonical, "azure:sp_")
	}
	return ""
}
