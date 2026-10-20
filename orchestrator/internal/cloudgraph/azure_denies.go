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
// definition shape, so the same net-action rules apply.
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

// azureDenyEntry is one deny assignment reduced to what edge attachment needs.
type azureDenyEntry struct {
	scope   string
	actions []string
	exclude map[string]bool
}

// DiscoverDenyAssignments reads every deny assignment in the subscription and
// indexes it by principal object ID ("*" for everyone). Without this pass,
// Azure's deny-overrides-allow rule is invisible and a discovered role grant
// is reported as usable when a deny assignment blocks it.
//
// A deny marked doNotApplyToChildScopes applies only at its exact scope. The
// evaluator's prefix coverage cannot express that, so such denies are counted
// as unmodelled rather than guessed. Ignoring them would hide a block;
// applying them to children would invent one.
func (c *AzureDiscoveryClient) DiscoverDenyAssignments(ctx context.Context) (map[string][]azureDenyEntry, *AzureDenyStats, error) {
	url := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01", c.ARMBaseURL, c.subscriptionID)
	pages, err := c.fetchAllPages(ctx, url, c.armTokens)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: listing deny assignments: %w", err)
	}

	index := map[string][]azureDenyEntry{}
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
		actions := effectiveRoleActions(&def)
		if len(actions) == 0 {
			continue
		}
		exclude := map[string]bool{}
		for _, ex := range d.Properties.ExcludePrincipals {
			exclude[ex.ID] = true
		}
		entry := azureDenyEntry{scope: d.Properties.Scope, actions: actions, exclude: exclude}
		for _, p := range d.Properties.Principals {
			index[p.ID] = append(index[p.ID], entry)
		}
	}
	return index, stats, nil
}

// AzureDenyStats counts deny assignments by how the pass handled them.
type AzureDenyStats struct {
	Found          int
	ExactScopeOnly int
}

// attachAzureDenies marks each permission edge the deny index blocks. An edge
// is blocked when a deny applies to its principal (or to everyone), its scope
// covers the target, and its actions include the edge's action. The edge's own
// action is written into deny_actions, so a wildcard deny action matches the
// concrete action without the evaluator having to expand wildcards. Returns the
// number of edges marked.
func attachAzureDenies(permissions []*CloudPermission, index map[string][]azureDenyEntry) int {
	marked := 0
	for _, p := range permissions {
		oid := azureObjectID(p.Source.CanonicalID)
		if oid == "" {
			continue
		}
		for _, key := range []string{oid, azureEveryonePrincipal} {
			entry, ok := firstCoveringDeny(index[key], oid, p.Target.CanonicalID, p.Action)
			if !ok {
				continue
			}
			if p.Attributes == nil {
				p.Attributes = map[string]string{}
			}
			p.Attributes["deny_assignment"] = "true"
			p.Attributes["deny_scope"] = entry.scope
			p.Attributes["deny_actions"] = p.Action
			marked++
			break
		}
	}
	return marked
}

func firstCoveringDeny(entries []azureDenyEntry, oid, target, action string) (azureDenyEntry, bool) {
	for _, e := range entries {
		if e.exclude[oid] {
			continue
		}
		if !scopeCovers(e.scope, target) {
			continue
		}
		if !denyActionsCover(e.actions, action) {
			continue
		}
		return e, true
	}
	return azureDenyEntry{}, false
}

// denyActionsCover reports whether a deny's net actions match an edge action.
// Deny actions may be wildcards ("*", "Microsoft.Storage/*"); the evaluator
// performs exact matching, so the check happens here and the concrete action
// is attached by the caller.
func denyActionsCover(actions []string, action string) bool {
	for _, pattern := range actions {
		if pattern == action {
			return true
		}
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(action, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
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
