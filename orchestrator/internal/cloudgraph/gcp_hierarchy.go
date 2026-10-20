package cloudgraph

import (
	"context"
	"fmt"
	"strings"

	crm "google.golang.org/api/cloudresourcemanager/v1"
	crmv2 "google.golang.org/api/cloudresourcemanager/v2"
)

// Folder and organization inheritance. IAM bindings and deny policies set above
// the project apply to it, so a project-scoped pass that ignores them
// under-reports grants and over-reports access that a deny above blocks.

// gcpAncestor is a folder or organization above the project.
type gcpAncestor struct {
	canonical  string // "folders/{id}" or "organizations/{id}"; recorded as inherited_from
	attachment string // URL-encoded attachment point for its deny policies
}

// projectAncestors returns the folders and organization above the project. An
// ancestor of an unrecognized type fails the pass: skipping it would silently
// drop its grants or denies.
func (c *GCPDiscoveryClient) projectAncestors(ctx context.Context) ([]gcpAncestor, error) {
	resp, err := c.crm.Projects.GetAncestry(c.projectID, &crm.GetAncestryRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: reading project ancestry (needs resourcemanager.projects.get): %w", err)
	}
	var out []gcpAncestor
	for _, a := range resp.Ancestor {
		if a.ResourceId == nil {
			return nil, fmt.Errorf("gcp discovery: ancestry entry without a resource ID; refusing to continue")
		}
		id := a.ResourceId.Id
		switch a.ResourceId.Type {
		case "project":
			// The project itself; its bindings are read separately.
		case "folder":
			out = append(out, gcpAncestor{canonical: "folders/" + id, attachment: "cloudresourcemanager.googleapis.com%2Ffolders%2F" + id})
		case "organization":
			out = append(out, gcpAncestor{canonical: "organizations/" + id, attachment: "cloudresourcemanager.googleapis.com%2Forganizations%2F" + id})
		default:
			return nil, fmt.Errorf("gcp discovery: ancestor type %q is not modelled; refusing to continue", a.ResourceId.Type)
		}
	}
	return out, nil
}

// ancestorBindings reads the IAM bindings set on a folder or organization.
// Conditional bindings are returned too; the caller skips and counts them, as
// it does for project bindings.
func (c *GCPDiscoveryClient) ancestorBindings(ctx context.Context, anc gcpAncestor) ([]*crm.Binding, error) {
	if strings.HasPrefix(anc.canonical, "organizations/") {
		pol, err := c.crm.Organizations.GetIamPolicy(anc.canonical, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("gcp discovery: reading IAM policy for %s (needs resourcemanager.organizations.getIamPolicy): %w", anc.canonical, err)
		}
		return pol.Bindings, nil
	}
	pol, err := c.crm2.Folders.GetIamPolicy(anc.canonical, &crmv2.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp discovery: reading IAM policy for %s (needs resourcemanager.folders.getIamPolicy): %w", anc.canonical, err)
	}
	out := make([]*crm.Binding, 0, len(pol.Bindings))
	for _, b := range pol.Bindings {
		var cond *crm.Expr
		if b.Condition != nil {
			cond = &crm.Expr{Expression: b.Condition.Expression}
		}
		out = append(out, &crm.Binding{Role: b.Role, Members: b.Members, Condition: cond})
	}
	return out, nil
}
