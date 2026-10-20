package cloudgraph

import (
	"context"
	"testing"
)

const gcpAncestryFolderOrg = `{"ancestor":[
 {"resourceId":{"type":"project","id":"proj-1"}},
 {"resourceId":{"type":"folder","id":"111"}},
 {"resourceId":{"type":"organization","id":"222"}}]}`

// hierarchyRoutes puts a folder binding, an organization deny and empty folder
// and organization bindings ahead of the standard project routes.
func hierarchyRoutes(ancestry string) []gcpRoute {
	return append([]gcpRoute{
		{needle: ":getAncestry", body: ancestry},
		{needle: "/folders/111:getIamPolicy", body: `{"bindings":[{"role":"roles/storage.objectViewer","members":["group:devs@example.com","user:carol@example.com"]}]}`},
		{needle: "/organizations/222:getIamPolicy", body: `{"bindings":[]}`},
		{needle: "cloudresourcemanager.googleapis.com%2Ffolders%2F111/denypolicies", body: `{"policies":[]}`},
		{needle: "cloudresourcemanager.googleapis.com%2Forganizations%2F222/denypolicies", body: `{"policies":[{"name":"org-deny-carol","rules":[{"denyRule":{"deniedPrincipals":["principal://goog/subject/carol@example.com"],"deniedPermissions":["storage.googleapis.com/objects.get"]}}]}]}`},
	}, gcpStandardRoutes()...)
}

func TestGCPAncestors_FolderGrantReachesProjectWithProvenance(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: hierarchyRoutes(gcpAncestryFolderOrg)})

	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	edge := gcpPerm(graph, "gcp:group:devs@example.com", "storage.objects.get", "projects/proj-1")
	if edge == nil {
		t.Fatal("the folder's objectViewer grant to the group produced no project edge")
	}
	if edge.Attributes["inherited_from"] != "folders/111" {
		t.Errorf("inherited_from = %q, want folders/111", edge.Attributes["inherited_from"])
	}
	if got := (&GCPEvaluator{}).EvaluatePermission(edge, &RequestContext{}); got.State != PolicySupported {
		t.Errorf("EvaluatePermission(folder grant) = %+v, want PolicySupported", got)
	}
}

func TestGCPAncestors_OrganizationDenyBlocksFolderGrant(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: hierarchyRoutes(gcpAncestryFolderOrg)})

	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	edge := gcpPerm(graph, "gcp:user:carol@example.com", "storage.objects.get", "projects/proj-1")
	if edge == nil {
		t.Fatal("carol's folder grant produced no project edge")
	}
	got := (&GCPEvaluator{}).EvaluatePermission(edge, &RequestContext{})
	if got.State != Blocked || got.BlockedBy != "deny-policy" {
		t.Errorf("EvaluatePermission(carol, org deny) = %+v, want Blocked by deny-policy", got)
	}
}

func TestGCPAncestors_UnrecognizedAncestorTypeFailsClosed(t *testing.T) {
	ancestry := `{"ancestor":[{"resourceId":{"type":"project","id":"proj-1"}},{"resourceId":{"type":"tagKey","id":"999"}}]}`
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: hierarchyRoutes(ancestry)})

	if _, _, err := client.Discover(context.Background()); err == nil {
		t.Fatal("Discover must fail on an ancestor type it does not model; skipping it would drop that level's grants and denies")
	}
}
