package cloudgraph

import (
	"context"
	"testing"
)

const gcpOpsMember = "gcp:group:ops@example.com"

// opsOwnerEdges returns every edge that grants ops the owner permission at the
// project scope. The fixture's owner binding is conditional.
func opsOwnerEdges(g *DiscoveredGraph) []*CloudPermission {
	var out []*CloudPermission
	for _, p := range g.Permissions {
		if p.Source.CanonicalID == gcpOpsMember && p.Action == "resourcemanager.projects.delete" && p.Target.CanonicalID == "projects/"+gcpProject {
			out = append(out, p)
		}
	}
	return out
}

// A conditional binding produces an edge marked as conditional, and the evaluator
// reports it as conditionally reachable with the condition named.
func TestGCPConditionalBinding_ProducesConditionalEdge(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: gcpStandardRoutes()})
	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if stats.ConditionalBindings != 1 {
		t.Errorf("ConditionalBindings = %d, want 1", stats.ConditionalBindings)
	}
	edges := opsOwnerEdges(graph)
	if len(edges) != 1 {
		t.Fatalf("ops owner edges = %d, want 1 conditional edge", len(edges))
	}
	if edges[0].Attributes["binding_condition"] != "true" {
		t.Errorf("edge is not marked conditional: %+v", edges[0].Attributes)
	}
	got := (&GCPEvaluator{}).EvaluatePermission(edges[0], &RequestContext{})
	if got.State != ConditionallyReachable {
		t.Fatalf("state = %s, want conditionally_reachable", got.State)
	}
	if len(got.UnresolvedConds) != 1 || got.UnresolvedConds[0] != gcpBindingCondition {
		t.Errorf("UnresolvedConds = %v, want [%s]", got.UnresolvedConds, gcpBindingCondition)
	}
}

// When the same member also holds the same role unconditionally, the
// unconditional grant stays a clean grant. The conditional one must not upgrade
// it or hide it.
func TestGCPConditionalBinding_UnconditionalGrantStaysClean(t *testing.T) {
	routes := append([]gcpRoute{{needle: ":getIamPolicy", body: `{"bindings":[` +
		`{"role":"roles/owner","members":["group:ops@example.com"]},` +
		`{"role":"roles/owner","members":["group:ops@example.com"],"condition":{"expression":"request.time < timestamp(\"2030-01-01T00:00:00Z\")"}}` +
		`]}`}}, gcpStandardRoutes()...)
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: routes})
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var clean, conditional int
	for _, p := range opsOwnerEdges(graph) {
		state := (&GCPEvaluator{}).EvaluatePermission(p, &RequestContext{}).State
		if p.Attributes["binding_condition"] == "true" {
			conditional++
			if state != ConditionallyReachable {
				t.Errorf("conditional edge state = %s, want conditionally_reachable", state)
			}
		} else {
			clean++
			if state != PolicySupported {
				t.Errorf("unconditional edge state = %s, want policy_supported", state)
			}
		}
	}
	if clean != 1 || conditional != 1 {
		t.Errorf("edges: clean=%d conditional=%d, want 1 each", clean, conditional)
	}
}

const gcpConditionalDenyRoute = `{"policies":[{"name":"cond-deny","rules":[` +
	`{"denyRule":{"deniedPrincipals":["principal://goog/subject/alice@example.com"],"deniedPermissions":["storage.googleapis.com/objects.get"],` +
	`"denialCondition":{"expression":"request.time < timestamp(\"2030-01-01T00:00:00Z\")"}}},` +
	`{"denyRule":{"deniedPrincipals":["principalSet://goog/group/ops@example.com"],"deniedPermissions":["resourcemanager.googleapis.com/projects.delete"],` +
	`"denialCondition":{"expression":"request.time < timestamp(\"2030-01-01T00:00:00Z\")"}}}` +
	`]}]}`

// conditionalDenyRoutes serves the conditional deny rules in place of the
// standard unconditional deny rule (routes match in order).
func conditionalDenyRoutes() []gcpRoute {
	return append([]gcpRoute{{
		needle: "cloudresourcemanager.googleapis.com%2Fprojects%2Fproj-1/denypolicies",
		body:   gcpConditionalDenyRoute,
	}}, gcpStandardRoutes()...)
}

// A conditional deny rule does not block outright. It makes the grant conditional,
// with the deny's condition named.
func TestGCPConditionalDeny_IsConditionalNotBlocked(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: conditionalDenyRoutes()})
	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if stats.ConditionalDenyRules != 2 {
		t.Errorf("ConditionalDenyRules = %d, want 2", stats.ConditionalDenyRules)
	}

	alice := gcpPerm(graph, "gcp:user:alice@example.com", "storage.objects.get", "projects/"+gcpProject)
	if alice == nil {
		t.Fatal("expected alice storage.objects.get edge")
	}
	got := (&GCPEvaluator{}).EvaluatePermission(alice, &RequestContext{})
	if got.State != ConditionallyReachable {
		t.Fatalf("state = %s, want conditionally_reachable (not blocked)", got.State)
	}
	if len(got.UnresolvedConds) != 1 || got.UnresolvedConds[0] != gcpDenyCondition {
		t.Errorf("UnresolvedConds = %v, want [%s]", got.UnresolvedConds, gcpDenyCondition)
	}
}

// A conditional binding and a conditional deny on the same grant name both
// conditions, so the reader sees every condition that could stop it.
func TestGCPConditionalDeny_StacksWithConditionalBinding(t *testing.T) {
	client, _ := newTestGCPClient(t, &gcpFakeAPI{routes: conditionalDenyRoutes()})
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	edges := opsOwnerEdges(graph)
	if len(edges) != 1 {
		t.Fatalf("ops owner edges = %d, want 1", len(edges))
	}
	got := (&GCPEvaluator{}).EvaluatePermission(edges[0], &RequestContext{})
	if got.State != ConditionallyReachable {
		t.Fatalf("state = %s, want conditionally_reachable", got.State)
	}
	want := map[string]bool{gcpBindingCondition: true, gcpDenyCondition: true}
	for _, c := range got.UnresolvedConds {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("UnresolvedConds = %v, missing %v", got.UnresolvedConds, want)
	}
}
