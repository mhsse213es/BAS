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
