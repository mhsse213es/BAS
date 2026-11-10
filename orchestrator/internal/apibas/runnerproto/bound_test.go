package runnerproto

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/binding"
	"github.com/audspect/bas/internal/apibas/openapi"
)

const boundYAML = `openapi: 3.0.0
info: {title: Shop, version: "1"}
security: [{bearer: []}]
paths:
  /v2/orders/{orderId}:
    get:
      parameters: [{name: orderId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
`

func testBound(t *testing.T) BoundPlan {
	t.Helper()
	inv, err := openapi.Import([]byte(boundYAML))
	if err != nil {
		t.Fatal(err)
	}
	return BoundPlan{InventoryVersion: 1, Inventory: *inv, Spec: binding.Spec{
		Identities: []binding.IdentitySpec{{Name: "alice", CredentialRef: "shop/alice"}, {Name: "bob", CredentialRef: "shop/bob"}},
		Objects: []binding.ObjectSpec{
			{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-A1"}, Owner: "alice", ProtectedValues: []string{"alice-secret-note"}},
			{Operation: "GET /v2/orders/{orderId}", Params: map[string]string{"orderId": "ORD-B1"}, Owner: "bob"},
		},
	}}
}

func boundRequest(t *testing.T) JobRequest {
	t.Helper()
	b := testBound(t)
	fx, err := BoundFixture(b)
	if err != nil {
		t.Fatal(err)
	}
	_, ids, err := BoundScenarioIDs(b)
	if err != nil {
		t.Fatal(err)
	}
	return JobRequest{SchemaVersion: SchemaVersion, JobID: "job-12345678", TargetBaseURL: "http://127.0.0.1:1", Fixture: fx, ScenarioIDs: ids, CredentialsFile: "x", Bound: &b}
}

func TestBoundRequestIsConsistent(t *testing.T) {
	q := boundRequest(t)
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	plan, err := q.CheckBound()
	if err != nil || plan == nil || len(plan.Scenarios) != 2 {
		t.Fatalf("CheckBound: %v %v", plan, err)
	}
	if !IsBoundFixture(q.Fixture) || !strings.HasPrefix(q.Fixture, BoundFixturePrefix) {
		t.Errorf("fixture %q", q.Fixture)
	}
	// The same plan always gives the same fixture name, and a different plan a different one.
	a, _ := BoundFixture(testBound(t))
	b := testBound(t)
	b.Spec.Objects[0].Params["orderId"] = "ORD-A2"
	c, _ := BoundFixture(b)
	if a != q.Fixture || a == c {
		t.Errorf("fixture names: %s %s %s", a, q.Fixture, c)
	}
}

func TestBoundRequestRefusals(t *testing.T) {
	mut := func(f func(*JobRequest)) JobRequest { q := boundRequest(t); f(&q); return q }
	cases := map[string]JobRequest{
		"plan missing":           mut(func(q *JobRequest) { q.Bound = nil }),
		"plan altered":           mut(func(q *JobRequest) { q.Bound.Spec.Objects[0].Params["orderId"] = "ORD-B1" }),
		"protected value edited": mut(func(q *JobRequest) { q.Bound.Spec.Objects[0].ProtectedValues = []string{"something-else-entirely"} }),
		"wrong scenario ids":     mut(func(q *JobRequest) { q.ScenarioIDs = []string{"API-BAS-AUTHZ-001", "API-BAS-AUTHZ-002"} }),
		"fewer scenario ids":     mut(func(q *JobRequest) { q.ScenarioIDs = q.ScenarioIDs[:1] }),
		"fixture not bound":      mut(func(q *JobRequest) { q.Fixture = "orders-two-tenant" }),
		"hash truncated":         mut(func(q *JobRequest) { q.Fixture = q.Fixture[:len(q.Fixture)-2] }),
	}
	for name, q := range cases {
		if _, err := q.CheckBound(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A plan that no longer binds (its inventory lost the operation) is refused too.
	q := boundRequest(t)
	q.Bound.Inventory.Operations = nil
	if fx, err := BoundFixture(*q.Bound); err == nil {
		q.Fixture = fx
		if _, err := q.CheckBound(); err == nil {
			t.Error("a plan that does not bind was accepted")
		}
	}
}

func TestOrdinaryRequestCarriesNoPlan(t *testing.T) {
	q := JobRequest{SchemaVersion: SchemaVersion, JobID: "job-12345678", TargetBaseURL: "http://127.0.0.1:1", Fixture: "orders-two-tenant", ScenarioIDs: []string{"API-BAS-AUTHZ-001"}, CredentialsFile: "x"}
	if plan, err := q.CheckBound(); err != nil || plan != nil {
		t.Errorf("ordinary request: %v %v", plan, err)
	}
	b := testBound(t)
	q.Bound = &b
	if _, err := q.CheckBound(); err == nil {
		t.Error("an ordinary fixture with a plan attached was accepted")
	}
}
