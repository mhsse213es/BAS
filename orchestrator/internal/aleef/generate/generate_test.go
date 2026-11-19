package generate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

// ---- generic toy application ----

func strS() *model.Schema { return &model.Schema{Type: "string"} }

func idP() []model.Param {
	return []model.Param{{Name: "id", In: "path", IsObjectID: true, Required: true, Schema: strS()}}
}

func mkOp(id, method, path string, pp []model.Param, body *model.Schema, class model.OpClass) model.Operation {
	return model.Operation{ID: id, Method: method, Path: path, PathParams: pp, Body: body, Class: class}
}

func toyModel() model.Model {
	patchBody := &model.Schema{Type: "object", Properties: map[string]*model.Schema{"title": strS(), "qty": {Type: "integer"}}}
	return model.Model{
		Roles: []string{"member", "admin"},
		Operations: []model.Operation{
			mkOp("getV1", "GET", "/api/v1/items/{id}", idP(), nil, model.ClassRead),
			mkOp("getV2", "GET", "/api/v2/items/{id}", idP(), nil, model.ClassRead),
			mkOp("patchV2", "PATCH", "/api/v2/items/{id}", idP(), patchBody, model.ClassReversible),
			mkOp("deleteV2", "DELETE", "/api/v2/items/{id}", idP(), nil, model.ClassReversible),
			mkOp("mystery", "GET", "/api/v2/mystery/{id}", idP(), nil, model.ClassUnknown),
			mkOp("payout", "PATCH", "/api/v2/payouts/{id}", idP(), patchBody, model.ClassMoney),
			mkOp("notify", "POST", "/api/v2/notices/{id}", idP(), &model.Schema{Type: "object", Properties: map[string]*model.Schema{"text": strS()}}, model.ClassNotifying),
		},
	}
}

func toyAccounts() []model.Account {
	return []model.Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "tok-alice", Role: "member"},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "tok-bob", Role: "member"},
		{Name: "carol", CustomerID: "cust-c", TokenRef: "tok-carol", Role: "member"},
	}
}

func toyFixture() fixture.Fixture {
	f := fixture.Fixture{Name: "toy"}
	objs := map[string]string{"alice": "item-a1", "bob": "item-b1", "carol": "item-c1"}
	for _, a := range toyAccounts() {
		f.Identities = append(f.Identities, fixture.Identity{Name: a.Name, CustomerID: a.CustomerID, TokenRef: a.TokenRef, Role: a.Role})
		f.Objects = append(f.Objects, fixture.Object{
			ID: objs[a.Name], OwnerID: a.CustomerID, Status: "pending",
			Public: map[string]string{}, Protected: map[string]string{"canary": "ALEEF-CANARY-t-" + a.Name},
		})
	}
	return f
}

// emptyCat avoids loading the embedded catalogue in unit tests.
var emptyCat = []contract.Scenario{}

func gen(t *testing.T, opt Options) []Test {
	t.Helper()
	if opt.Catalogue == nil {
		opt.Catalogue = emptyCat
	}
	out, err := Generate(toyModel(), toyFixture(), toyAccounts(), opt)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func ids(ts []Test) map[string]bool {
	m := map[string]bool{}
	for _, x := range ts {
		m[x.ID] = true
	}
	return m
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- required tests ----

func TestGenerateIsDeterministic(t *testing.T) {
	opt := Options{Seed: 7, Variations: AllVariations()}
	a, b := mustJSON(t, gen(t, opt)), mustJSON(t, gen(t, opt))
	if a != b {
		t.Fatal("same input and seed must give byte-identical output")
	}
	x, y := gen(t, opt), gen(t, Options{Seed: 8, Variations: AllVariations()})
	if len(x) == 0 {
		t.Fatal("no tests generated")
	}
	if len(ids(x)) != len(x) {
		t.Fatal("duplicate ids")
	}
	if len(x) != len(y) {
		t.Fatalf("seed changed the number of tests: %d vs %d", len(x), len(y))
	}
	for id := range ids(x) {
		if !ids(y)[id] {
			t.Fatalf("seed changed the id set (missing %s)", id)
		}
	}
	if mustJSON(t, x) == mustJSON(t, y) {
		t.Fatal("different seeds should order the variations differently")
	}
	for i := range x {
		if x[i].Params["variation"] == "" && x[i].ID != y[i].ID {
			t.Fatal("base tests must keep their order across seeds")
		}
	}
}

func TestGenerateRespectsMaxTests(t *testing.T) {
	all := gen(t, Options{Seed: 3, Variations: AllVariations()})
	if len(all) < 10 {
		t.Fatalf("need a larger set, got %d", len(all))
	}
	cut := gen(t, Options{Seed: 3, Variations: AllVariations(), MaxTests: 5})
	if len(cut) != 5 {
		t.Fatalf("MaxTests 5 gave %d", len(cut))
	}
	for i := range cut {
		if cut[i].ID != all[i].ID {
			t.Fatalf("truncation must take a stable prefix; index %d differs", i)
		}
	}
	if n := len(gen(t, Options{Variations: AllVariations(), MaxTests: 100000})); n != len(gen(t, Options{Variations: AllVariations()})) {
		t.Fatalf("large MaxTests must not drop tests: %d", n)
	}
}

func TestGenerateOutputsPassContractValidate(t *testing.T) {
	all := gen(t, Options{Seed: 1, Variations: AllVariations()})
	if len(all) == 0 {
		t.Fatal("no tests")
	}
	for _, x := range all {
		if err := x.Scenario.Validate(); err != nil {
			t.Errorf("%s: %v", x.ID, err)
		}
		if x.Scenario.ID != x.ID || x.Scenario.Category != "ALEEF" {
			t.Errorf("%s: scenario id/category = %s/%s", x.ID, x.Scenario.ID, x.Scenario.Category)
		}
		if !strings.HasPrefix(x.ID, "ALEEF-GEN-"+x.Property+"-") {
			t.Errorf("id %s does not embed property %s", x.ID, x.Property)
		}
		if x.Template.Property != x.Property || x.Template.Oracle == "" {
			t.Errorf("%s: template missing property or oracle", x.ID)
		}
	}
}

func TestGenerateSkipsUnclassifiedAndMoneyMovementOps(t *testing.T) {
	m := toyModel()
	out, rep, err := GenerateWithReport(m, toyFixture(), toyAccounts(), Options{Catalogue: emptyCat, Variations: AllVariations()})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("runnable operations produced nothing")
	}
	for _, x := range out {
		switch x.Params["operation"] {
		case "mystery", "payout", "notify":
			t.Fatalf("test %s targets a non-runnable operation %s", x.ID, x.Params["operation"])
		}
	}
	if rep.SkippedByClass["unknown"] != 1 || rep.SkippedByClass["money"] != 1 || rep.SkippedByClass["notifying"] != 1 {
		t.Fatalf("report = %+v", rep.SkippedByClass)
	}
	if strings.Join(rep.SkippedOps, ",") != "mystery,notify,payout" {
		t.Fatalf("skipped ops = %v", rep.SkippedOps)
	}
	// Once the operator classifies the operation, it generates.
	for i := range m.Operations {
		if m.Operations[i].ID == "mystery" {
			m.Operations[i].Class = model.ClassRead
		}
	}
	out2, _, err := GenerateWithReport(m, toyFixture(), toyAccounts(), Options{Catalogue: emptyCat})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range out2 {
		found = found || x.Params["operation"] == "mystery"
	}
	if !found {
		t.Fatal("a classified operation must generate tests")
	}
}

// ---- ids ----

func TestIDHashCoversPropertyOpAndParams(t *testing.T) {
	a := testID("P-OWN-1", "getV1", map[string]string{"a": "1", "b": "2"})
	if a != testID("P-OWN-1", "getV1", map[string]string{"b": "2", "a": "1"}) {
		t.Fatal("id must not depend on map order")
	}
	for _, other := range []string{
		testID("P-OWN-2", "getV1", map[string]string{"a": "1", "b": "2"}),
		testID("P-OWN-1", "getV2", map[string]string{"a": "1", "b": "2"}),
		testID("P-OWN-1", "getV1", map[string]string{"a": "1", "b": "3"}),
	} {
		if other == a {
			t.Fatal("id must change with property, operation and params")
		}
	}
	if !strings.HasPrefix(a, "ALEEF-GEN-P-OWN-1-") || len(a) != len("ALEEF-GEN-P-OWN-1-")+8 {
		t.Fatalf("bad id %q", a)
	}
}

// ---- novelty ----

func TestGenerateMarksCoveredAgainstCatalogue(t *testing.T) {
	cat := []contract.Scenario{{
		ID: "API-BAS-AUTHZ-001", Claim: "cross_identity",
		Steps: []contract.Step{
			{Identity: "owner", Method: "GET", Path: "/api/v2/items/{object}"},
			{Identity: "other", Method: "GET", Path: "/api/v2/items/{object}"},
		},
	}}
	out := gen(t, Options{Catalogue: cat})
	var covered, fresh int
	for _, x := range out {
		if x.Covered {
			covered++
			if x.Scenario.Claim != "cross_identity" {
				t.Errorf("%s covered with claim %s", x.ID, x.Scenario.Claim)
			}
		} else {
			fresh++
		}
	}
	if covered == 0 || fresh == 0 {
		t.Fatalf("covered=%d fresh=%d", covered, fresh)
	}
}

func TestGenerateRejectsUnknownVariation(t *testing.T) {
	if _, err := Generate(toyModel(), toyFixture(), toyAccounts(), Options{Catalogue: emptyCat, Variations: []string{"nope"}}); err == nil {
		t.Fatal("unknown variation must error")
	}
}

// ---- variations ----

// varTests returns the variant tests produced by one variation.
func varTests(t *testing.T, name string) []Test {
	t.Helper()
	var out []Test
	for _, x := range gen(t, Options{Variations: []string{name}}) {
		if x.Params["variation"] == name {
			out = append(out, x)
		}
	}
	return out
}

func attack(x Test) contract.Step { return x.Scenario.Steps[len(x.Scenario.Steps)-1] }

func TestBaseOnlyWhenNoVariations(t *testing.T) {
	for _, x := range gen(t, Options{}) {
		if x.Params["variation"] != "" {
			t.Fatalf("unrequested variation %s", x.Params["variation"])
		}
	}
}

func TestVariationOtherAccountAddressesThirdObject(t *testing.T) {
	vs := varTests(t, VarOtherAccount)
	if len(vs) == 0 {
		t.Fatal("no variants")
	}
	objOf := map[string]string{"alice": "item-a1", "bob": "item-b1", "carol": "item-c1"}
	custOf := map[string]string{"alice": "cust-a", "bob": "cust-b", "carol": "cust-c"}
	for _, x := range vs {
		p := x.Params
		third := ""
		for n, o := range objOf {
			if o == p["other_object"] {
				third = n
			}
		}
		if third == "" || third == p["victim"] || third == p["attacker"] {
			t.Fatalf("%s: other object %q must belong to a third account (%v)", x.ID, p["other_object"], p)
		}
		a := attack(x)
		if !strings.Contains(a.Path, p["other_object"]) || strings.Contains(a.Path, "{object}") {
			t.Errorf("%s: attack path %s", x.ID, a.Path)
		}
		found := false
		for _, v := range x.Scenario.ForbiddenValues {
			found = found || v == custOf[third]
		}
		if !found {
			t.Errorf("%s: third owner's customer id missing from forbidden values %v", x.ID, x.Scenario.ForbiddenValues)
		}
	}
}

func TestVariationNeighbourAndStaleID(t *testing.T) {
	for name, want := range map[string]string{VarNeighbourID: "item-a2", VarStaleID: "item-a1-stale"} {
		vs := varTests(t, name)
		if len(vs) == 0 {
			t.Fatalf("%s: no variants", name)
		}
		hit := false
		for _, x := range vs {
			if strings.Contains(attack(x).Path, "{object}") {
				t.Errorf("%s: token not replaced in %s", name, attack(x).Path)
			}
			if x.Params["victim"] == "alice" && strings.Contains(attack(x).Path, want) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s: no attack path contains %q", name, want)
		}
	}
}

func TestVariationFieldLocationPollutesQuery(t *testing.T) {
	vs := varTests(t, VarFieldLocation)
	if len(vs) == 0 {
		t.Fatal("no variants")
	}
	for _, x := range vs {
		a := attack(x)
		if a.Method != "GET" || !strings.Contains(a.Path, "id={object}") || strings.Contains(strings.SplitN(a.Path, "?", 2)[0], "{object}") {
			t.Errorf("%s: attack = %s %s", x.ID, a.Method, a.Path)
		}
	}
}

func TestVariationMethodOverride(t *testing.T) {
	vs := varTests(t, VarMethodOverride)
	if len(vs) == 0 {
		t.Fatal("no variants")
	}
	seen := map[string]bool{}
	for _, x := range vs {
		a := attack(x)
		if a.Method != "POST" || a.Headers["X-HTTP-Method-Override"] == "" || strings.TrimSpace(a.Body) == "" {
			t.Errorf("%s: attack = %+v", x.ID, a)
		}
		seen[a.Headers["X-HTTP-Method-Override"]] = true
	}
	if !seen["PATCH"] || !seen["DELETE"] {
		t.Errorf("overrides seen: %v", seen)
	}
}

func TestVariationAPIVersion(t *testing.T) {
	vs := varTests(t, VarAPIVersion)
	if len(vs) == 0 {
		t.Fatal("no variants")
	}
	for _, x := range vs {
		a := attack(x)
		if x.Params["api_version"] == "" || !strings.Contains(a.Path, "/"+x.Params["api_version"]+"/") {
			t.Errorf("%s: path %s, version %s", x.ID, a.Path, x.Params["api_version"])
		}
		// Only versions the model serves for that method are tried: the
		// patch and delete operations exist in v2 only.
		if a.Method != "GET" {
			t.Errorf("%s: %s has no other version", x.ID, a.Method)
		}
	}
}

func TestVariationBoundaryValues(t *testing.T) {
	vs := varTests(t, VarBoundary)
	if len(vs) == 0 {
		t.Fatal("no variants")
	}
	seen := map[string]bool{}
	for _, x := range vs {
		var doc map[string]any
		dec := json.NewDecoder(strings.NewReader(attack(x).Body))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("%s: body %q: %v", x.ID, attack(x).Body, err)
		}
		seen[x.Params["boundary"]] = true
		if n, ok := doc["qty"].(json.Number); !ok || n.String() != boundaryValues[x.Params["boundary"]] {
			t.Errorf("%s: qty = %v for boundary %s", x.ID, doc["qty"], x.Params["boundary"])
		}
	}
	for _, k := range []string{"zero", "negative", "max", "rounding"} {
		if !seen[k] {
			t.Errorf("boundary %s not generated", k)
		}
	}
}

func TestVariationRepeatAndParallel(t *testing.T) {
	for name, parallel := range map[string]bool{VarRepeat: false, VarParallel: true} {
		vs := varTests(t, name)
		if len(vs) == 0 {
			t.Fatalf("%s: no variants", name)
		}
		for _, x := range vs {
			a := attack(x)
			if a.Repeat < 3 || a.Parallel != parallel || x.Scenario.MaxAcceptedAttempts != 1 {
				t.Errorf("%s: repeat=%d parallel=%v max=%d", x.ID, a.Repeat, a.Parallel, x.Scenario.MaxAcceptedAttempts)
			}
			if x.Template.Oracle != property.OracleRepeatAccepted || x.Template.RunnerLeakValid || x.Template.RunnerStateValid {
				t.Errorf("%s: oracle %s leak=%v state=%v", x.ID, x.Template.Oracle, x.Template.RunnerLeakValid, x.Template.RunnerStateValid)
			}
		}
	}
}

func threeStepTemplate() property.Template {
	mk := func(id, role string) contract.Step {
		return contract.Step{ID: id, Role: role, Identity: "alice", Method: "GET", Path: "/p", Hypothesis: "h"}
	}
	return property.Template{Steps: []contract.Step{mk("b", "baseline"), mk("s1", "setup"), mk("s2", "setup"), mk("a", "attack")}}
}

func TestReorderSetupSteps(t *testing.T) {
	tpl := threeStepTemplate()
	got, ok := reorderSteps(tpl)
	if !ok {
		t.Fatal("reorder refused")
	}
	if got.Steps[0].ID != "b" || got.Steps[1].ID != "s2" || got.Steps[2].ID != "s1" || got.Steps[3].ID != "a" {
		t.Fatalf("order = %v", got.Steps)
	}
	if tpl.Steps[1].ID != "s1" {
		t.Fatal("input mutated")
	}
	one := tpl
	one.Steps = []contract.Step{tpl.Steps[0], tpl.Steps[1], tpl.Steps[3]}
	if _, ok := reorderSteps(one); ok {
		t.Fatal("a single setup step cannot be reordered")
	}
	for _, x := range varTests(t, VarRequestOrder) {
		if len(x.Scenario.Steps) < 4 {
			t.Errorf("%s: fewer than two setup steps", x.ID)
		}
	}
}

func TestNeighbourID(t *testing.T) {
	for in, want := range map[string]string{"item-a1": "item-a2", "x9": "x10", "007": "008", "abc": "abc-1"} {
		if got := neighbourID(in); got != want {
			t.Errorf("neighbourID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGenerateLoadsEmbeddedCatalogueByDefault(t *testing.T) {
	out, err := Generate(toyModel(), toyFixture(), toyAccounts(), Options{})
	if err != nil || len(out) == 0 {
		t.Fatalf("%d tests, err %v", len(out), err)
	}
}

// ---- step safety ----

func flowModel(authzClass model.OpClass) model.Model {
	m := toyModel()
	m.Operations = append(m.Operations, mkOp("authz", "POST", "/api/v2/items/{id}/authorize", idP(),
		&model.Schema{Type: "object", Properties: map[string]*model.Schema{"comment": strS()}}, authzClass))
	return m
}

func flowOpts() Options {
	return Options{Catalogue: emptyCat, Workflow: &property.Workflow{Name: "approval", Steps: []property.WorkflowStep{
		{Op: "authz", Kind: property.StepAuthorize},
		{Op: "patchV2", Kind: property.StepModify},
	}}}
}

func hasProp(ts []Test, prop string) bool {
	for _, x := range ts {
		if x.Property == prop {
			return true
		}
	}
	return false
}

func TestGenerateDropsTestWhoseCoActorStepIsMoney(t *testing.T) {
	out, rep, err := GenerateWithReport(flowModel(model.ClassMoney), toyFixture(), toyAccounts(), flowOpts())
	if err != nil {
		t.Fatal(err)
	}
	if hasProp(out, "P-AUTH-2") {
		t.Fatal("a flow whose approval step is a money operation must not be emitted")
	}
	if rep.SkippedStepClass == 0 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestGenerateCleanWorkflowStillEmits(t *testing.T) {
	out, rep, err := GenerateWithReport(flowModel(model.ClassReversible), toyFixture(), toyAccounts(), flowOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !hasProp(out, "P-AUTH-2") {
		t.Fatalf("clean workflow produced no P-AUTH-2 test (report %+v)", rep)
	}
}

func TestGenerateDropsTestWhoseBaselineIsUnknownClass(t *testing.T) {
	m := model.Model{Operations: []model.Operation{
		mkOp("patchW", "PATCH", "/api/v3/widgets/{id}", idP(),
			&model.Schema{Type: "object", Properties: map[string]*model.Schema{"title": strS()}}, model.ClassReversible),
		mkOp("peekW", "GET", "/api/v3/widgets/{id}", idP(), nil, model.ClassUnknown),
	}}
	out, rep, err := GenerateWithReport(m, toyFixture(), toyAccounts(), Options{Catalogue: emptyCat})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("baseline on an unknown-class operation must drop the test, got %d tests", len(out))
	}
	if rep.SkippedStepClass == 0 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestStepBlock(t *testing.T) {
	m := toyModel()
	step := func(method, path string, hdr map[string]string) contract.Step {
		return contract.Step{Method: method, Path: path, Headers: hdr}
	}
	cases := []struct {
		name string
		st   contract.Step
		want string
	}{
		{"runnable", step("GET", "/api/v2/items/item-a1?x=1", nil), ""},
		{"token placeholder", step("PATCH", "/api/v2/items/{object}", nil), ""},
		{"unknown class", step("GET", "/api/v2/mystery/{object}", nil), blockedClass},
		{"money", step("PATCH", "/api/v2/payouts/p1", nil), blockedClass},
		{"no such path", step("GET", "/nowhere/{object}", nil), blockedUnknown},
		{"no such method", step("DELETE", "/api/v2/mystery/x", nil), blockedUnknown},
		{"override to runnable", step("POST", "/api/v2/items/i1", map[string]string{"X-HTTP-Method-Override": "PATCH"}), ""},
		{"override to money", step("POST", "/api/v2/payouts/i1", map[string]string{"X-HTTP-Method-Override": "PATCH"}), blockedClass},
	}
	for _, c := range cases {
		if got := stepBlock(m, []contract.Step{c.st}); got != c.want {
			t.Errorf("%s: stepBlock = %q, want %q", c.name, got, c.want)
		}
	}
}
