package generate

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
)

const twoResSpec = `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
 "/api/orders/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/invoices/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/shops/{shopId}/orders/{id}":{"get":{"parameters":[{"name":"shopId","in":"path","required":true,"schema":{"type":"string"}},{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
 "/api/widgets/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}
}}`

func twoResModel(t *testing.T) model.Model {
	t.Helper()
	m, err := model.Import([]byte(twoResSpec))
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Operations {
		m.Operations[i].Class = model.ClassRead
	}
	m.Roles = []string{"member"}
	return m
}

// twoResFixture: ids are chosen so that the OLD selection (lowest id of any
// kind per owner) would give alice and bob an invoice for every operation,
// including the order and shop-order reads.
func twoResFixture() (fixture.Fixture, []model.Account) {
	accts := []model.Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "ta", Role: "member"},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "tb", Role: "member"},
		{Name: "carol", CustomerID: "cust-c", TokenRef: "tc", Role: "member"},
	}
	f := fixture.Fixture{Name: "two"}
	for _, a := range accts {
		f.Identities = append(f.Identities, fixture.Identity{Name: a.Name, CustomerID: a.CustomerID, TokenRef: a.TokenRef, Role: a.Role})
	}
	add := func(id, owner, kind string) {
		f.Objects = append(f.Objects, fixture.Object{ID: id, OwnerID: owner, Kind: kind, Public: map[string]string{"confidence": "structural"}, Protected: map[string]string{}})
	}
	add("inv-a", "cust-a", "invoice")
	add("ord-a", "cust-a", "order")
	add("shop-a", "cust-a", "shop")
	add("inv-b", "cust-b", "invoice")
	add("ord-b", "cust-b", "order")
	add("shop-b", "cust-b", "shop")
	add("inv-c", "cust-c", "invoice")
	add("ord-c", "cust-c", "order")
	// carol has no shop and nobody has a widget
	return f, accts
}

var idPrefixOfCollection = map[string]string{"orders": "ord-", "invoices": "inv-", "shops": "shop-"}

// wrongResourceID plays the toy server that answers 404 for an id of the
// wrong resource type: it returns a description of every mismatched segment.
func wrongResourceID(t Test, steps []contract.Step) []string {
	var bad []string
	for _, st := range steps {
		path := strings.ReplaceAll(st.Path, "{object}", t.Scenario.Preconditions.Object)
		segs := strings.Split(strings.Trim(path, "/"), "/")
		for i := 1; i < len(segs); i++ {
			if want, ok := idPrefixOfCollection[segs[i-1]]; ok && !strings.HasPrefix(segs[i], want) {
				bad = append(bad, st.Method+" "+path)
			}
		}
	}
	return bad
}

func TestResourceAwareSelectionNeverSendsAWrongResourceID(t *testing.T) {
	m := twoResModel(t)
	fx, accts := twoResFixture()
	tests, rep, err := GenerateWithReport(m, fx, accts, Options{Seed: 1, Catalogue: emptyCat, Variations: AllVariations()})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("nothing generated")
	}
	perOp := map[string]int{}
	for _, x := range tests {
		perOp[x.Params["operation"]]++
		all := append([]contract.Step(nil), x.Scenario.Steps...)
		if x.OwnerControl != nil {
			all = append(all, x.OwnerControl.Scenario.Steps...)
		}
		if x.NegativeControl != nil {
			all = append(all, x.NegativeControl.Scenario.Steps...)
		}
		if bad := wrongResourceID(x, all); len(bad) > 0 {
			t.Fatalf("%s sent a wrong-resource id: %v", x.ID, bad)
		}
		for _, st := range all {
			if strings.Contains(st.Path+st.Body, "ALEEF_NO_OBJECT") {
				t.Fatalf("%s carries an unresolved marker", x.ID)
			}
		}
	}
	for _, op := range []string{"get_api_orders_by_id", "get_api_invoices_by_id", "get_api_shops_by_shopid_orders_by_id"} {
		if perOp[op] == 0 {
			t.Errorf("no tests for %s: %v", op, perOp)
		}
	}
	// the old behaviour: lowest id of any kind is the invoice
	if o, _ := property.OwnedObject(fx, accts[0], ""); o.ID != "inv-a" {
		t.Fatalf("test premise: lowest object is %s", o.ID)
	}
	// the order read must name the order object
	for _, x := range tests {
		if x.Params["operation"] == "get_api_orders_by_id" && !strings.HasPrefix(x.Scenario.Preconditions.Object, "ord-") {
			t.Fatalf("order test names %s", x.Scenario.Preconditions.Object)
		}
	}
	_ = rep
}

func TestMissingFixtureObjectsAreDroppedWithAReason(t *testing.T) {
	m := twoResModel(t)
	fx, accts := twoResFixture()
	_, rep, err := GenerateWithReport(m, fx, accts, Options{Seed: 1, Catalogue: emptyCat})
	if err != nil {
		t.Fatal(err)
	}
	if rep.NoFixtureOps["get_api_widgets_by_id"] != "widget" {
		t.Fatalf("operation-level skip missing: %v", rep.NoFixtureOps)
	}
	if got := NoFixtureReason("widget"); got != "no fixture object of resource type widget" {
		t.Fatalf("reason text: %q", got)
	}
	// carol has no shop, so tests of the shop-order read that need carol's shop are dropped and counted
	if rep.NoFixture["shop"] == 0 {
		t.Fatalf("expected dropped tests for the missing shop: %v", rep.NoFixture)
	}
}

func TestResourceSelectionIsDeterministic(t *testing.T) {
	m := twoResModel(t)
	fx, accts := twoResFixture()
	a, _, _ := GenerateWithReport(m, fx, accts, Options{Seed: 3, Catalogue: emptyCat, Variations: AllVariations()})
	b, _, _ := GenerateWithReport(m, fx, accts, Options{Seed: 3, Catalogue: emptyCat, Variations: AllVariations()})
	if len(a) != len(b) {
		t.Fatalf("%d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID || mustJSON(t, a[i].Scenario) != mustJSON(t, b[i].Scenario) {
			t.Fatalf("test %d differs", i)
		}
	}
}

func TestAllowedOpsLetAnEngagementPermittedClassRun(t *testing.T) {
	m := twoResModel(t)
	for i := range m.Operations {
		if m.Operations[i].ID == "get_api_invoices_by_id" {
			m.Operations[i].Class = model.ClassMoney
		}
	}
	fx, accts := twoResFixture()
	count := func(opt Options) int {
		n := 0
		tests, _, _ := GenerateWithReport(m, fx, accts, opt)
		for _, x := range tests {
			if x.Params["operation"] == "get_api_invoices_by_id" {
				n++
			}
		}
		return n
	}
	if count(Options{Seed: 1, Catalogue: emptyCat}) != 0 {
		t.Fatal("money operation generated by default")
	}
	if count(Options{Seed: 1, Catalogue: emptyCat, AllowedOps: map[string]bool{"get_api_invoices_by_id": true}}) == 0 {
		t.Fatal("explicitly allowed money operation not generated")
	}
}
