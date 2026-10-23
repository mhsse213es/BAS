package property

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/grade"
)

func TestOwnTemplatesDetectToyBOLA(t *testing.T) {
	// P-OWN-1: read of another account's object.
	ty, srv := newToy("read-v2")
	defer srv.Close()
	tpls := templatesFor(t, "P-OWN-1", "getV2", nil)
	expect(t, ty, srv, tpls, grade.FAIL)
	// The leak is evidence-backed by the canary.
	if rep := run(t, ty, srv, tpls[0]); rep.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("want exploited, got %+v", rep.Outcome)
	}

	// P-OWN-2: modify and delete of another account's object.
	ty2, srv2 := newToy("write")
	defer srv2.Close()
	for _, id := range []string{"patchV2", "deleteV2"} {
		expect(t, ty2, srv2, templatesFor(t, "P-OWN-2", id, nil), grade.FAIL)
	}

	// Corrected toy: every template passes.
	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, templatesFor(t, "P-OWN-1", "getV2", nil), grade.PASS)
	for _, id := range []string{"patchV2", "deleteV2"} {
		expect(t, ok, srvOK, templatesFor(t, "P-OWN-2", id, nil), grade.PASS)
	}
}

func TestOwnTemplatesCoverBodyQueryHeaderIDs(t *testing.T) {
	cases := []struct {
		flaw, op, location string
	}{
		{"query", "listQ", "query:owner_ref"},
		{"body", "move", "body:target.item_id"},
		{"header", "getV2", "header:X-Object-Id"},
	}
	for _, c := range cases {
		t.Run(c.location, func(t *testing.T) {
			tpls := templatesFor(t, "P-OWN-3", c.op, nil)
			var sel []Template
			for _, tp := range tpls {
				if tp.Params["location"] == c.location {
					sel = append(sel, tp)
				}
			}
			if len(sel) == 0 {
				t.Fatalf("no template for location %s among %d", c.location, len(tpls))
			}
			ty, srv := newToy(c.flaw)
			defer srv.Close()
			expect(t, ty, srv, sel, grade.FAIL)
			ok, srvOK := newToy()
			defer srvOK.Close()
			expect(t, ok, srvOK, sel, grade.PASS)
		})
	}
}

func TestOwnTemplatesAreDeterministicAndScoped(t *testing.T) {
	a := templatesFor(t, "P-OWN-3", "getV2", nil)
	b := templatesFor(t, "P-OWN-3", "getV2", nil)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("unstable template count %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Description != b[i].Description || a[i].Params["location"] != b[i].Params["location"] {
			t.Fatalf("template %d differs between runs", i)
		}
	}
	// P-OWN-1 does not apply to writes; P-OWN-2 not to reads; PUT never.
	all := map[string]Property{}
	for _, p := range All() {
		all[p.ID()] = p
	}
	m := toyModel()
	if all["P-OWN-1"].Applies(modelOp(t, m, "patchV2"), m) || all["P-OWN-2"].Applies(modelOp(t, m, "getV2"), m) {
		t.Fatal("method scoping broken")
	}
	put := modelOp(t, m, "patchV2")
	put.Method = "PUT"
	if all["P-OWN-2"].Applies(put, m) || all["P-OWN-3"].Applies(put, m) {
		t.Fatal("PUT must not apply: the contract cannot express it")
	}
	// Every cross-identity template names a different attacker and owner.
	for _, tp := range a {
		if tp.Claim != "cross_identity" || tp.Steps[0].Identity == tp.Steps[len(tp.Steps)-1].Identity {
			t.Fatalf("bad identities in %+v", tp)
		}
		if tp.Steps[0].Role != "baseline" || tp.Steps[len(tp.Steps)-1].Role != "attack" {
			t.Fatalf("bad step roles in %+v", tp)
		}
	}
}

func TestOwnSoftFailureIsNotAFinding(t *testing.T) {
	// A corrected app that refuses with HTTP 200 and an error body must not be
	// reported as exploited. The runner grades it inconclusive, and the
	// template's Denied helper classifies the exchange as a refusal.
	ty, srv := newToy("soft")
	defer srv.Close()
	tpls := templatesFor(t, "P-OWN-1", "getV2", nil)
	for _, tp := range tpls {
		rep := run(t, ty, srv, tp)
		if rep.Outcome.Result == grade.FAIL {
			t.Fatalf("soft failure graded as exploited: %+v", rep.Outcome)
		}
		atk := rep.Exchanges[len(rep.Exchanges)-1]
		if !tp.Denied(atk.Status, []byte(atk.Body)) {
			t.Fatalf("soft failure not classified as denied: %d %s", atk.Status, atk.Body)
		}
	}
}

func TestSoftFailureRule(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{200, `{"error":"nope"}`, true},
		{200, `{"status":"error"}`, true},
		{201, `{"status":"ERROR","x":1}`, true},
		{200, `{"success":false}`, true},
		{200, `{"success":true}`, false},
		{200, `{"error":null}`, false},
		{200, `{"id":"1"}`, false},
		{200, `not json`, false},
		{200, `[1,2]`, false},
		{403, `{"error":"x"}`, false},
	}
	for _, c := range cases {
		if got := IsSoftFailure(c.status, []byte(c.body)); got != c.want {
			t.Errorf("IsSoftFailure(%d,%s)=%v want %v", c.status, c.body, got, c.want)
		}
	}
	tpl := Template{DeniedStatuses: []int{403}, SoftFailure: true}
	if !tpl.Denied(403, nil) || !tpl.Denied(200, []byte(`{"error":"x"}`)) || tpl.Denied(200, []byte(`{"ok":1}`)) {
		t.Fatal("Template.Denied wrong")
	}
	if (Template{DeniedStatuses: []int{403}}).Denied(200, []byte(`{"error":"x"}`)) {
		t.Fatal("soft failure must only count when the template opts in")
	}
}

func TestOwn3MassAssignmentFillsPrincipalFieldsWithOwner(t *testing.T) {
	tpls := templatesFor(t, "P-OWN-3", "patchV2", nil)
	if len(tpls) == 0 {
		t.Fatal("no templates")
	}
	for _, tp := range tpls {
		atk := tp.Steps[len(tp.Steps)-1]
		var body map[string]any
		if err := json.Unmarshal([]byte(atk.Body), &body); err != nil {
			t.Fatal(err)
		}
		// The principal field carries the victim's customer id (never an
		// item id); the path carries the object token.
		if body["owner_id"] != "cust-"+ownerSuffix(tp.Params["victim"]) {
			t.Fatalf("owner_id = %v for victim %s", body["owner_id"], tp.Params["victim"])
		}
		if !strings.Contains(atk.Path, objToken) {
			t.Fatalf("path must name the victim's object: %s", atk.Path)
		}
	}
	ty, srv := newToy("mass-owner")
	defer srv.Close()
	expect(t, ty, srv, tpls, grade.FAIL)
	ok, srvOK := newToy()
	defer srvOK.Close()
	expect(t, ok, srvOK, tpls, grade.PASS)
}

func ownerSuffix(victim string) string {
	return map[string]string{"alice": "a", "bob": "b", "carol": "c", "dave": "d"}[victim]
}
