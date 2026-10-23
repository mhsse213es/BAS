package property

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/runner"
)

// ---- toy application ----
//
// A tiny multi-route "tracker" service used by every property test. Each test
// switches on one deliberate flaw by name; the zero-flaw server is the
// corrected variant. Flaws: read-v1, read-v2, write, query, body, header,
// soft, role, selfapprove, noauth, tamper, revive, status-lie, idem-ignore,
// idem-nobody, race.

type titem struct {
	ID, Owner, Title, Status string
	Amount                   int
}

type keyRec struct {
	hash, id string
}

type toy struct {
	mu     sync.Mutex
	items  map[string]*titem
	keys   map[string]keyRec
	flaws  map[string]bool
	seq    int
	tokens map[string][2]string // token -> customer, role
}

func newToy(flaws ...string) (*toy, *httptest.Server) {
	t := &toy{flaws: map[string]bool{}, tokens: map[string][2]string{
		"tok-alice": {"cust-a", "member"}, "tok-bob": {"cust-b", "member"},
		"tok-carol": {"cust-c", "checker"}, "tok-dave": {"cust-d", "admin"},
	}}
	for _, f := range flaws {
		t.flaws[f] = true
	}
	t.reset()
	return t, httptest.NewServer(t)
}

func (t *toy) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items = map[string]*titem{}
	t.keys = map[string]keyRec{}
	t.seq = 0
	for _, s := range []struct{ id, owner, who string }{{"item-a1", "cust-a", "alice"}, {"item-b1", "cust-b", "bob"}, {"item-c1", "cust-c", "carol"}, {"item-d1", "cust-d", "dave"}} {
		t.items[s.id] = &titem{ID: s.id, Owner: s.owner, Title: "ALEEF-CANARY-t-" + s.who, Status: "pending", Amount: 10}
	}
}

func (t *toy) Snapshot(context.Context) (map[string]runner.StateRecord, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]runner.StateRecord{}
	for id, it := range t.items {
		out[id] = runner.StateRecord{ID: id, OwnerID: it.Owner, Status: it.Status, Tag: it.Title, Quantity: fmt.Sprint(it.Amount)}
	}
	return out, nil
}

func (t *toy) Reset(context.Context) error { t.reset(); return nil }

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (t *toy) deny(w http.ResponseWriter) {
	if t.flaws["soft"] {
		reply(w, 200, map[string]any{"error": "forbidden"})
		return
	}
	reply(w, 403, map[string]any{"error": "forbidden"})
}

func view(it *titem) map[string]any {
	return map[string]any{"id": it.ID, "owner": it.Owner, "title": it.Title, "status": it.Status, "amount": it.Amount}
}

func (t *toy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	who, ok := t.tokens[tok]
	if !ok {
		reply(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	cust, role := who[0], who[1]
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	get := func(id string) (*titem, bool) {
		t.mu.Lock()
		defer t.mu.Unlock()
		it, ok := t.items[id]
		return it, ok
	}
	switch {
	// versioned item routes
	case len(p) == 4 && p[0] == "api" && p[2] == "items":
		ver, id := p[1], p[3]
		it, found := get(id)
		if !found {
			reply(w, 404, map[string]any{"error": "not found"})
			return
		}
		switch r.Method {
		case "GET":
			unchecked := (ver == "v1" && t.flaws["read-v1"]) || (ver == "v2" && t.flaws["read-v2"])
			if it.Owner != cust && !unchecked {
				t.deny(w)
				return
			}
			if h := r.Header.Get("X-Object-Id"); h != "" && t.flaws["header"] {
				if other, ok := get(h); ok {
					it = other
				}
			}
			t.mu.Lock()
			v := view(it)
			t.mu.Unlock()
			reply(w, 200, v)
		case "PATCH", "DELETE":
			if it.Owner != cust && !t.flaws["write"] {
				t.deny(w)
				return
			}
			t.mu.Lock()
			if r.Method == "DELETE" {
				delete(t.items, id)
			} else if s, ok := body["title"].(string); ok {
				it.Title = s
			}
			t.mu.Unlock()
			reply(w, 200, map[string]any{"ok": true})
		}
	// query-carried identifier
	case len(p) == 2 && p[1] == "items" && r.Method == "GET":
		it, found := get(r.URL.Query().Get("owner_ref"))
		if !found {
			reply(w, 404, map[string]any{"error": "not found"})
			return
		}
		if it.Owner != cust && !t.flaws["query"] {
			t.deny(w)
			return
		}
		t.mu.Lock()
		v := view(it)
		t.mu.Unlock()
		reply(w, 200, v)
	// body-carried (nested) identifier
	case len(p) == 2 && p[1] == "moves" && r.Method == "POST":
		tgt, _ := body["target"].(map[string]any)
		id, _ := tgt["item_id"].(string)
		it, found := get(id)
		if !found {
			reply(w, 404, map[string]any{"error": "not found"})
			return
		}
		if it.Owner != cust && !t.flaws["body"] {
			t.deny(w)
			return
		}
		t.mu.Lock()
		it.Status = "moved"
		t.mu.Unlock()
		reply(w, 200, map[string]any{"ok": true})
	case len(p) == 4 && p[2] == "admin" && p[3] == "reports" && r.Method == "GET":
		if role != "admin" && !t.flaws["role"] {
			t.deny(w)
			return
		}
		reply(w, 200, map[string]any{"report": "ok"})
	case len(p) == 3 && p[2] == "invoices" && r.Method == "POST":
		t.invoice(w, r, cust, raw, body)
	case len(p) == 5 && p[2] == "items":
		t.action(w, r, cust, role, p[3], p[4], body)
	default:
		reply(w, 404, map[string]any{"error": "no route"})
	}
}

func (t *toy) invoice(w http.ResponseWriter, r *http.Request, cust string, raw []byte, body map[string]any) {
	key := r.Header.Get("Idempotency-Key")
	h := sha1.Sum(raw)
	hash := hex.EncodeToString(h[:])
	t.mu.Lock()
	defer t.mu.Unlock()
	if key != "" && !t.flaws["idem-ignore"] {
		if rec, ok := t.keys[key]; ok {
			if rec.hash != hash && !t.flaws["idem-nobody"] {
				reply(w, 422, map[string]any{"error": "key reused with a different request"})
				return
			}
			if rec.hash == hash {
				reply(w, 200, map[string]any{"id": rec.id, "replayed": true})
				return
			}
		}
	}
	t.seq++
	id := fmt.Sprintf("inv-%d", t.seq)
	t.items[id] = &titem{ID: id, Owner: cust, Title: "invoice", Status: "open", Amount: 1}
	if key != "" {
		t.keys[key] = keyRec{hash: hash, id: id}
	}
	reply(w, 201, map[string]any{"id": id})
}

func (t *toy) action(w http.ResponseWriter, r *http.Request, cust, role, id, act string, body map[string]any) {
	t.mu.Lock()
	it, found := t.items[id]
	t.mu.Unlock()
	if !found {
		reply(w, 404, map[string]any{"error": "not found"})
		return
	}
	switch {
	case act == "authorize" && r.Method == "POST":
		if role != "checker" || (it.Owner == cust && !t.flaws["selfapprove"]) {
			t.deny(w)
			return
		}
		t.mu.Lock()
		it.Status = "authorized"
		t.mu.Unlock()
		reply(w, 200, map[string]any{"ok": true})
		return
	}
	if it.Owner != cust {
		t.deny(w)
		return
	}
	switch {
	case act == "execute" && r.Method == "POST":
		t.mu.Lock()
		okState := it.Status == "authorized" || t.flaws["noauth"] || (t.flaws["revive"] && it.Status == "reversed")
		if okState {
			it.Status = "executed"
		}
		t.mu.Unlock()
		if !okState {
			reply(w, 409, map[string]any{"error": "not authorized"})
			return
		}
		reply(w, 200, map[string]any{"ok": true})
	case act == "terms" && r.Method == "PATCH":
		t.mu.Lock()
		locked := it.Status == "authorized" && !t.flaws["tamper"]
		if !locked {
			if f, ok := body["amount"].(float64); ok {
				it.Amount = int(f)
			}
		}
		t.mu.Unlock()
		if locked {
			reply(w, 409, map[string]any{"error": "authorized items are immutable"})
			return
		}
		reply(w, 200, map[string]any{"ok": true})
	case act == "reverse" && r.Method == "POST":
		t.mu.Lock()
		it.Status = "reversed"
		t.mu.Unlock()
		reply(w, 200, map[string]any{"ok": true})
	case act == "archive" && r.Method == "POST":
		if role != "admin" && !t.flaws["role"] {
			t.deny(w)
			return
		}
		t.mu.Lock()
		it.Status = "archived"
		t.mu.Unlock()
		reply(w, 200, map[string]any{"ok": true})
	case act == "redeem" && r.Method == "POST":
		t.redeem(w, it)
	default:
		reply(w, 404, map[string]any{"error": "no route"})
	}
}

// redeem is a once-only action. The flawed variant checks, sleeps, then acts
// (check-then-act race); the corrected one holds the lock throughout.
func (t *toy) redeem(w http.ResponseWriter, it *titem) {
	if t.flaws["race"] {
		t.mu.Lock()
		done := it.Status == "redeemed"
		t.mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		if done {
			reply(w, 409, map[string]any{"error": "already redeemed"})
			return
		}
		t.mu.Lock()
		it.Status = "redeemed"
		t.mu.Unlock()
		reply(w, 200, map[string]any{"ok": true})
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if it.Status == "redeemed" {
		reply(w, 409, map[string]any{"error": "already redeemed"})
		return
	}
	it.Status = "redeemed"
	reply(w, 200, map[string]any{"ok": true})
}

// ---- fixture, accounts, model ----

type secretMap map[string]string

func (s secretMap) Resolve(ref string) (string, error) {
	if v, ok := s[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no secret")
}

func toyAccounts() []model.Account {
	return []model.Account{
		{Name: "alice", CustomerID: "cust-a", TokenRef: "tok-alice", Role: "member"},
		{Name: "bob", CustomerID: "cust-b", TokenRef: "tok-bob", Role: "member"},
		{Name: "carol", CustomerID: "cust-c", TokenRef: "tok-carol", Role: "checker"},
		{Name: "dave", CustomerID: "cust-d", TokenRef: "tok-dave", Role: "admin"},
	}
}

func toyFixture() fixture.Fixture {
	f := fixture.Fixture{Name: "toy"}
	objs := map[string]string{"alice": "item-a1", "bob": "item-b1", "carol": "item-c1", "dave": "item-d1"}
	for _, a := range toyAccounts() {
		f.Identities = append(f.Identities, fixture.Identity{Name: a.Name, CustomerID: a.CustomerID, TokenRef: a.TokenRef, Role: a.Role})
		f.Objects = append(f.Objects, fixture.Object{
			ID: objs[a.Name], OwnerID: a.CustomerID, Status: "pending",
			Public: map[string]string{}, Protected: map[string]string{"canary": "ALEEF-CANARY-t-" + a.Name},
		})
	}
	return f
}

func idParam() model.Param {
	return model.Param{Name: "id", In: "path", IsObjectID: true, Required: true, Schema: &model.Schema{Type: "string"}}
}

func str() *model.Schema { return &model.Schema{Type: "string"} }

func op(id, method, path string, pp []model.Param, body *model.Schema, class model.OpClass) model.Operation {
	return model.Operation{ID: id, Method: method, Path: path, PathParams: pp, Body: body, Class: class}
}

func toyModel() model.Model {
	idp := []model.Param{idParam()}
	return model.Model{
		Roles: []string{"member", "checker", "admin"},
		Operations: []model.Operation{
			op("getV1", "GET", "/api/v1/items/{id}", idp, nil, model.ClassRead),
			op("getV2", "GET", "/api/v2/items/{id}", idp, nil, model.ClassRead),
			op("patchV2", "PATCH", "/api/v2/items/{id}", idp, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"title": str()}}, model.ClassReversible),
			op("deleteV2", "DELETE", "/api/v2/items/{id}", idp, nil, model.ClassReversible),
			{ID: "listQ", Method: "GET", Path: "/api/items", Class: model.ClassRead,
				QueryParams: []model.Param{{Name: "owner_ref", In: "query", IsObjectID: true, Required: true, Schema: str()}}},
			op("move", "POST", "/api/moves", nil, &model.Schema{Type: "object", Properties: map[string]*model.Schema{
				"note": str(), "target": {Type: "object", Properties: map[string]*model.Schema{"item_id": str()}}}}, model.ClassReversible),
			op("reports", "GET", "/api/v2/admin/reports", nil, nil, model.ClassRead),
			op("archive", "POST", "/api/v2/items/{id}/archive", idp, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"reason": str()}}, model.ClassReversible),
			op("authorize", "POST", "/api/v2/items/{id}/authorize", idp, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"comment": str()}}, model.ClassReversible),
			op("execute", "POST", "/api/v2/items/{id}/execute", idp, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"comment": str()}}, model.ClassMoney),
			op("terms", "PATCH", "/api/v2/items/{id}/terms", idp, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"amount": {Type: "integer"}}}, model.ClassReversible),
			op("reverse", "POST", "/api/v2/items/{id}/reverse", idp, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"comment": str()}}, model.ClassReversible),
			op("redeem", "POST", "/api/v2/items/{id}/redeem", idp, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"comment": str()}}, model.ClassMoney),
			op("invoice", "POST", "/api/v2/invoices", nil, &model.Schema{Type: "object", Properties: map[string]*model.Schema{"amount": {Type: "integer"}, "label": str()}}, model.ClassSetupSafe),
		},
	}
}

func modelOp(t *testing.T, m model.Model, id string) model.Operation {
	t.Helper()
	o, ok := opByID(m, id)
	if !ok {
		t.Fatalf("op %s not in toy model", id)
	}
	return o
}

func toyCtx(t *testing.T, opID string) TemplateCtx {
	m := toyModel()
	return TemplateCtx{Op: modelOp(t, m, opID), Model: m, Fixture: toyFixture(), Identities: toyAccounts()}
}

func toyWorkflow() *Workflow {
	return &Workflow{Name: "approval", SuccessValues: []string{"completed"}, Steps: []WorkflowStep{
		{Op: "authorize", Kind: StepAuthorize, Role: "checker"},
		{Op: "terms", Kind: StepModify},
		{Op: "execute", Kind: StepExecute},
		{Op: "reverse", Kind: StepReverse},
		{Op: "getV2", Kind: StepRead},
	}}
}

// ---- template -> scenario -> runner ----

var scenarioSeq = 0

// toScenario is a test-only assembler (Task 7 owns the real one). It gives
// the template a catalogue-valid id and validates it with the real contract.
func toScenario(t *testing.T, tpl Template, category string) contract.Scenario {
	t.Helper()
	scenarioSeq++
	s := contract.Scenario{
		ID:                  fmt.Sprintf("API-BAS-%s-%03d", category, 900+scenarioSeq%99),
		Name:                tpl.Property + " " + tpl.Description,
		Category:            category,
		Claim:               tpl.Claim,
		AttackObjective:     tpl.Description,
		ThreatModel:         contract.ThreatModel{Objective: tpl.Description},
		Preconditions:       tpl.Preconditions,
		Steps:               tpl.Steps,
		DeniedStatuses:      tpl.DeniedStatuses,
		ForbiddenValues:     tpl.ForbiddenValues,
		CleanIsEnforced:     tpl.CleanIsEnforced,
		MaxAcceptedAttempts: tpl.MaxAccepted,
		ExpectedControl:     "The control refuses the attack.",
		GroundTruth:         contract.GroundTruth{Adapters: []string{"state", "response"}},
		DetectionAssert:     contract.DetectionAssertion{Status: "not_evaluated", Reason: "test"},
		SideEffectClass:     tpl.SideEffect,
	}
	if tpl.SideEffect == "STATE_CHANGE_SANDBOX" {
		s.Cleanup = []string{"reset"}
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("template does not validate as a scenario: %v\n%+v", err, tpl)
	}
	return s
}

func category(prop string) string {
	if strings.HasPrefix(prop, "P-OWN") || strings.HasPrefix(prop, "P-ROLE") {
		return "AUTHZ"
	}
	return "BIZ"
}

// run executes a template against a toy server and returns the report.
func run(t *testing.T, ty *toy, srv *httptest.Server, tpl Template) runner.Report {
	t.Helper()
	r, err := runner.New(runner.Config{
		BaseURL: srv.URL, Fixture: toyFixture(), State: ty, Reset: ty,
		Secrets: secretMap{"tok-alice": "tok-alice", "tok-bob": "tok-bob", "tok-carol": "tok-carol", "tok-dave": "tok-dave"},
		HTTP:    &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	ty.reset()
	rep, err := r.Run(context.Background(), toScenario(t, tpl, category(tpl.Property)))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// expect runs every template and asserts all have the wanted result.
func expect(t *testing.T, ty *toy, srv *httptest.Server, tpls []Template, want grade.Result) {
	t.Helper()
	if len(tpls) == 0 {
		t.Fatal("no templates generated")
	}
	for _, tpl := range tpls {
		rep := run(t, ty, srv, tpl)
		if rep.Outcome.Result != want {
			t.Errorf("%s [%s]: got %s/%s (%s %s), want %s\nsteps: %+v\nexchanges: %+v",
				tpl.Property, tpl.Params["location"], rep.Outcome.Result, rep.Outcome.Exploitability,
				rep.Outcome.Reason, rep.Detail, want, tpl.Steps, rep.Exchanges)
		}
	}
}

// templatesFor generates templates of one property for one toy operation.
func templatesFor(t *testing.T, propID, opID string, mod func(*TemplateCtx)) []Template {
	t.Helper()
	ctx := toyCtx(t, opID)
	if mod != nil {
		mod(&ctx)
	}
	for _, p := range All() {
		if p.ID() == propID {
			return p.Templates(ctx)
		}
	}
	t.Fatalf("property %s not found", propID)
	return nil
}
