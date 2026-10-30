package safety

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/targetscope"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

const uatOrigin = "https://uat.bank.example:8443"

func uatEngagement() Engagement {
	return Engagement{
		ID: "eng-1", Customer: "Example Bank", Environment: "uat",
		Hosts:     []string{uatOrigin},
		Approver:  "ciso@bank.example",
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour),
		MaxRequests: 100, MaxConcurrent: 2, RPS: 50,
	}
}

func uatScope() *targetscope.TargetScopeImport {
	return &targetscope.TargetScopeImport{SourceType: "manual",
		AuthorizedTargets: []targetscope.AuthorizedTarget{{Host: "uat.bank.example"}}}
}

func TestAuthorizeAcceptsUAT(t *testing.T) {
	if err := uatEngagement().Authorize(uatOrigin, uatScope(), t0); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeRefusesProduction(t *testing.T) {
	for _, env := range []string{"production", "prod", "", "staging", "PRODUCTION"} {
		e := uatEngagement()
		e.Environment = env
		if err := e.Authorize(uatOrigin, uatScope(), t0); err == nil {
			t.Fatalf("environment %q accepted", env)
		}
	}
}

func TestAuthorizeRefusesExpiredWindow(t *testing.T) {
	e := uatEngagement()
	if err := e.Authorize(uatOrigin, uatScope(), e.NotAfter); err == nil {
		t.Fatal("window end is exclusive")
	}
	if err := e.Authorize(uatOrigin, uatScope(), e.NotAfter.Add(time.Second)); !errors.Is(err, ErrOutsideWindow) {
		t.Fatalf("got %v", err)
	}
}

func TestAuthorizeRefusesNotYetValid(t *testing.T) {
	e := uatEngagement()
	if err := e.Authorize(uatOrigin, uatScope(), e.NotBefore.Add(-time.Second)); !errors.Is(err, ErrOutsideWindow) {
		t.Fatalf("got %v", err)
	}
}

func TestAuthorizeRefusesUnlistedHost(t *testing.T) {
	e := uatEngagement()
	for _, o := range []string{
		"https://evil.example:8443", "https://uat.bank.example", "http://uat.bank.example:8443",
		"https://uat.bank.example:9443", "https://uat.bank.example:8443@evil.example", "https://listed@uat.bank.example:8443",
		"", "uat.bank.example:8443",
	} {
		if err := e.Authorize(o, uatScope(), t0); err == nil {
			t.Fatalf("origin %q accepted", o)
		}
	}
	// host listed in the engagement but not in the target scope
	sc := &targetscope.TargetScopeImport{AuthorizedTargets: []targetscope.AuthorizedTarget{{Host: "other.example"}}}
	if err := e.Authorize(uatOrigin, sc, t0); err == nil {
		t.Fatal("host outside target scope accepted")
	}
}

func TestAuthorizeCaseInsensitiveHost(t *testing.T) {
	e := uatEngagement()
	if err := e.Authorize("https://UAT.Bank.Example:8443", uatScope(), t0); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeRefusesLongWindow(t *testing.T) {
	e := uatEngagement()
	e.NotAfter = e.NotBefore.Add(31 * 24 * time.Hour)
	if err := e.Authorize(uatOrigin, uatScope(), t0); err == nil {
		t.Fatal("31 day window accepted")
	}
	e.NotAfter = e.NotBefore
	if err := e.Authorize(uatOrigin, uatScope(), t0); err == nil {
		t.Fatal("empty window accepted")
	}
}

func TestAuthorizeRefusesMissingApprover(t *testing.T) {
	e := uatEngagement()
	e.Approver = "  "
	if err := e.Authorize(uatOrigin, uatScope(), t0); err == nil {
		t.Fatal("missing approver accepted")
	}
}

func TestAuthorizeUATRequiresScope(t *testing.T) {
	if err := uatEngagement().Authorize(uatOrigin, nil, t0); err == nil {
		t.Fatal("UAT without a target scope accepted")
	}
}

func TestAuthorizeAcceptsLabLoopback(t *testing.T) {
	e := uatEngagement()
	e.Environment = "lab"
	e.Hosts = []string{"http://127.0.0.1:5555"}
	if err := e.Authorize("http://127.0.0.1:5555", nil, t0); err != nil {
		t.Fatal(err)
	}
	// lab without scope is still refused for a non-loopback host
	e.Hosts = []string{uatOrigin}
	if err := e.Authorize(uatOrigin, nil, t0); err == nil {
		t.Fatal("lab non-loopback host without scope accepted")
	}
	// a scope, when given, is always enforced
	e.Hosts = []string{"http://127.0.0.1:5555"}
	sc := &targetscope.TargetScopeImport{AuthorizedTargets: []targetscope.AuthorizedTarget{{Host: "other.example"}}}
	if err := e.Authorize("http://127.0.0.1:5555", sc, t0); err == nil {
		t.Fatal("scope not enforced for lab")
	}
}

func TestEngagementValidationRefusesBadLimitsAndHosts(t *testing.T) {
	cases := map[string]func(*Engagement){
		"no hosts":       func(e *Engagement) { e.Hosts = nil },
		"host with path": func(e *Engagement) { e.Hosts = []string{uatOrigin + "/api"} },
		"host userinfo":  func(e *Engagement) { e.Hosts = []string{"https://a@uat.bank.example:8443"} },
		"ftp host":       func(e *Engagement) { e.Hosts = []string{"ftp://uat.bank.example"} },
		"no budget":      func(e *Engagement) { e.MaxRequests = 0 },
		"no concurrency": func(e *Engagement) { e.MaxConcurrent = 0 },
		"no rate":        func(e *Engagement) { e.RPS = 0 },
		"no customer":    func(e *Engagement) { e.Customer = "" },
	}
	for name, mut := range cases {
		e := uatEngagement()
		mut(&e)
		if err := e.Authorize(uatOrigin, uatScope(), t0); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestParseRoundTripAndValidation(t *testing.T) {
	e := uatEngagement()
	b, err := e.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != e.ID || got.Hosts[0] != e.Hosts[0] || !got.NotAfter.Equal(e.NotAfter) {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if _, err := Parse([]byte(strings.Replace(string(b), `"uat"`, `"production"`, 1))); err == nil {
		t.Fatal("production parsed")
	}
	if _, err := Parse([]byte(`{"id":"x","bogus":1}`)); err == nil {
		t.Fatal("unknown field parsed")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("garbage parsed")
	}
}

// ---- classes ----

func TestFromOpClass(t *testing.T) {
	cases := map[model.OpClass]Class{
		model.ClassRead: ClassRead, model.ClassSetupSafe: ClassSetupSafe, model.ClassReversible: ClassReversible,
		model.ClassMoney: ClassMoney, model.ClassNotifying: ClassNotifying, model.ClassUnknown: ClassUnknown,
		"": ClassUnknown, "weird": ClassUnknown,
	}
	for in, want := range cases {
		if got := FromOpClass(in); got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestMoneyMovementRefusedWithoutSimulatedRail(t *testing.T) {
	e := uatEngagement()
	e.Operations = []string{"POST /pay"}
	e.SimulatorBeneficiaries = []string{"SIM-1"}
	e.SimulatedRail = false
	if err := Allow(ClassMoney, model.Operation{ID: "pay", Method: "POST", Path: "/pay"}, e); !errors.Is(err, ErrClassRefused) {
		t.Fatalf("got %v", err)
	}
	e.SimulatedRail = true
	if err := Allow(ClassMoney, model.Operation{ID: "pay", Method: "POST", Path: "/pay"}, e); err != nil {
		t.Fatal(err)
	}
	e.SimulatorBeneficiaries = nil
	if err := Allow(ClassMoney, model.Operation{ID: "pay", Method: "POST", Path: "/pay"}, e); err == nil {
		t.Fatal("money allowed without simulator beneficiaries")
	}
}

func TestMoneyRefusedUnlessOperationListed(t *testing.T) {
	e := uatEngagement()
	e.SimulatedRail = true
	e.SimulatorBeneficiaries = []string{"SIM-1"}
	if err := Allow(ClassMoney, model.Operation{ID: "pay", Method: "POST", Path: "/pay"}, e); err == nil {
		t.Fatal("money allowed with empty allowlist")
	}
	e.Operations = []string{"POST /other"}
	if err := Allow(ClassMoney, model.Operation{ID: "pay", Method: "POST", Path: "/pay"}, e); err == nil {
		t.Fatal("money allowed for unlisted op")
	}
}

func TestUnknownClassNeverRuns(t *testing.T) {
	e := uatEngagement()
	e.SimulatedRail = true
	e.SimulatorBeneficiaries = []string{"x"}
	e.TestRecipients = []string{"x"}
	e.Operations = []string{"POST /op"}
	for _, c := range []Class{ClassUnknown, "", "nonsense"} {
		if err := Allow(c, model.Operation{ID: "op", Method: "POST", Path: "/op"}, e); err == nil {
			t.Fatalf("class %q allowed", c)
		}
	}
}

func TestNotifyingOnlyWithRecipientsAndListed(t *testing.T) {
	e := uatEngagement()
	op := model.Operation{ID: "sms", Method: "POST", Path: "/sms"}
	if err := Allow(ClassNotifying, op, e); err == nil {
		t.Fatal("notifying allowed without recipients")
	}
	e.TestRecipients = []string{"qa@bank.example"}
	if err := Allow(ClassNotifying, op, e); err == nil {
		t.Fatal("notifying allowed when unlisted")
	}
	e.Operations = []string{"POST /sms"}
	if err := Allow(ClassNotifying, op, e); err != nil {
		t.Fatal(err)
	}
}

func TestAllowReadSetupReversibleAndAllowlist(t *testing.T) {
	e := uatEngagement()
	for _, c := range []Class{ClassRead, ClassSetupSafe, ClassReversible} {
		if err := Allow(c, model.Operation{ID: "a", Method: "GET", Path: "/a"}, e); err != nil {
			t.Fatalf("%s: %v", c, err)
		}
	}
	e.Operations = []string{"GET /b"}
	for _, c := range []Class{ClassRead, ClassSetupSafe, ClassReversible} {
		if err := Allow(c, model.Operation{ID: "a", Method: "GET", Path: "/a"}, e); err == nil {
			t.Fatalf("%s allowed outside non-empty allowlist", c)
		}
		if err := Allow(c, model.Operation{ID: "b", Method: "GET", Path: "/b"}, e); err != nil {
			t.Fatalf("%s: %v", c, err)
		}
	}
}

func TestParseValidatesClassesAndTokenRefs(t *testing.T) {
	base := `{"customer":"c","environment":"lab","hosts":["http://127.0.0.1:1"],"approver":"user:1",
		"notBefore":"2026-10-23T00:00:00Z","notAfter":"2026-10-24T00:00:00Z","maxRequests":10,"maxConcurrent":1,"rps":1,
		"classes":%s,"tokenRefs":["a/b"]}`
	good := strings.Replace(base, "%s", `{"GET /items/{id}":"read","post /pay":"money","GET /x":"unknown"}`, 1)
	e, err := Parse([]byte(good))
	if err != nil || e.Classes["POST /pay"] != "money" || e.Classes["GET /items/{}"] != "read" || len(e.TokenRefs) != 1 {
		t.Fatalf("good engagement: %+v %v", e, err)
	}
	for _, bad := range []string{`{"GET /a":"readonly"}`, `{"GET /a":"READ"}`, `{"GET /a":""}`, `{"":"read"}`,
		`{"getItem":"read"}`, `{"GET /a/{id}":"read","GET /a/{other}":"money"}`, `{"GET /a//b":"read"}`, `{"GET /a?x=1":"read"}`} {
		if _, err := Parse([]byte(strings.Replace(base, "%s", bad, 1))); !errors.Is(err, ErrInvalidEngagement) {
			t.Fatalf("classes %s accepted: %v", bad, err)
		}
	}
}

func TestAtLeastAsRestrictive(t *testing.T) {
	order := []Class{ClassRead, ClassSetupSafe, ClassReversible, ClassNotifying, ClassMoney, ClassUnknown}
	for i, ceiling := range order {
		for j, requested := range order {
			if got := AtLeastAsRestrictive(requested, ceiling); got != (j >= i) {
				t.Fatalf("requested %s ceiling %s: %v", requested, ceiling, got)
			}
		}
	}
}

func TestParseCanonicalisesAndValidatesOperations(t *testing.T) {
	mk := func(ops string) string {
		return `{"customer":"c","environment":"lab","hosts":["http://127.0.0.1:1"],"approver":"user:1",
		"notBefore":"2026-10-23T00:00:00Z","notAfter":"2026-10-24T00:00:00Z","maxRequests":10,"maxConcurrent":1,"rps":1,"operations":` + ops + `}`
	}
	e, err := Parse([]byte(mk(`["post /pay/{paymentId}","POST /pay/{id}"]`)))
	if err != nil || len(e.Operations) != 1 || e.Operations[0] != "POST /pay/{}" {
		t.Fatalf("operations %v %v", e.Operations, err)
	}
	for _, bad := range []string{`["pay"]`, `["POST"]`, `["POST /a//b"]`} {
		if _, err := Parse([]byte(mk(bad))); !errors.Is(err, ErrInvalidEngagement) {
			t.Fatalf("operations %s accepted: %v", bad, err)
		}
	}
}

// An analyst controls the operation ids in the document under test. Renaming an operation to an id
// that sounds listed gains nothing; only the signature (method + path) is looked up.
func TestAllowUsesTheSignatureNotTheOperationID(t *testing.T) {
	e := uatEngagement()
	e.SimulatedRail = true
	e.SimulatorBeneficiaries = []string{"SIM-1"}
	e.Operations = []string{"POST /pay", "pay"}
	other := model.Operation{ID: "pay", Method: "POST", Path: "/settle"} // id equals a listed string
	if err := Allow(ClassMoney, other, e); err == nil {
		t.Fatal("an operation gained money permission by taking a listed id")
	}
	listed := model.Operation{ID: "anything", Method: "POST", Path: "/pay"}
	if err := Allow(ClassMoney, listed, e); err != nil {
		t.Fatalf("the listed signature was refused: %v", err)
	}
	// param names do not matter, the template does
	e.Operations = []string{"POST /pay/{}"}
	if err := Allow(ClassMoney, model.Operation{ID: "x", Method: "POST", Path: "/pay/{paymentId}"}, e); err != nil {
		t.Fatalf("param-name variation refused: %v", err)
	}
	// an operation with no valid signature never runs
	if err := Allow(ClassRead, model.Operation{ID: "x", Method: "GET", Path: "no-slash"}, e); err == nil {
		t.Fatal("operation without a valid signature allowed")
	}
}
