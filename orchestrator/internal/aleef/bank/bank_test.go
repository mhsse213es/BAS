package bank

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

type env struct {
	t   *testing.T
	srv *Server
	ts  *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	s, err := New(Config{Policy: FixedPolicy(), Tokens: map[string]Principal{
		"tok-a":  {ID: "alice", Role: RoleCustomer},
		"tok-b":  {ID: "bob", Role: RoleCustomer},
		"tok-c1": {ID: "check1", Role: RoleApprover},
		"tok-c2": {ID: "check2", Role: RoleApprover},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, srv: s, ts: ts}
}

func (e *env) do(method, path, tok string, body any, hdr map[string]string) (int, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func denied(code int) bool { return code == 403 || code == 404 }

func (e *env) mustID(code int, m map[string]any, want int) string {
	e.t.Helper()
	if code != want {
		e.t.Fatalf("status %d want %d body %v", code, want, m)
	}
	id, _ := m["id"].(string)
	return id
}

func TestFixedBankEnforcesAllProperties(t *testing.T) {
	e := newEnv(t)
	acct := e.srv.AddAccount("alice", 1000)
	doc := e.srv.AddDocument("alice", "passport")

	// Unauthenticated callers are refused.
	if c, _ := e.do("GET", "/v2/accounts/"+acct.ID, "", nil, nil); c != 401 {
		t.Fatalf("unauthenticated got %d", c)
	}

	c, m := e.do("POST", "/v2/transactions", "tok-a", map[string]any{"account_id": acct.ID, "amount": 10}, nil)
	txn := e.mustID(c, m, 201)

	// Owner control: Alice can read her own objects on both versions.
	for _, p := range []string{
		"/v2/accounts/" + acct.ID, "/v1/accounts/" + acct.ID,
		"/v2/transactions/" + txn, "/v1/transactions/" + txn,
		"/v2/kyc/documents/" + doc.ID, "/v1/kyc/documents/" + doc.ID,
		"/v2/customers/alice/documents/" + doc.ID, "/v1/customers/alice/documents/" + doc.ID,
	} {
		if c, _ := e.do("GET", p, "tok-a", nil, nil); c != 200 {
			t.Fatalf("owner GET %s got %d", p, c)
		}
	}

	// H1/H7/H8: Bob cannot reach Alice's objects on any endpoint or version.
	for _, p := range []string{
		"/v2/accounts/" + acct.ID, "/v1/accounts/" + acct.ID,
		"/v2/transactions/" + txn, "/v1/transactions/" + txn,
		"/v2/kyc/documents/" + doc.ID, "/v1/kyc/documents/" + doc.ID,
		"/v2/customers/alice/documents/" + doc.ID, "/v1/customers/alice/documents/" + doc.ID,
	} {
		if c, _ := e.do("GET", p, "tok-b", nil, nil); !denied(c) {
			t.Fatalf("cross-customer GET %s got %d", p, c)
		}
	}

	// H2: Bob cannot modify Alice's beneficiary or payment.
	c, m = e.do("POST", "/v2/beneficiaries", "tok-a", map[string]any{"name": "Carol", "account_number": "111"}, nil)
	ben := e.mustID(c, m, 201)
	c, m = e.do("POST", "/v2/beneficiaries", "tok-a", map[string]any{"name": "Dave", "account_number": "222"}, nil)
	ben2 := e.mustID(c, m, 201)
	c, m = e.do("POST", "/v2/payments", "tok-a", map[string]any{"account_id": acct.ID, "beneficiary_id": ben, "amount": 50}, nil)
	pay := e.mustID(c, m, 201)
	if c, _ := e.do("PATCH", "/v2/beneficiaries/"+ben, "tok-b", map[string]any{"account_number": "999"}, nil); !denied(c) {
		t.Fatalf("cross-customer beneficiary PATCH got %d", c)
	}
	if c, _ := e.do("PATCH", "/v2/payments/"+pay, "tok-b", map[string]any{"amount": 1}, nil); !denied(c) {
		t.Fatalf("cross-customer payment PATCH got %d", c)
	}
	if c, m := e.do("GET", "/v2/beneficiaries/"+ben, "tok-a", nil, nil); c != 200 || m["account_number"] != "111" {
		t.Fatalf("beneficiary changed or unreadable: %d %v", c, m)
	}

	// H3: amount or beneficiary change after approval returns 409 and clears approval.
	for _, change := range []map[string]any{{"amount": 5000}, {"beneficiary_id": ben2}} {
		c, m = e.do("POST", "/v2/payments", "tok-a", map[string]any{"account_id": acct.ID, "beneficiary_id": ben, "amount": 50}, nil)
		p := e.mustID(c, m, 201)
		if c, m := e.do("POST", "/v2/payments/"+p+"/approve", "tok-a", nil, nil); c != 200 || m["state"] != "approved" {
			t.Fatalf("self approve (single control) got %d %v", c, m)
		}
		if c, _ := e.do("PATCH", "/v2/payments/"+p, "tok-a", change, nil); c != 409 {
			t.Fatalf("post-approval change %v got %d", change, c)
		}
		_, m = e.do("GET", "/v2/payments/"+p, "tok-a", nil, nil)
		if n := len(m["approvals"].([]any)); n != 0 || m["state"] != "initiated" {
			t.Fatalf("approval not cleared: %v", m)
		}
		if c, _ := e.do("POST", "/v2/payments/"+p+"/settle", "tok-a", nil, nil); c != 409 {
			t.Fatalf("settle after cleared approval got %d", c)
		}
	}

	// H4: a repeated Idempotency-Key returns the original transaction, no second row.
	h := map[string]string{"Idempotency-Key": "k-1"}
	before := e.srv.TransactionCount()
	c, m = e.do("POST", "/v2/transactions", "tok-a", map[string]any{"account_id": acct.ID, "amount": 7}, h)
	first := e.mustID(c, m, 201)
	c, m = e.do("POST", "/v2/transactions", "tok-a", map[string]any{"account_id": acct.ID, "amount": 7}, h)
	if second := e.mustID(c, m, 200); second != first {
		t.Fatalf("replay returned %s want %s", second, first)
	}
	if got := e.srv.TransactionCount(); got != before+1 {
		t.Fatalf("transaction rows %d want %d", got, before+1)
	}

	// H5: settle without the required approvals returns 409.
	c, m = e.do("POST", "/v2/payments", "tok-a", map[string]any{"account_id": acct.ID, "beneficiary_id": ben, "amount": 80, "dual_control": true}, nil)
	dual := e.mustID(c, m, 201)
	if c, _ := e.do("POST", "/v2/payments/"+dual+"/settle", "tok-a", nil, nil); c != 409 {
		t.Fatalf("settle with no approvals got %d", c)
	}

	// H6: the initiator cannot approve under dual control; others cannot approve across customers.
	if c, _ := e.do("POST", "/v2/payments/"+dual+"/approve", "tok-a", nil, nil); !denied(c) {
		t.Fatalf("initiator approve under dual control got %d", c)
	}
	if c, _ := e.do("POST", "/v2/payments/"+dual+"/approve", "tok-b", nil, nil); !denied(c) {
		t.Fatalf("non-approver customer approve got %d", c)
	}
	if c, _ := e.do("POST", "/v2/payments/"+dual+"/approve", "tok-c1", nil, nil); c != 200 {
		t.Fatalf("first approver got %d", c)
	}
	if c, _ := e.do("POST", "/v2/payments/"+dual+"/approve", "tok-c1", nil, nil); !denied(c) {
		t.Fatalf("same approver twice got %d", c)
	}
	if c, _ := e.do("POST", "/v2/payments/"+dual+"/settle", "tok-a", nil, nil); c != 409 {
		t.Fatalf("settle with one of two approvals got %d", c)
	}
	if c, _ := e.do("POST", "/v2/payments/"+dual+"/approve", "tok-c2", nil, nil); c != 200 {
		t.Fatalf("second approver got %d", c)
	}
	if c, m := e.do("POST", "/v2/payments/"+dual+"/settle", "tok-a", nil, nil); c != 200 || m["state"] != "settled" {
		t.Fatalf("legitimate settle got %d %v", c, m)
	}
}

func TestBankOpenAPIHasNoLabels(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.ts.URL+"/openapi.json", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("openapi status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("openapi is not JSON: %v", err)
	}
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, bad := range []string{"vulnerable", "defect", "sealed"} {
		if strings.Contains(text, bad) {
			t.Fatalf("openapi contains %q", bad)
		}
	}
	if regexp.MustCompile(`(?i)\bh[1-8]\b`).MatchString(string(raw)) {
		t.Fatal("openapi contains an H1..H8 label")
	}
}

func TestNewRejectsIncompletePolicy(t *testing.T) {
	if _, err := New(Config{Policy: Policy{}}); err == nil {
		t.Fatal("expected error for empty policy")
	}
}
