package bank

import "testing"

// permissiveIn returns the fixed policy with exactly one hook replaced by a
// function that always allows. Test helper for hook independence only.
func permissiveIn(hook string) Policy {
	p := FixedPolicy()
	own := func(Principal, string) bool { return true }
	switch hook {
	case "CanReadAccount":
		p.CanReadAccount = own
	case "CanReadBeneficiary":
		p.CanReadBeneficiary = own
	case "CanReadPayment":
		p.CanReadPayment = own
	case "CanUseAccount":
		p.CanUseAccount = own
	case "CanReferenceBeneficiary":
		p.CanReferenceBeneficiary = own
	case "CanModifyBeneficiary":
		p.CanModifyBeneficiary = own
	case "CanModifyPayment":
		p.CanModifyPayment = own
	case "CanRequestSettle":
		p.CanRequestSettle = own
	case "ApprovalStillValid":
		p.ApprovalStillValid = func(Payment, int64, string) bool { return true }
	case "DedupeIdempotency":
		p.DedupeIdempotency = func(Principal, string, *Transaction) bool { return true }
	case "CanSettle":
		p.CanSettle = func(Payment) bool { return true }
	case "CanApprove":
		p.CanApprove = func(Principal, Payment) bool { return true }
	case "CanReadDocument":
		p.CanReadDocument = func(Principal, Document, DocRoute, string) bool { return true }
	case "LegacyAuthorize":
		p.LegacyAuthorize = func(Principal, string, string) bool { return true }
	default:
		panic("unknown hook " + hook)
	}
	return p
}

type fixtures struct {
	aliceAcct, bobAcct, aliceTxn, aliceBen, bobBen, aliceDoc, payApproved, payOpen string
}

// setupFixtures seeds alice-owned objects with the fixed policy, then installs pol.
func setupFixtures(t *testing.T, pol Policy) (*env, fixtures) {
	t.Helper()
	e := newEnv(t)
	var f fixtures
	f.aliceAcct = e.srv.AddAccount("alice", 100).ID
	f.bobAcct = e.srv.AddAccount("bob", 100).ID
	f.aliceDoc = e.srv.AddDocument("alice", "passport").ID
	c, m := e.do("POST", "/v2/transactions", "tok-a", map[string]any{"account_id": f.aliceAcct, "amount": 1}, map[string]string{"Idempotency-Key": "ka"})
	f.aliceTxn = e.mustID(c, m, 201)
	c, m = e.do("POST", "/v2/beneficiaries", "tok-a", map[string]any{"name": "A", "account_number": "1"}, nil)
	f.aliceBen = e.mustID(c, m, 201)
	c, m = e.do("POST", "/v2/beneficiaries", "tok-b", map[string]any{"name": "B", "account_number": "2"}, nil)
	f.bobBen = e.mustID(c, m, 201)
	for _, dst := range []*string{&f.payApproved, &f.payOpen} {
		c, m = e.do("POST", "/v2/payments", "tok-a", map[string]any{"account_id": f.aliceAcct, "beneficiary_id": f.aliceBen, "amount": 10}, nil)
		*dst = e.mustID(c, m, 201)
	}
	if c, _ := e.do("POST", "/v2/payments/"+f.payApproved+"/approve", "tok-a", nil, nil); c != 200 {
		t.Fatalf("fixture approve got %d", c)
	}
	e.srv.pol = pol
	return e, f
}

func TestEachHookIsIndependent(t *testing.T) {
	hooks := []string{
		"CanReadAccount", "CanReadBeneficiary", "CanReadPayment", "CanUseAccount", "CanReferenceBeneficiary",
		"CanModifyBeneficiary", "CanModifyPayment", "CanRequestSettle", "ApprovalStillValid", "DedupeIdempotency",
		"CanSettle", "CanApprove", "CanReadDocument", "LegacyAuthorize",
	}
	type op struct {
		name string
		hook string // the only hook that owns this operation
		run  func(e *env, f fixtures) bool
	}
	// call reports whether the response is a 2xx.
	call := func(e *env, method, path, tok string, body any, hdr map[string]string) bool {
		c, _ := e.do(method, path, tok, body, hdr)
		return c >= 200 && c < 300
	}
	ops := []op{
		{"v2 account read", "CanReadAccount", func(e *env, f fixtures) bool { return call(e, "GET", "/v2/accounts/"+f.aliceAcct, "tok-b", nil, nil) }},
		{"v2 transaction read", "CanReadAccount", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v2/transactions/"+f.aliceTxn, "tok-b", nil, nil)
		}},
		{"beneficiary read", "CanReadBeneficiary", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v2/beneficiaries/"+f.aliceBen, "tok-b", nil, nil)
		}},
		{"payment read", "CanReadPayment", func(e *env, f fixtures) bool { return call(e, "GET", "/v2/payments/"+f.payOpen, "tok-b", nil, nil) }},
		{"transaction create on other account", "CanUseAccount", func(e *env, f fixtures) bool {
			return call(e, "POST", "/v2/transactions", "tok-b", map[string]any{"account_id": f.aliceAcct, "amount": 2}, nil)
		}},
		{"payment create on other account", "CanUseAccount", func(e *env, f fixtures) bool {
			return call(e, "POST", "/v2/payments", "tok-b", map[string]any{"account_id": f.aliceAcct, "beneficiary_id": f.bobBen, "amount": 2}, nil)
		}},
		{"payment create with other beneficiary", "CanReferenceBeneficiary", func(e *env, f fixtures) bool {
			return call(e, "POST", "/v2/payments", "tok-b", map[string]any{"account_id": f.bobAcct, "beneficiary_id": f.aliceBen, "amount": 2}, nil)
		}},
		{"payment patch to other beneficiary", "CanReferenceBeneficiary", func(e *env, f fixtures) bool {
			return call(e, "PATCH", "/v2/payments/"+f.payOpen, "tok-a", map[string]any{"beneficiary_id": f.bobBen}, nil)
		}},
		{"beneficiary patch", "CanModifyBeneficiary", func(e *env, f fixtures) bool {
			return call(e, "PATCH", "/v2/beneficiaries/"+f.aliceBen, "tok-b", map[string]any{"name": "x"}, nil)
		}},
		{"payment patch", "CanModifyPayment", func(e *env, f fixtures) bool {
			return call(e, "PATCH", "/v2/payments/"+f.payOpen, "tok-b", map[string]any{"amount": 3}, nil)
		}},
		{"settle by other customer", "CanRequestSettle", func(e *env, f fixtures) bool {
			return call(e, "POST", "/v2/payments/"+f.payApproved+"/settle", "tok-b", nil, nil)
		}},
		{"settle unapproved payment", "CanSettle", func(e *env, f fixtures) bool {
			return call(e, "POST", "/v2/payments/"+f.payOpen+"/settle", "tok-a", nil, nil)
		}},
		{"approved payment amount change", "ApprovalStillValid", func(e *env, f fixtures) bool {
			return call(e, "PATCH", "/v2/payments/"+f.payApproved, "tok-a", map[string]any{"amount": 99}, nil)
		}},
		{"idempotency replay of another customer key", "DedupeIdempotency", func(e *env, f fixtures) bool {
			c, _ := e.do("POST", "/v2/transactions", "tok-b", map[string]any{"account_id": f.bobAcct, "amount": 2}, map[string]string{"Idempotency-Key": "ka"})
			return c == 200
		}},
		{"approve by other customer", "CanApprove", func(e *env, f fixtures) bool {
			return call(e, "POST", "/v2/payments/"+f.payOpen+"/approve", "tok-b", nil, nil)
		}},
		{"v2 document primary", "CanReadDocument", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v2/kyc/documents/"+f.aliceDoc, "tok-b", nil, nil)
		}},
		{"v2 document alternate", "CanReadDocument", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v2/customers/alice/documents/"+f.aliceDoc, "tok-b", nil, nil)
		}},
		{"v2 document alternate wrong customer", "CanReadDocument", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v2/customers/bob/documents/"+f.aliceDoc, "tok-b", nil, nil)
		}},
		{"v1 account read", "LegacyAuthorize", func(e *env, f fixtures) bool { return call(e, "GET", "/v1/accounts/"+f.aliceAcct, "tok-b", nil, nil) }},
		{"v1 transaction read", "LegacyAuthorize", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v1/transactions/"+f.aliceTxn, "tok-b", nil, nil)
		}},
		{"v1 document primary", "LegacyAuthorize", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v1/kyc/documents/"+f.aliceDoc, "tok-b", nil, nil)
		}},
		{"v1 document alternate", "LegacyAuthorize", func(e *env, f fixtures) bool {
			return call(e, "GET", "/v1/customers/alice/documents/"+f.aliceDoc, "tok-b", nil, nil)
		}},
	}
	covered := map[string]bool{}
	for _, o := range ops {
		covered[o.hook] = true
	}
	for _, h := range hooks {
		if !covered[h] {
			t.Fatalf("hook %s has no owned operation in the table", h)
		}
	}
	for _, o := range ops {
		e, f := setupFixtures(t, FixedPolicy())
		if o.run(e, f) {
			t.Fatalf("fixed policy permitted %q", o.name)
		}
	}
	for _, h := range hooks {
		for _, o := range ops {
			e, f := setupFixtures(t, permissiveIn(h))
			got := o.run(e, f)
			if want := o.hook == h; got != want {
				t.Errorf("hook %s permissive: op %q permitted=%v want %v", h, o.name, got, want)
			}
		}
	}
}
