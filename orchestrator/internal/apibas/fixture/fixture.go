// Package fixture defines the deterministic, synthetic test data shared by
// the API BAS lab (the target) and the runner (the test executor). Both sides
// must agree on identities and object ownership, so the fixture lives in one
// place and is imported by both.
//
// Every protected value is fabricated and tagged BAS-SIM. No value here is
// real customer data.
package fixture

// Identity is a synthetic test principal. TokenRef names a secret; the token
// itself is never stored in a fixture or scenario.
type Identity struct {
	Name       string // e.g. "customer-a"
	CustomerID string // e.g. "cust-a"
	TokenRef   string // secret reference resolved by the runner at execution time
	// RevokedTokenRef names a credential that the lab has revoked. It exists
	// so authentication scenarios can prove a revoked credential is refused.
	RevokedTokenRef string
}

// Object is a synthetic resource owned by one identity. Public fields may be
// returned to anyone authorised to read the object. Protected fields must only
// ever reach the owner; a disclosure of any protected value is a leak.
type Object struct {
	ID        string
	OwnerID   string
	Status    string
	Public    map[string]string
	Protected map[string]string
}

// Fixture is a complete, deterministic test environment.
type Fixture struct {
	Name       string
	Identities []Identity
	Objects    []Object
}

// Identity returns the named identity and whether it exists.
func (f Fixture) Identity(name string) (Identity, bool) {
	for _, id := range f.Identities {
		if id.Name == name {
			return id, true
		}
	}
	return Identity{}, false
}

// Object returns the object with the given ID and whether it exists.
func (f Fixture) Object(id string) (Object, bool) {
	for _, o := range f.Objects {
		if o.ID == id {
			return o, true
		}
	}
	return Object{}, false
}

// OrdersTwoTenant is the Phase 1 fixture: two customers in separate tenants,
// each owning one order with protected card and account fields.
func OrdersTwoTenant() Fixture {
	return Fixture{
		Name: "orders-two-tenant",
		Identities: []Identity{
			{Name: "customer-a", CustomerID: "cust-a", TokenRef: "apibas/lab/customer-a", RevokedTokenRef: "apibas/lab/customer-a-revoked"},
			{Name: "customer-b", CustomerID: "cust-b", TokenRef: "apibas/lab/customer-b"},
		},
		Objects: []Object{
			{
				ID:      "ORD-1001",
				OwnerID: "cust-a",
				Status:  "shipped",
				Public:  map[string]string{"sku": "SKU-1001", "quantity": "2"},
				Protected: map[string]string{
					"card_last4":  "BAS-SIM-1001",
					"account_ref": "BAS-SIM-ACC-A",
				},
			},
			{
				ID:      "ORD-2001",
				OwnerID: "cust-b",
				Status:  "pending",
				Public:  map[string]string{"sku": "SKU-2001", "quantity": "1"},
				Protected: map[string]string{
					"card_last4":  "BAS-SIM-2001",
					"account_ref": "BAS-SIM-ACC-B",
				},
			},
		},
	}
}

// OrdersNoProtected is a variant of the Phase 1 fixture whose objects carry no
// protected values. It exists to prove that a 2xx response with nothing
// sensitive in it is graded as inconclusive, not as an exploit.
func OrdersNoProtected() Fixture {
	f := OrdersTwoTenant()
	f.Name = "orders-no-protected"
	for i := range f.Objects {
		f.Objects[i].Protected = map[string]string{}
	}
	return f
}
