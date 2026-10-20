package protocol

import "testing"

func TestValidateMethodPathAcceptsFullyQualifiedMethods(t *testing.T) {
	for _, p := range []string{
		"/pkg.orders.v1.OrderService/GetOrder",
		"/OrderService/GetOrder",
	} {
		if err := ValidateMethodPath(p); err != nil {
			t.Fatalf("%s refused: %v", p, err)
		}
	}
}

func TestValidateMethodPathRefusesEverythingElse(t *testing.T) {
	for _, p := range []string{
		"/api/orders/ORD-2001",
		"/pkg.orders.v1.OrderService",
		"/pkg.orders.v1.OrderService/",
		"pkg.orders.v1.OrderService/GetOrder",
		"/pkg.orders.v1.OrderService/GetOrder?x=1",
		"/OrderService",
		"/pkg.orders.v1.OrderService/Get Order",
	} {
		if err := ValidateMethodPath(p); err == nil {
			t.Fatalf("%q accepted, want refusal", p)
		}
	}
}

func TestGRPCValidateBodyIsJSONObject(t *testing.T) {
	g := GRPC{}
	if err := g.Validate(`{"order_id": "ORD-2001"}`); err != nil {
		t.Fatalf("object refused: %v", err)
	}
	for _, bad := range []string{`not json`, `[1,2]`, `null`, `"text"`} {
		if err := g.Validate(bad); err == nil {
			t.Fatalf("%s accepted, want refusal", bad)
		}
	}
}

func TestGRPCIsRegistered(t *testing.T) {
	if !Supported("grpc") {
		t.Fatal("grpc has an adapter but Supported reports false")
	}
}
