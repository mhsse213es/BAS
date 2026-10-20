package protocol

import "testing"

func TestAsyncValidateBody(t *testing.T) {
	a := Async{}
	if err := a.Validate(`{"event": "order.created", "order_id": "ORD-2001"}`); err != nil {
		t.Fatalf("valid event refused: %v", err)
	}
	for _, bad := range []string{`not json`, `{"order_id": "ORD-2001"}`, `{"event": ""}`, `[1]`} {
		if err := a.Validate(bad); err == nil {
			t.Fatalf("%s accepted, want refusal", bad)
		}
	}
}

func TestValidatePublishPath(t *testing.T) {
	for _, p := range []string{"/broker/topics/orders.events/publish", "/broker/topics/orders.retries/publish"} {
		if err := ValidatePublishPath(p); err != nil {
			t.Fatalf("%s refused: %v", p, err)
		}
	}
	for _, p := range []string{"/broker/topics//publish", "/broker/topics/orders.events", "/api/orders/ORD-2001/publish"} {
		if err := ValidatePublishPath(p); err == nil {
			t.Fatalf("%q accepted, want refusal", p)
		}
	}
}

func TestValidateSignatureHeader(t *testing.T) {
	if err := ValidateSignatureHeader("sha256=5129c98fc86b1946a04292e04aa9c0bbc5cdd590a8a6d0afeb2285fed9824d52"); err != nil {
		t.Fatalf("well-formed signature refused: %v", err)
	}
	for _, bad := range []string{"sha256=abc", "md5=5129c98fc86b1946a04292e04aa9c0bbc5cdd590a8a6d0afeb2285fed9824d52", "sha256=5129C98FC86B1946A04292E04AA9C0BBC5CDD590A8A6D0AFEB2285FED9824D52"} {
		if err := ValidateSignatureHeader(bad); err == nil {
			t.Fatalf("%q accepted, want refusal", bad)
		}
	}
}

func TestAsyncIsRegistered(t *testing.T) {
	if !Supported("async") {
		t.Fatal("async has an adapter but Supported reports false")
	}
}
