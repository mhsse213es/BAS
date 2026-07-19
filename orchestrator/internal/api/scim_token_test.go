package api

import "testing"

func TestGenerateSCIMToken_UniqueAndNonEmpty(t *testing.T) {
	t1, err := generateSCIMToken()
	if err != nil {
		t.Fatalf("generateSCIMToken: %v", err)
	}
	t2, err := generateSCIMToken()
	if err != nil {
		t.Fatalf("generateSCIMToken: %v", err)
	}
	if t1 == "" || t2 == "" {
		t.Fatal("token must not be empty")
	}
	if t1 == t2 {
		t.Fatal("two calls to generateSCIMToken must not produce the same token")
	}
}

func TestHashSCIMToken_DeterministicAndDistinguishesInputs(t *testing.T) {
	h1 := hashSCIMToken("token-a")
	h2 := hashSCIMToken("token-a")
	h3 := hashSCIMToken("token-b")
	if h1 != h2 {
		t.Error("hashSCIMToken must be deterministic for the same input")
	}
	if h1 == h3 {
		t.Error("hashSCIMToken must distinguish different inputs")
	}
	if h1 == "token-a" {
		t.Error("hashSCIMToken must not return the input unchanged")
	}
}
