package cigate

import (
	"strings"
	"testing"
)

func TestNewToken_ShapeAndUniqueness(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if !IsCIToken(a) {
		t.Fatalf("NewToken() = %q, not accepted as a CI token", a)
	}
	if a == b {
		t.Fatal("two tokens are equal")
	}
	if !strings.HasPrefix(a, TokenPrefix) {
		t.Fatalf("token %q lacks prefix %q", a, TokenPrefix)
	}
}

func TestHashToken_StableAndNotPlaintext(t *testing.T) {
	tok, _ := NewToken()
	h := HashToken(tok)
	if h != HashToken(tok) {
		t.Fatal("hash is not stable")
	}
	if strings.Contains(h, tok) || len(h) != 64 {
		t.Fatalf("stored form %q must be a 64-char digest, never the token", h)
	}
}

func TestIsCIToken_RejectsSessionsAndMalformed(t *testing.T) {
	cases := map[string]bool{
		"":                                  false,
		"eyJhbGciOiJIUzI1NiJ9.x.y":          false,
		"bas_ci_":                           false,
		"bas_ci_" + strings.Repeat("a", 63): false,
		"bas_ci_" + strings.Repeat("a", 64): true,
	}
	for in, want := range cases {
		if got := IsCIToken(in); got != want {
			t.Errorf("IsCIToken(%q) = %v, want %v", in, got, want)
		}
	}
}
