package pki

import (
	"testing"

	"github.com/audspect/bas/internal/pki/pkitest"
)

func TestCSRKeyFingerprint_SameKeySameFingerprint(t *testing.T) {
	key, err := pkitest.NewTestKey()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := pkitest.GenerateTestCSRWith(key, "one")
	b, _ := pkitest.GenerateTestCSRWith(key, "two")
	fa, err := CSRKeyFingerprint(a)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	fb, err := CSRKeyFingerprint(b)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if fa != fb {
		t.Errorf("same key gave different fingerprints: %s vs %s", fa, fb)
	}
}

func TestCSRKeyFingerprint_DifferentKeyDifferentFingerprint(t *testing.T) {
	k1, _ := pkitest.NewTestKey()
	k2, _ := pkitest.NewTestKey()
	a, _ := pkitest.GenerateTestCSRWith(k1, "x")
	b, _ := pkitest.GenerateTestCSRWith(k2, "x")
	fa, _ := CSRKeyFingerprint(a)
	fb, _ := CSRKeyFingerprint(b)
	if fa == fb {
		t.Error("different keys gave the same fingerprint")
	}
}

func TestCSRKeyFingerprint_RejectsNonCSR(t *testing.T) {
	if _, err := CSRKeyFingerprint([]byte("not a csr")); err == nil {
		t.Error("expected an error for input that is not a CSR")
	}
}
