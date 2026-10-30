package model

import (
	"strings"
	"testing"
)

func TestSignatureNormalisation(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{"get", "/payments/{id}", "GET /payments/{}"},
		{"GET", "/payments/{paymentId}", "GET /payments/{}"},
		{"post", "/payments/settle", "POST /payments/settle"},
		{"Get", "/a/b/", "GET /a/b"},
		{"GET", "/", "GET /"},
		{"delete", "/v2/{a}/items/{b}", "DELETE /v2/{}/items/{}"},
	}
	for _, c := range cases {
		got, err := Signature(c.method, c.path)
		if err != nil || got != c.want {
			t.Fatalf("Signature(%q,%q) = %q, %v; want %q", c.method, c.path, got, err, c.want)
		}
	}
	for _, bad := range [][2]string{{"GET", ""}, {"GET", "a/b"}, {"GET", "/a//b"}, {"GET", "/a/{}x"}, {"GET", "/a/x{id}"}, {"GET", "/a/{}"[:5] + "{"},
		{"GET", "/a?x=1"}, {"GET", "/a/../b"}, {"GET", "/a/./b"}, {"", "/a"}, {"GE T", "/a"}, {"GET", "/a b"}, {"GET", "/a/{i{d}}"}} {
		if s, err := Signature(bad[0], bad[1]); err == nil {
			t.Fatalf("Signature(%q,%q) = %q, want an error", bad[0], bad[1], s)
		}
	}
}

func TestParseSignature(t *testing.T) {
	if got, err := ParseSignature("get /payments/{paymentId}"); err != nil || got != "GET /payments/{}" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"listAccounts", "GET", "GET  /a", " GET /a", "GET /a ", "GET /a b", "/a"} {
		if _, err := ParseSignature(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// Two operations that normalise to the same signature are ambiguous: the import refuses them.
func TestImportRefusesDuplicateSignatures(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
	 "/a/{id}":{"get":{"operationId":"one","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
	 "/a/{other}":{"get":{"operationId":"two","parameters":[{"name":"other","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}`
	if _, err := Import([]byte(spec)); err == nil || !strings.Contains(err.Error(), "same signature") {
		t.Fatalf("duplicate signature accepted: %v", err)
	}
}

func TestOperationSignatureIgnoresTheAnalystsOperationID(t *testing.T) {
	a := Operation{ID: "listAccounts", Method: "POST", Path: "/payments/settle"}
	b := Operation{ID: "settle", Method: "POST", Path: "/payments/settle"}
	if a.Signature() != "POST /payments/settle" || a.Signature() != b.Signature() {
		t.Fatalf("%q %q", a.Signature(), b.Signature())
	}
}
