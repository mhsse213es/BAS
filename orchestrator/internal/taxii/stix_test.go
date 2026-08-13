package taxii

import (
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/iocregistry"
)

func TestParseObject_ValidIndicator(t *testing.T) {
	raw := json.RawMessage(`{"id":"indicator--abc","type":"indicator","modified":"2026-01-01T00:00:00Z","pattern":"[ipv4-addr:value = '203.0.113.9']","pattern_type":"stix"}`)
	env, err := ParseObject(raw)
	if err != nil {
		t.Fatalf("ParseObject: %v", err)
	}
	if env.ID != "indicator--abc" || env.Type != "indicator" {
		t.Errorf("ParseObject() = %+v", env)
	}
}

func TestParseObject_MalformedJSON(t *testing.T) {
	_, err := ParseObject(json.RawMessage(`{not valid json`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

func TestParseObject_MissingIDOrType(t *testing.T) {
	_, err := ParseObject(json.RawMessage(`{"modified":"2026-01-01T00:00:00Z"}`))
	if err == nil {
		t.Fatal("expected an error for a STIX object missing id/type")
	}
}

func TestParsePattern_RecognizedForms(t *testing.T) {
	cases := []struct {
		pattern   string
		wantType  iocregistry.Type
		wantValue string
	}{
		{"[ipv4-addr:value = '203.0.113.9']", iocregistry.TypeIP, "203.0.113.9"},
		{"[ipv6-addr:value = '2001:db8::1']", iocregistry.TypeIP, "2001:db8::1"},
		{"[domain-name:value = 'evil.example.com']", iocregistry.TypeDomain, "evil.example.com"},
		{"[url:value = 'http://evil.example.com/payload']", iocregistry.TypeURL, "http://evil.example.com/payload"},
		{"[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']", iocregistry.TypeFileHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"[file:hashes.'MD5' = '5d41402abc4b2a76b9719d911017c592']", iocregistry.TypeFileHash, "5d41402abc4b2a76b9719d911017c592"},
	}
	for _, tc := range cases {
		gotType, gotValue, ok := ParsePattern(tc.pattern)
		if !ok {
			t.Errorf("ParsePattern(%q) ok = false, want true", tc.pattern)
			continue
		}
		if gotType != tc.wantType || gotValue != tc.wantValue {
			t.Errorf("ParsePattern(%q) = (%q, %q), want (%q, %q)", tc.pattern, gotType, gotValue, tc.wantType, tc.wantValue)
		}
	}
}

func TestParsePattern_CompositePatternRejected(t *testing.T) {
	_, _, ok := ParsePattern("[ipv4-addr:value = '203.0.113.9' AND domain-name:value = 'evil.example.com']")
	if ok {
		t.Error("expected ok=false for a composite/boolean pattern")
	}
}

func TestParsePattern_UnrecognizedObservableRejected(t *testing.T) {
	_, _, ok := ParsePattern("[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\Software\\\\Evil']")
	if ok {
		t.Error("expected ok=false for an unrecognized observable type")
	}
}
