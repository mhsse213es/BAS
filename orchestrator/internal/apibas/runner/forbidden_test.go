package runner

import "testing"

// Regression tests for the forbidden-value scan. The three cases the design names are: a foreign ID present at the top
// level, the same ID nested inside an array, and no foreign ID present. The others pin the decoding and inspection rules.

const foreignID = "ORD-1001"

func TestForbiddenScan_ForeignIDPresent(t *testing.T) {
	raw := []byte(`{"id":"ORD-1001","status":"ok"}`)
	hits, ok := forbiddenScan(raw, "", []string{foreignID}, "GET /api/x")
	if !ok || hits != 1 {
		t.Fatalf("top-level foreign ID: hits=%d inspectable=%t, want 1 true", hits, ok)
	}
}

func TestForbiddenScan_ForeignIDNestedInArray(t *testing.T) {
	raw := []byte(`{"results":[{"fields":{"tags":["x",{"deep":"ORD-1001"}]}}]}`)
	hits, ok := forbiddenScan(raw, "", []string{foreignID}, "GET /api/x")
	if !ok || hits != 1 {
		t.Fatalf("foreign ID nested in array: hits=%d inspectable=%t, want 1 true", hits, ok)
	}
}

func TestForbiddenScan_NoForeignIDPresent(t *testing.T) {
	raw := []byte(`{"results":[{"id":"ORD-2001","fields":{"sku":"SKU-2001-A"}}]}`)
	hits, ok := forbiddenScan(raw, "", []string{foreignID}, "GET /api/x")
	if !ok || hits != 0 {
		t.Fatalf("no foreign ID: hits=%d inspectable=%t, want 0 true", hits, ok)
	}
}

func TestForbiddenScan_JSONEscapedValueIsFound(t *testing.T) {
	raw := []byte(`{"id":"ORD-1001"}`)
	hits, ok := forbiddenScan(raw, "", []string{foreignID}, "GET /api/x")
	if !ok || hits != 1 {
		t.Fatalf("JSON-escaped value: hits=%d inspectable=%t, want 1 true", hits, ok)
	}
}

func TestForbiddenScan_KeyNameIsSearched(t *testing.T) {
	raw := []byte(`{"ORD-1001":{"status":"ok"}}`)
	hits, _ := forbiddenScan(raw, "", []string{foreignID}, "GET /api/x")
	if hits != 1 {
		t.Fatalf("value in a key name: hits=%d, want 1", hits)
	}
}

func TestForbiddenScan_NonJSONTextIsSearched(t *testing.T) {
	raw := []byte("status=ok; owner=ORD-1001")
	hits, ok := forbiddenScan(raw, "", []string{foreignID}, "GET /api/x")
	if !ok || hits != 1 {
		t.Fatalf("text body: hits=%d inspectable=%t, want 1 true", hits, ok)
	}
}

// A value the attacker sent is the echo of their own input, not a disclosure.
func TestForbiddenScan_EchoedRequestValueIsNotCounted(t *testing.T) {
	raw := []byte(`{"error":"no match for ORD-1001"}`)
	hits, _ := forbiddenScan(raw, "", []string{foreignID}, "GET /api/x?q=ORD-1001")
	if hits != 0 {
		t.Fatalf("echoed request value: hits=%d, want 0", hits)
	}
}

func TestForbiddenScan_CompressedBodyIsUninspectable(t *testing.T) {
	hits, ok := forbiddenScan([]byte{0x1f, 0x8b, 0x08}, "gzip", []string{foreignID}, "GET /api/x")
	if ok || hits != 0 {
		t.Fatalf("compressed body: hits=%d inspectable=%t, want 0 false", hits, ok)
	}
}

func TestForbiddenScan_InvalidUTF8IsUninspectable(t *testing.T) {
	hits, ok := forbiddenScan([]byte("ORD-1001\xff\xfe"), "", []string{foreignID}, "GET /api/x")
	if ok {
		t.Fatalf("invalid UTF-8 body: inspectable=true (hits=%d), want false", hits)
	}
}

func TestForbiddenScan_NoValuesDeclaredIsInspectable(t *testing.T) {
	hits, ok := forbiddenScan([]byte(`{"a":"b"}`), "gzip", nil, "GET /api/x")
	if !ok || hits != 0 {
		t.Fatalf("no forbidden values: hits=%d inspectable=%t, want 0 true", hits, ok)
	}
}
