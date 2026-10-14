package evidence

import "testing"

func TestNormalizeConfidence_OpenCTIIntegerPassesThrough(t *testing.T) {
	raw, norm, version := NormalizeConfidence("opencti", "72")
	if raw == nil || *raw != "72" {
		t.Fatalf("raw = %v, want \"72\"", raw)
	}
	if norm == nil || *norm != 72 {
		t.Fatalf("normalized = %v, want 72", norm)
	}
	if version == "" {
		t.Fatal("mapping version must not be empty")
	}
}

func TestNormalizeConfidence_MISPKnownLevelMaps(t *testing.T) {
	_, norm, _ := NormalizeConfidence("misp", "high")
	if norm == nil || *norm != 85 {
		t.Fatalf("normalized = %v, want 85 for MISP \"high\"", norm)
	}
}

func TestNormalizeConfidence_MISPUnrecognizedIsNil(t *testing.T) {
	_, norm, _ := NormalizeConfidence("misp", "extremely-confident")
	if norm != nil {
		t.Fatalf("normalized = %v, want nil for an unrecognized MISP level", norm)
	}
}

func TestNormalizeConfidence_BundleAndOTXAlwaysNil(t *testing.T) {
	for _, source := range []string{"bundle", "otx"} {
		raw, norm, _ := NormalizeConfidence(source, "90")
		if raw != nil {
			t.Errorf("%s: raw = %v, want nil (no invented value)", source, raw)
		}
		if norm != nil {
			t.Errorf("%s: normalized = %v, want nil", source, norm)
		}
	}
}
