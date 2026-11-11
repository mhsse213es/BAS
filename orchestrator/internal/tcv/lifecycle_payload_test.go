package tcv

import "testing"

func TestLifecyclePayloadCarriesRejectionReason(t *testing.T) {
	p := LifecyclePayload("REJECTED", "relevance")
	if p["reason_code"] != "relevance" || p["to_lifecycle"] != "REJECTED" {
		t.Fatalf("rejection payload = %v, want reason_code relevance", p)
	}
}

func TestLifecyclePayloadLegacyRejectionIsUnclassified(t *testing.T) {
	p := LifecyclePayload("REJECTED", "")
	if p["reason_code"] != UnclassifiedReason {
		t.Fatalf("legacy rejection payload = %v, want reason_code %q", p, UnclassifiedReason)
	}
}

func TestLifecyclePayloadNonRejectionHasNoReason(t *testing.T) {
	p := LifecyclePayload("PUBLISHED", "")
	if _, ok := p["reason_code"]; ok {
		t.Fatalf("non-rejection payload must not carry reason_code: %v", p)
	}
}
