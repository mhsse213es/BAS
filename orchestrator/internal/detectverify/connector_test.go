package detectverify

import "testing"

func TestNewConnector_DispatchesKnownProviders(t *testing.T) {
	if _, err := NewConnector(Config{Provider: "microsoft_sentinel", WorkspaceID: "w1"}); err != nil {
		t.Errorf("microsoft_sentinel: %v", err)
	}
	if _, err := NewConnector(Config{Provider: "microsoft_defender"}); err != nil {
		t.Errorf("microsoft_defender: %v", err)
	}
}

func TestNewConnector_UnsupportedProvider_ReturnsError(t *testing.T) {
	if _, err := NewConnector(Config{Provider: "qradar"}); err == nil {
		t.Fatal("expected an error for a provider not yet implemented in this slice")
	}
}
