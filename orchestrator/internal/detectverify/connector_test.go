package detectverify

import "testing"

func TestNewConnector_DispatchesKnownProviders(t *testing.T) {
	if _, err := NewConnector(Config{Provider: "microsoft_sentinel", WorkspaceID: "w1"}); err != nil {
		t.Errorf("microsoft_sentinel: %v", err)
	}
	if _, err := NewConnector(Config{Provider: "microsoft_defender"}); err != nil {
		t.Errorf("microsoft_defender: %v", err)
	}
	if _, err := NewConnector(Config{Provider: "splunk", BaseURL: "https://splunk.example"}); err != nil {
		t.Errorf("splunk: %v", err)
	}
	if _, err := NewConnector(Config{Provider: "qradar", BaseURL: "https://qradar.example"}); err != nil {
		t.Errorf("qradar: %v", err)
	}
}

func TestNewConnector_UnsupportedProvider_ReturnsError(t *testing.T) {
	if _, err := NewConnector(Config{Provider: "crowdstrike"}); err == nil {
		t.Fatal("expected an error for a provider not yet implemented in this slice")
	}
}
