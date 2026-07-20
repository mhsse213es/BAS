package ioc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testProvider(t *testing.T, handler http.HandlerFunc) *otxProvider {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &otxProvider{
		apiKey:     "test-key",
		httpClient: http.DefaultClient,
		baseURL:    server.URL,
	}
}

func TestOTXLookup_ZeroPulses(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-OTX-API-KEY"); got != "test-key" {
			t.Errorf("X-OTX-API-KEY header = %q, want test-key", got)
		}
		w.Write([]byte(`{"indicator":"1.2.3.4","pulse_info":{"count":0,"pulses":[],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]}}}}`))
	})

	got, err := p.LookupIP(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if got.PulseCount != 0 {
		t.Errorf("PulseCount = %d, want 0", got.PulseCount)
	}
	if got.Confidence != ConfidenceUnknown {
		t.Errorf("Confidence = %q, want %q", got.Confidence, ConfidenceUnknown)
	}
	if got.Indicator != "1.2.3.4" || got.Type != "ip" || got.Provider != "otx" {
		t.Errorf("Indicator/Type/Provider = %q/%q/%q, want 1.2.3.4/ip/otx", got.Indicator, got.Type, got.Provider)
	}
}

func TestOTXLookup_ThreePulses_HighConfidence(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"indicator":"evil.example.com","pulse_info":{"count":3,"pulses":[{"name":"Emotet Campaign","tags":["emotet"]},{"name":"TA542 Infrastructure","tags":["ta542"]},{"name":"Banking Trojan IOCs","tags":["banking"]}],"related":{"alienvault":{"adversary":["TA542"],"malware_families":["Emotet"],"industries":["Financial Services"]}}}}`))
	})

	got, err := p.LookupDomain(context.Background(), "evil.example.com")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if got.PulseCount != 3 {
		t.Errorf("PulseCount = %d, want 3", got.PulseCount)
	}
	if got.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", got.Confidence, ConfidenceHigh)
	}
	wantPulses := []string{"Emotet Campaign", "TA542 Infrastructure", "Banking Trojan IOCs"}
	if len(got.PulseNames) != len(wantPulses) {
		t.Fatalf("PulseNames = %v, want %v", got.PulseNames, wantPulses)
	}
	for i, name := range wantPulses {
		if got.PulseNames[i] != name {
			t.Errorf("PulseNames[%d] = %q, want %q", i, got.PulseNames[i], name)
		}
	}
	if len(got.MalwareFamilies) != 1 || got.MalwareFamilies[0] != "Emotet" {
		t.Errorf("MalwareFamilies = %v, want [Emotet]", got.MalwareFamilies)
	}
	if len(got.AdversaryNames) != 1 || got.AdversaryNames[0] != "TA542" {
		t.Errorf("AdversaryNames = %v, want [TA542]", got.AdversaryNames)
	}
	if len(got.Industries) != 1 || got.Industries[0] != "Financial Services" {
		t.Errorf("Industries = %v, want [Financial Services]", got.Industries)
	}
}

func TestOTXLookup_OnePulse_LowConfidence(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"indicator":"maybe-bad.example","pulse_info":{"count":1,"pulses":[{"name":"Low Confidence Report","tags":[]}],"related":{"alienvault":{"adversary":[],"malware_families":[],"industries":[]}}}}`))
	})

	got, err := p.LookupDomain(context.Background(), "maybe-bad.example")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if got.Confidence != ConfidenceLow {
		t.Errorf("Confidence = %q, want %q", got.Confidence, ConfidenceLow)
	}
}

func TestOTXLookup_404_NotAnError(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	got, err := p.LookupHash(context.Background(), "deadbeef")
	if err != nil {
		t.Fatalf("LookupHash returned an error for a 404, want a zero-pulse Result: %v", err)
	}
	if got.Confidence != ConfidenceUnknown || got.PulseCount != 0 {
		t.Errorf("got %+v, want zero-pulse unknown-confidence result", got)
	}
}

func TestOTXLookup_UnexpectedStatus_ReturnsError(t *testing.T) {
	p := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})

	_, err := p.LookupCVE(context.Background(), "CVE-2024-0001")
	if err == nil {
		t.Fatal("LookupCVE with a 500 response returned no error, want one")
	}
}

func TestNewProvider_OTX(t *testing.T) {
	p, err := NewProvider(Config{Provider: "otx", APIKey: "k"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("NewProvider returned nil provider with no error")
	}
}

func TestNewProvider_UnknownProvider(t *testing.T) {
	_, err := NewProvider(Config{Provider: "not-a-real-provider"})
	if err == nil {
		t.Fatal("NewProvider with an unknown provider name returned no error")
	}
}
