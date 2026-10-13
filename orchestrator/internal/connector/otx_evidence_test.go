package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/evidence"
)

func TestOTXSource_FetchActivity_TruncatedAtPageCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every page returns a full otxPageLimit-sized page, so the loop
		// never sees a short page and must report truncated (spec §5.2).
		pulses := make([]otxPulse, otxPageLimit)
		for i := range pulses {
			pulses[i] = otxPulse{Name: fmt.Sprintf("pulse-%d", i), Modified: "2026-01-15T00:00:00Z"}
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: otxPageLimit * otxMaxPages, Results: pulses})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL
	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	report := c.Completeness()
	if report.Completeness != evidence.Truncated {
		t.Fatalf("Completeness() = %+v, want Truncated", report)
	}
}

func TestOTXSource_FetchActivity_PartialOnLaterPageFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			pulses := make([]otxPulse, otxPageLimit)
			for i := range pulses {
				pulses[i] = otxPulse{Name: fmt.Sprintf("pulse-%d", i), Modified: "2026-01-15T00:00:00Z"}
			}
			json.NewEncoder(w).Encode(otxPulsesResponse{Count: otxPageLimit * 2, Results: pulses})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL
	if _, err := c.FetchActivity(); err == nil {
		t.Fatal("expected an error from the page-2 failure")
	}
	report := c.Completeness()
	if report.Completeness != evidence.Partial {
		t.Fatalf("Completeness() = %+v, want Partial", report)
	}
}

func TestOTXSource_FetchActivity_CompleteOnShortFinalPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: 1, Results: []otxPulse{{Name: "p", Modified: "2026-01-15T00:00:00Z"}}})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL
	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	report := c.Completeness()
	if report.Completeness != evidence.Complete {
		t.Fatalf("Completeness() = %+v, want Complete", report)
	}
}
