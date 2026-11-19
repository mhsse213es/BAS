package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestValidateCandidateHost_RejectsPathAndQuery(t *testing.T) {
	_, err := ValidateCandidateHost("https://host:9443/foo?x=1")
	if err == nil {
		t.Fatal("expected rejection of a URL with a path/query, got none")
	}
}

func TestValidateCandidateHost_AcceptsSchemeHostPort(t *testing.T) {
	got, err := ValidateCandidateHost("https://10.0.0.5:9443")
	if err != nil || got != "https://10.0.0.5:9443" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestClassifyTestResult_TLSHandshakeFails_IsCertInvalid(t *testing.T) {
	got := ClassifyTestResult(errors.New("x509: certificate signed by unknown authority"), nil)
	if got != TestOutcomeCertInvalid {
		t.Fatalf("got %q, want %q", got, TestOutcomeCertInvalid)
	}
}

func TestClassifyTestResult_TLSOK_AuthRejected_IsServerRejected(t *testing.T) {
	got := ClassifyTestResult(nil, errors.New("401 unauthorized"))
	if got != TestOutcomeServerRejected {
		t.Fatalf("got %q, want %q", got, TestOutcomeServerRejected)
	}
}

func TestClassifyTestResult_BothOK_IsConnected(t *testing.T) {
	if got := ClassifyTestResult(nil, nil); got != TestOutcomeConnected {
		t.Fatalf("got %q, want %q", got, TestOutcomeConnected)
	}
}

func TestClassifyTestResult_DialFails_IsHostUnreachable(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	got := ClassifyTestResult(dialErr, nil)
	if got != TestOutcomeHostUnreachable {
		t.Fatalf("got %q, want %q", got, TestOutcomeHostUnreachable)
	}
}

// The Settings window shows the design's plain-language outcome names, not the internal codes.
func TestTestOutcome_Label_UsesTheDesignsWording(t *testing.T) {
	cases := map[TestOutcome]string{
		TestOutcomeConnected:       "Connected",
		TestOutcomeServerRejected:  "Server rejected connection",
		TestOutcomeCertInvalid:     "Certificate validation failed",
		TestOutcomeHostUnreachable: "Host unreachable",
		TestOutcomeInvalidHost:     "Invalid host",
	}
	for o, want := range cases {
		if got := o.Label(); got != want {
			t.Errorf("%q.Label() = %q, want %q", o, got, want)
		}
	}
	if got := TestOutcome("something_new").Label(); got != "something_new" {
		t.Errorf("an unknown outcome must still show something honest, got %q", got)
	}
}

func TestFormatTestResult_NeverRepeatsItselfAndNeverShowsACode(t *testing.T) {
	cases := []struct {
		o      TestOutcome
		detail string
		want   string
	}{
		{TestOutcomeConnected, "Connected", "Connected"},
		{TestOutcomeConnected, "", "Connected"},
		{TestOutcomeCertInvalid, "x509: certificate signed by unknown authority", "Certificate validation failed: x509: certificate signed by unknown authority"},
		{TestOutcomeInvalidHost, "invalid host: missing scheme or host", "Invalid host: missing scheme or host"},
		{TestOutcomeHostUnreachable, "", "Host unreachable"},
	}
	for _, c := range cases {
		got := FormatTestResult(c.o, c.detail)
		if got != c.want {
			t.Errorf("FormatTestResult(%q, %q) = %q, want %q", c.o, c.detail, got, c.want)
		}
		if strings.Contains(got, "cert_invalid") || strings.Contains(got, "host_unreachable") || strings.Contains(got, "server_rejected") {
			t.Errorf("a raw outcome code leaked into %q", got)
		}
	}
}
