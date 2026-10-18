package main

import (
	"errors"
	"net"
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
