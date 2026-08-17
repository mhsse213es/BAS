package auth

import (
	"testing"
	"time"
)

func TestSSOState_RoundTrip(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	claims, err := ValidateSSOState(tok, "secret")
	if err != nil {
		t.Fatalf("ValidateSSOState: %v", err)
	}
	if claims.TenantID != "acme" {
		t.Errorf("TenantID = %q, want acme", claims.TenantID)
	}
	if claims.CodeVerifier != "verifier-abc123" {
		t.Errorf("CodeVerifier = %q, want verifier-abc123", claims.CodeVerifier)
	}
}

func TestSSOState_Expired(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", -time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	if _, err := ValidateSSOState(tok, "secret"); err == nil {
		t.Fatal("expected an error for an expired state token, got nil")
	}
}

func TestSSOState_WrongSecret(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	if _, err := ValidateSSOState(tok, "wrong-secret"); err == nil {
		t.Fatal("expected an error for a state token signed with a different secret, got nil")
	}
}

func TestSSOState_Tampered(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	tampered := flipMiddleChar(tok)
	if _, err := ValidateSSOState(tampered, "secret"); err == nil {
		t.Fatal("expected an error for a tampered state token, got nil")
	}
}
