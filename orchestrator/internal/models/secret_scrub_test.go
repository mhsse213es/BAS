package models

import (
	"strings"
	"testing"
)

// Output from an ordinary step can print a secret (a cloud access key, a
// bearer token, a private key, a password assignment). Exports and run lists
// must not return it, while the rest of the line is kept.
func TestWithholdSecrets_ScrubsSecretShapedValues(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string
	}{
		{"aws access key id", "aws_access_key_id=AKIAIOSFODNN7EXAMPLE region=us-east-1", "AKIAIOSFODNN7EXAMPLE"},
		{"bearer token", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9.payload.sig"},
		{"password assignment", "connecting with password=Hunter2!Secret", "Hunter2!Secret"},
		{"api key assignment", "api_key: sk_live_4f9a8b7c6d5e4f3a", "sk_live_4f9a8b7c6d5e4f3a"},
		{"pem private key header", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := WithholdSecrets(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Fatalf("secret survived scrub: %q", got)
			}
			if !strings.Contains(got, SecretWithheld) {
				t.Fatalf("no withheld marker in %q", got)
			}
		})
	}
}

// Ordinary output with no secret-shaped values is returned unchanged.
func TestWithholdSecrets_LeavesOrdinaryOutputUnchanged(t *testing.T) {
	const in = `Get-Process: 42 processes; exit 0; user=alice; path=C:\Windows\System32`
	if got := WithholdSecrets(in); got != in {
		t.Fatalf("ordinary output changed: %q", got)
	}
}
