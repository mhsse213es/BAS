package models

import (
	"strings"
	"testing"
)

const testNTLMHash = "aad3b435b51404eeaad3b435b51404ee"

func TestRedactCredentialOutput_WithholdsCredentialAccessOutput(t *testing.T) {
	results := []SimulationResult{
		{ID: "cred", Technique: AttackTechnique{ID: "T1003.001", Tactic: "credential-access"},
			RawOutput: "Administrator:500:" + testNTLMHash + ":::", Details: "dumped NTLM " + testNTLMHash},
		{ID: "exec", Technique: AttackTechnique{ID: "T1059.001", Tactic: "execution"},
			RawOutput: "hello", Details: "ran"},
	}
	RedactCredentialOutput(results)

	cred := results[0]
	if strings.Contains(cred.RawOutput, testNTLMHash) || strings.Contains(cred.Details, testNTLMHash) {
		t.Fatalf("credential-access output still contains the hash: raw=%q details=%q", cred.RawOutput, cred.Details)
	}
	if cred.RawOutput != CredentialOutputWithheld {
		t.Fatalf("RawOutput = %q, want the withheld marker", cred.RawOutput)
	}
	if results[1].RawOutput != "hello" {
		t.Fatalf("non-credential RawOutput changed to %q; only credential-access output may be withheld", results[1].RawOutput)
	}
}

// The detection alert's command line is serialized on the result, so an
// export would return a pass-the-hash hash that RawOutput redaction misses.
func TestRedactCredentialOutput_WithholdsAlertCommandLineHash(t *testing.T) {
	results := []SimulationResult{
		{ID: "cred", Technique: AttackTechnique{ID: "T1003.001", Tactic: "credential-access"},
			DetectionAlert: &DetectionAlert{CommandLine: "mimikatz.exe sekurlsa::pth /ntlm:" + testNTLMHash}},
		{ID: "exec", Technique: AttackTechnique{ID: "T1059.001", Tactic: "execution"},
			DetectionAlert: &DetectionAlert{CommandLine: "certutil -hashfile x " + testNTLMHash}},
	}
	RedactCredentialOutput(results)

	if got := results[0].DetectionAlert.CommandLine; strings.Contains(got, testNTLMHash) || !strings.Contains(got, "sekurlsa::pth") {
		t.Fatalf("credential-access alert command line = %q; want hash withheld, command kept", got)
	}
	if got := results[1].DetectionAlert.CommandLine; got != "certutil -hashfile x "+testNTLMHash {
		t.Fatalf("non-credential alert command line changed to %q", got)
	}
}

// A secret printed by an ordinary (non-credential) step is withheld too.
// Other output on the same step is unchanged.
func TestRedactCredentialOutput_ScrubsSecretsFromOrdinarySteps(t *testing.T) {
	const token = "eyJhbGciOiJIUzI1NiJ9.payload.sig"
	results := []SimulationResult{
		{ID: "exec", Technique: AttackTechnique{ID: "T1059.001", Tactic: "execution"},
			RawOutput: "Authorization: Bearer " + token + " status=ok",
			Details:   "api_key=sk_live_4f9a8b7c6d5e4f3a"},
	}
	RedactCredentialOutput(results)

	r := results[0]
	if strings.Contains(r.RawOutput, token) || strings.Contains(r.Details, "sk_live_4f9a8b7c6d5e4f3a") {
		t.Fatalf("ordinary step leaked a secret: raw=%q details=%q", r.RawOutput, r.Details)
	}
	if !strings.Contains(r.RawOutput, "status=ok") {
		t.Fatalf("non-secret text lost: %q", r.RawOutput)
	}
}
