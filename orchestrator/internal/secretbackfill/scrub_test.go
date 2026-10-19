package secretbackfill

import (
	"encoding/json"
	"strings"
	"testing"
)

const secretValue = "Sup3rSecretValue99"

func TestScrubResults_RemovesSecretFromStoredOutput(t *testing.T) {
	raw := []byte(`[{"technique":{"id":"T1059"},"result":"fail","rawOutput":"connecting password=` + secretValue + `",
		"details":"ran curl -H api_key=AbCdEf0123456789XyZ9","detectionAlert":{"commandLine":"tool token=AbCdEf0123456789XyZ9"}}]`)
	out, changed, err := ScrubResults(raw)
	if err != nil {
		t.Fatalf("ScrubResults: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true for a stored secret")
	}
	if strings.Contains(string(out), secretValue) || strings.Contains(string(out), "AbCdEf0123456789XyZ9") {
		t.Errorf("stored output still holds a secret: %s", out)
	}
	if !json.Valid(out) {
		t.Errorf("scrubbed output is not valid JSON: %s", out)
	}
}

func TestScrubResults_CleanRowUnchanged(t *testing.T) {
	raw := []byte(`[{"technique":{"id":"T1059"},"result":"pass","rawOutput":"ordinary output"}]`)
	out, changed, err := ScrubResults(raw)
	if err != nil {
		t.Fatalf("ScrubResults: %v", err)
	}
	if changed {
		t.Error("changed = true for a row with no secrets")
	}
	if string(out) != string(raw) {
		t.Errorf("unchanged row was rewritten: %s", out)
	}
}

func TestScrubResults_Idempotent(t *testing.T) {
	raw := []byte(`[{"technique":{"id":"T1059"},"result":"fail","rawOutput":"password=` + secretValue + `"}]`)
	once, _, err := ScrubResults(raw)
	if err != nil {
		t.Fatalf("first scrub: %v", err)
	}
	twice, changed, err := ScrubResults(once)
	if err != nil {
		t.Fatalf("second scrub: %v", err)
	}
	if changed {
		t.Error("a second pass changed an already-scrubbed row")
	}
	if string(twice) != string(once) {
		t.Errorf("second pass altered output: %s", twice)
	}
}

func TestScrubAlerts_RemovesCommandLineSecret(t *testing.T) {
	raw := []byte(`[{"channel":"edr","provider":"crowdstrike","eventId":1,"commandLine":"curl.exe -H api_key=AbCdEf0123456789XyZ9"}]`)
	out, changed, err := ScrubAlerts(raw)
	if err != nil {
		t.Fatalf("ScrubAlerts: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true for a stored alert secret")
	}
	if strings.Contains(string(out), "AbCdEf0123456789XyZ9") {
		t.Errorf("alert still holds the secret: %s", out)
	}
}
