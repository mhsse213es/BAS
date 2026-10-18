package license

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withSignedLicense writes a validly-signed license to a temp file under a
// test-generated keypair (installed as PublicKeyPEM for the test's
// duration) and returns its path plus the raw signed bytes, so a test can
// tamper with a copy of those bytes without needing to re-derive a valid
// signature.
func withSignedLicense(t *testing.T, lic License) (licPath string, signedBytes []byte) {
	t.Helper()
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	t.Cleanup(func() { PublicKeyPEM = orig })

	signed := SignForTest(priv, lic)
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed license: %v", err)
	}
	licPath = filepath.Join(t.TempDir(), "bas.lic")
	if err := os.WriteFile(licPath, data, 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	return licPath, data
}

func validTestLicense() License {
	return License{
		Customer:   "Acme Corp",
		CustomerID: "acme-1",
		IssuedAt:   "2026-01-01",
		ExpiresAt:  time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02"),
		Features:   []string{"base", "enterprise"},
	}
}

func TestVerifiedRead_ValidSignedLicense_Succeeds(t *testing.T) {
	licPath, _ := withSignedLicense(t, validTestLicense())
	lic, err := VerifiedRead(licPath)
	if err != nil {
		t.Fatalf("VerifiedRead: unexpected error: %v", err)
	}
	if lic.Customer != "Acme Corp" || lic.CustomerID != "acme-1" {
		t.Errorf("VerifiedRead returned %+v, want the original signed fields", lic)
	}
}

func TestVerifiedRead_TamperedExpiry_Fails(t *testing.T) {
	licPath, signedBytes := withSignedLicense(t, validTestLicense())
	var raw map[string]any
	if err := json.Unmarshal(signedBytes, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw["expires_at"] = "2099-12-31" // extend validity, signature left untouched
	tampered, _ := json.Marshal(raw)
	if err := os.WriteFile(licPath, tampered, 0644); err != nil {
		t.Fatalf("write tampered license: %v", err)
	}
	if _, err := VerifiedRead(licPath); err == nil {
		t.Fatal("VerifiedRead: expected an error for a tampered expires_at, got nil")
	}
}

func TestVerifiedRead_TamperedCustomerID_Fails(t *testing.T) {
	licPath, signedBytes := withSignedLicense(t, validTestLicense())
	var raw map[string]any
	if err := json.Unmarshal(signedBytes, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw["customer_id"] = "someone-elses-id"
	tampered, _ := json.Marshal(raw)
	if err := os.WriteFile(licPath, tampered, 0644); err != nil {
		t.Fatalf("write tampered license: %v", err)
	}
	if _, err := VerifiedRead(licPath); err == nil {
		t.Fatal("VerifiedRead: expected an error for a tampered customer_id, got nil")
	}
}

func TestVerifiedRead_TamperedFeatures_Fails(t *testing.T) {
	licPath, signedBytes := withSignedLicense(t, validTestLicense())
	var raw map[string]any
	if err := json.Unmarshal(signedBytes, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw["features"] = []string{"every-feature-we-sell"}
	tampered, _ := json.Marshal(raw)
	if err := os.WriteFile(licPath, tampered, 0644); err != nil {
		t.Fatalf("write tampered license: %v", err)
	}
	if _, err := VerifiedRead(licPath); err == nil {
		t.Fatal("VerifiedRead: expected an error for tampered features, got nil")
	}
}

func TestVerifiedRead_MissingFile_Fails(t *testing.T) {
	if _, err := VerifiedRead(filepath.Join(t.TempDir(), "does-not-exist.lic")); err == nil {
		t.Fatal("VerifiedRead: expected an error for a missing file, got nil")
	}
}

func TestVerifiedRead_MalformedJSON_Fails(t *testing.T) {
	licPath := filepath.Join(t.TempDir(), "bas.lic")
	if err := os.WriteFile(licPath, []byte("{not json"), 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	if _, err := VerifiedRead(licPath); err == nil {
		t.Fatal("VerifiedRead: expected an error for malformed JSON, got nil")
	}
}

func TestVerifiedRead_SignedByWrongKey_Fails(t *testing.T) {
	// Sign with one keypair, but verify against a DIFFERENT one's public
	// key — models an attacker who generated their own keypair and
	// self-signed a replacement license, since they do not have Audspect's
	// real private key.
	wrongPriv, _ := GenerateTestKeypair()
	_, realPubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = realPubPEM
	t.Cleanup(func() { PublicKeyPEM = orig })

	lic := SignForTest(wrongPriv, validTestLicense())
	data, _ := json.Marshal(lic)
	licPath := filepath.Join(t.TempDir(), "bas.lic")
	if err := os.WriteFile(licPath, data, 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	if _, err := VerifiedRead(licPath); err == nil {
		t.Fatal("VerifiedRead: expected an error for a license signed by a non-matching key, got nil")
	}
}

func TestCheck_ValidSignedLicense_Succeeds(t *testing.T) {
	licPath, _ := withSignedLicense(t, validTestLicense())
	if err := Check(licPath); err != nil {
		t.Fatalf("Check: unexpected error: %v", err)
	}
}

func TestCheck_TamperedLicense_FailsClosed(t *testing.T) {
	licPath, signedBytes := withSignedLicense(t, validTestLicense())
	var raw map[string]any
	if err := json.Unmarshal(signedBytes, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw["expires_at"] = "2099-12-31"
	tampered, _ := json.Marshal(raw)
	if err := os.WriteFile(licPath, tampered, 0644); err != nil {
		t.Fatalf("write tampered license: %v", err)
	}
	if err := Check(licPath); err == nil {
		t.Fatal("Check: expected an error for a tampered license, got nil")
	}
}

func TestCheck_DevModeBypass_SkipsVerificationEntirely(t *testing.T) {
	orig := PublicKeyPEM
	PublicKeyPEM = "KEYGEN_REQUIRED"
	t.Cleanup(func() { PublicKeyPEM = orig })

	// A path that does not exist -- the whole point of the bypass is that
	// Check never even tries to read it.
	if err := Check(filepath.Join(t.TempDir(), "never-created.lic")); err != nil {
		t.Fatalf("Check in KEYGEN_REQUIRED mode: unexpected error: %v", err)
	}
}

// Check() with PublicKeyPEM still at its dev-mode placeholder always
// returns nil regardless of expiry — this test only exercises the
// production code path indirectly via Evaluate, since Check() itself
// requires a real signed .lic file on disk to test the signature branch
// meaningfully (out of scope here — Check()'s signature verification is
// unchanged by this task). This task's regression coverage is: Status()
// must agree with Evaluate() for the same three boundary cases Task 1
// already covers for Evaluate directly.
func TestStatus_Valid(t *testing.T) {
	if got := Status("2099-01-01"); got != "valid" {
		t.Errorf("Status = %q, want %q", got, "valid")
	}
}

func TestStatus_Expired(t *testing.T) {
	if got := Status("2000-01-01"); got != "expired" {
		t.Errorf("Status = %q, want %q", got, "expired")
	}
}

func TestStatus_ExpiringSoon(t *testing.T) {
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format("2006-01-02")
	if got := Status(soon); got != "expiring_soon" {
		t.Errorf("Status(%q) = %q, want %q", soon, got, "expiring_soon")
	}
}

func TestStatus_UnknownOnBadDate(t *testing.T) {
	if got := Status("garbage"); got != "unknown" {
		t.Errorf("Status = %q, want %q", got, "unknown")
	}
}
