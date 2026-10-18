package integrity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func selfIntegrityTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func selfIntegritySign(t *testing.T, k *rsa.PrivateKey, content []byte) []byte {
	t.Helper()
	h := sha256.Sum256(content)
	s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// writeSelfIntegrityManifest writes a SELFINTEGRITY.sha256 (+.sig) listing
// hash for "orchestrator", signed by k, and returns the manifest path.
func writeSelfIntegrityManifest(t *testing.T, dir, hash string, k *rsa.PrivateKey) string {
	t.Helper()
	content := []byte(hash + "  orchestrator\n")
	path := filepath.Join(dir, "SELFINTEGRITY.sha256")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	sig := selfIntegritySign(t, k, content)
	sigB64 := []byte(base64.StdEncoding.EncodeToString(sig))
	if err := os.WriteFile(path+".sig", sigB64, 0644); err != nil {
		t.Fatalf("write manifest sig: %v", err)
	}
	return path
}

func hashOfString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hashHex(h)
}

// hashHex mirrors hashFile's hex encoding without needing a real file.
func hashHex(sum [32]byte) string {
	const hextable = "0123456789abcdef"
	b := make([]byte, 64)
	for i, c := range sum {
		b[i*2] = hextable[c>>4]
		b[i*2+1] = hextable[c&0x0f]
	}
	return string(b)
}

// selfExecutableAndHash writes content to a temp file and returns its
// path and hash, standing in for "the running executable" — tests can't
// control the real os.Executable() path, so CheckSelfIntegrity's own
// os.Executable() call is exercised separately (TestCheckSelfIntegrity_UsesRealExecutablePath);
// everything else here tests checkSelfIntegrity's decision logic given an
// executable path, via a thin wrapper.
func writeExecutableFixture(t *testing.T, dir, content string) (path, hash string) {
	t.Helper()
	path = filepath.Join(dir, "fake-exe")
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write executable fixture: %v", err)
	}
	return path, hashOfString(content)
}

func TestCheckSelfIntegrity_NotExpected_SkipsEntirely_EvenWithNoManifest(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)
	manifestPath := filepath.Join(dir, "does-not-exist", "SELFINTEGRITY.sha256")

	got := checkSelfIntegrity(nil, nil, manifestPath, false, v)
	if got != SelfIntegrityDisabled {
		t.Errorf("outcome = %q, want %q", got, SelfIntegrityDisabled)
	}
}

func TestCheckSelfIntegrity_Expected_ManifestMissing_IsCritical(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)
	manifestPath := filepath.Join(dir, "SELFINTEGRITY.sha256") // never written

	got := checkSelfIntegrity(nil, nil, manifestPath, true, v)
	if got != SelfIntegrityCritical {
		t.Errorf("outcome = %q, want %q (deleting the manifest must not disable the check)", got, SelfIntegrityCritical)
	}
}

func TestCheckSelfIntegrity_ManifestUnsigned_IsCritical(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)
	manifestPath := filepath.Join(dir, "SELFINTEGRITY.sha256")
	if err := os.WriteFile(manifestPath, []byte("abc  orchestrator\n"), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	// no .sig written

	got := checkSelfIntegrity(nil, nil, manifestPath, true, v)
	if got != SelfIntegrityCritical {
		t.Errorf("outcome = %q, want %q", got, SelfIntegrityCritical)
	}
}

func TestCheckSelfIntegrity_ManifestSignedByWrongKey_IsCritical(t *testing.T) {
	dir := t.TempDir()
	signingKey := selfIntegrityTestKey(t) // what actually signed it
	trustedKey := selfIntegrityTestKey(t) // what the verifier trusts
	v := NewKeyVerifier(&trustedKey.PublicKey)

	manifestPath := writeSelfIntegrityManifest(t, dir, "deadbeef", signingKey)

	got := checkSelfIntegrity(nil, nil, manifestPath, true, v)
	if got != SelfIntegrityCritical {
		t.Errorf("outcome = %q, want %q (manifest signed by a non-trusted key)", got, SelfIntegrityCritical)
	}
}

func TestCheckSelfIntegrity_HashMismatch_IsCritical(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)

	_, realHash := writeExecutableFixture(t, dir, "real binary bytes")
	manifestPath := writeSelfIntegrityManifest(t, dir, realHash, k)

	// Simulate tampering: the manifest says realHash, but the "executable"
	// hashFile will actually read has different content.
	exePath := filepath.Join(dir, "tampered-exe")
	if err := os.WriteFile(exePath, []byte("tampered binary bytes"), 0755); err != nil {
		t.Fatalf("write tampered exe: %v", err)
	}

	got := checkSelfIntegrityAgainstExecutable(nil, nil, manifestPath, true, v, exePath)
	if got != SelfIntegrityCritical {
		t.Errorf("outcome = %q, want %q", got, SelfIntegrityCritical)
	}
}

func TestCheckSelfIntegrity_HashMatches_IsOK(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)

	exePath, hash := writeExecutableFixture(t, dir, "real binary bytes")
	manifestPath := writeSelfIntegrityManifest(t, dir, hash, k)

	got := checkSelfIntegrityAgainstExecutable(nil, nil, manifestPath, true, v, exePath)
	if got != SelfIntegrityOK {
		t.Errorf("outcome = %q, want %q", got, SelfIntegrityOK)
	}
}

func TestCheckSelfIntegrity_ManifestEntryMissing_IsCritical(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)

	// Signed, but lists a different filename, not "orchestrator".
	content := []byte("abc  something-else\n")
	manifestPath := filepath.Join(dir, "SELFINTEGRITY.sha256")
	os.WriteFile(manifestPath, content, 0644)
	sig := selfIntegritySign(t, k, content)
	os.WriteFile(manifestPath+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0644)

	got := checkSelfIntegrity(nil, nil, manifestPath, true, v)
	if got != SelfIntegrityCritical {
		t.Errorf("outcome = %q, want %q", got, SelfIntegrityCritical)
	}
}

func TestCheckSelfIntegrity_ExecutableUnreadable_IsInspectionErrorNotCritical(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)

	manifestPath := writeSelfIntegrityManifest(t, dir, "deadbeef", k)
	missingExePath := filepath.Join(dir, "does-not-exist")

	got := checkSelfIntegrityAgainstExecutable(nil, nil, manifestPath, true, v, missingExePath)
	if got != SelfIntegrityInspectionError {
		t.Errorf("outcome = %q, want %q (a read error must not be escalated to critical)", got, SelfIntegrityInspectionError)
	}
}

// TestCheckSelfIntegrity_RestoringOriginalBinary_Succeeds proves recovery
// goes through the SAME strict check as any other call: once the real,
// matching binary is back in place, the check succeeds again. The
// tamper_handlers.go-level policy (don't auto-clear DispatchBlocked just
// because this succeeds) is tested separately in internal/api.
func TestCheckSelfIntegrity_RestoringOriginalBinary_Succeeds(t *testing.T) {
	dir := t.TempDir()
	k := selfIntegrityTestKey(t)
	v := NewKeyVerifier(&k.PublicKey)

	exePath, hash := writeExecutableFixture(t, dir, "real binary bytes")
	manifestPath := writeSelfIntegrityManifest(t, dir, hash, k)

	// Tamper.
	if err := os.WriteFile(exePath, []byte("tampered"), 0755); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if got := checkSelfIntegrityAgainstExecutable(nil, nil, manifestPath, true, v, exePath); got != SelfIntegrityCritical {
		t.Fatalf("outcome after tampering = %q, want %q", got, SelfIntegrityCritical)
	}

	// Restore the exact original bytes.
	if err := os.WriteFile(exePath, []byte("real binary bytes"), 0755); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := checkSelfIntegrityAgainstExecutable(nil, nil, manifestPath, true, v, exePath); got != SelfIntegrityOK {
		t.Errorf("outcome after restoring the original binary = %q, want %q", got, SelfIntegrityOK)
	}
}

func TestSelfIntegrityExpected_DefaultsFalse(t *testing.T) {
	if SelfIntegrityExpected() {
		t.Error("SelfIntegrityExpected() = true by default; want false unless set via -ldflags by the Docker build")
	}
}

func TestRegisterSelfIntegrityManifest_TickIsNoOpUntilRegistered(t *testing.T) {
	selfIntegrityMu.Lock()
	wasRegistered := selfIntegrityRegistered
	wasPath := selfIntegrityManifestPath
	selfIntegrityRegistered = false
	selfIntegrityManifestPath = ""
	selfIntegrityMu.Unlock()
	defer func() {
		selfIntegrityMu.Lock()
		selfIntegrityRegistered = wasRegistered
		selfIntegrityManifestPath = wasPath
		selfIntegrityMu.Unlock()
	}()

	// Must not panic or touch any file -- there is nothing to check yet.
	checkSelfIntegrityTick(nil, nil)

	RegisterSelfIntegrityManifest("/some/path")
	selfIntegrityMu.Lock()
	registered := selfIntegrityRegistered
	path := selfIntegrityManifestPath
	selfIntegrityMu.Unlock()
	if !registered || path != "/some/path" {
		t.Errorf("after RegisterSelfIntegrityManifest: registered=%v path=%q", registered, path)
	}
}
