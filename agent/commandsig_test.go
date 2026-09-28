package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"audspect/agent/protocol"
)

// signingTestKey mints a throwaway RSA keypair + self-signed cert standing
// in for the deployment command-signing key, and returns the key plus its
// PEM-encoded certificate -- mirrors this package's existing newTestCA
// (bootstrap_test.go) pattern for the mTLS CA, but for RSA/command-signing
// specifically.
func signingTestKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048) // small key -- fast test
	if err != nil {
		t.Fatalf("generate signing test key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test command-signing key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create signing test cert: %v", err)
	}
	certPEM := pemEncodeCert(t, der)
	return key, certPEM
}

func pemEncodeCert(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func setupSigningTrust(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	key, certPEM := signingTestKey(t)
	if err := saveCommandSigningCert(certPEM); err != nil {
		t.Fatalf("saveCommandSigningCert: %v", err)
	}
	return key
}

func validEnvelope(t *testing.T, key *rsa.PrivateKey, agentID string) protocol.CommandEnvelope {
	t.Helper()
	now := time.Now().UTC()
	env := protocol.CommandEnvelope{
		Version:     protocol.CommandEnvelopeVersion,
		CommandID:   "cmd-" + t.Name(),
		CommandType: "command_scenario",
		AgentID:     agentID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(60 * time.Second),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"runId":"run-1"}`),
	}
	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign test envelope: %v", err)
	}
	env.Signature = sig
	return env
}

func marshalEnvelope(t *testing.T, env protocol.CommandEnvelope) []byte {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

func TestVerifyCommandEnvelope_AcceptsValidEnvelope(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")

	got, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario")
	if err != nil {
		t.Fatalf("expected acceptance, got: %v", err)
	}
	if got.CommandID != env.CommandID {
		t.Errorf("CommandID = %q, want %q", got.CommandID, env.CommandID)
	}
}

func TestVerifyCommandEnvelope_RejectsInvalidSignature(t *testing.T) {
	setupSigningTrust(t) // establishes trust in a DIFFERENT key than the one below
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, wrongKey, "abc123deadbeef01")

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection for a signature from an untrusted key")
	}
}

func TestVerifyCommandEnvelope_RejectsExpiredEnvelope(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.ExpiresAt = time.Now().Add(-time.Second) // already expired
	env.IssuedAt = time.Now().Add(-2 * time.Minute)
	env = resign(t, key, env)

	_, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario")
	if err == nil {
		t.Fatal("expected rejection for an expired envelope")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should name the specific failed check (expired), got: %v", err)
	}
}

func TestVerifyCommandEnvelope_RejectsExpiresAtBeforeIssuedAt(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.ExpiresAt = env.IssuedAt.Add(-time.Second)
	env = resign(t, key, env)

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection when expiresAt <= issuedAt")
	}
}

func TestVerifyCommandEnvelope_RejectsIssuedAtFarInFuture(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.IssuedAt = time.Now().Add(time.Hour)
	env.ExpiresAt = env.IssuedAt.Add(60 * time.Second)
	env = resign(t, key, env)

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection for an issuedAt unreasonably far in the future")
	}
}

func TestVerifyCommandEnvelope_RejectsUnsupportedVersion(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.Version = 999
	env = resign(t, key, env)

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection for an unsupported envelope version")
	}
}

func TestVerifyCommandEnvelope_RejectsAgentIDMismatch(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "some-other-agent-entirely")

	_, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario")
	if err == nil {
		t.Fatal("expected rejection when envelope.AgentID does not match this agent's own identity -- a captured envelope must not be usable against a different agent")
	}
}

func TestVerifyCommandEnvelope_RejectsCommandTypeMismatch(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01") // signed as command_scenario

	// The WS message claimed a different type than what's inside the
	// signed envelope -- must be rejected, not silently accepted using
	// whichever type wins.
	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_cancel"); err == nil {
		t.Fatal("expected rejection when the envelope's signed CommandType does not match the WS message's claimed type")
	}
}

func TestVerifyCommandEnvelope_RejectsReplayedCommandID(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	raw := marshalEnvelope(t, env)

	if _, err := a.verifyCommandEnvelope(raw, "command_scenario"); err != nil {
		t.Fatalf("first delivery should succeed, got: %v", err)
	}
	if _, err := a.verifyCommandEnvelope(raw, "command_scenario"); err == nil {
		t.Fatal("expected rejection of the exact same CommandID delivered a second time")
	}
}

func TestVerifyCommandEnvelope_RejectsWhenNoTrustEstablished(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir) // no saveCommandSigningCert call -- enrollment never delivered trust
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection when no command-signing certificate has ever been persisted")
	}
}

// resign re-signs env after a test has mutated one of its fields --
// mirrors how a real forged/tampered envelope with a stale signature
// would fail signature verification if NOT re-signed; tests that need to
// isolate ONE specific rejection reason (expiry, version, etc.) re-sign
// so signature validity itself isn't the thing being tested there.
func resign(t *testing.T, key *rsa.PrivateKey, env protocol.CommandEnvelope) protocol.CommandEnvelope {
	t.Helper()
	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("resign: %v", err)
	}
	env.Signature = sig
	return env
}
