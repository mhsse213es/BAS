package cmdsigning

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func testEnvelope(t *testing.T) models.CommandEnvelope {
	t.Helper()
	return models.CommandEnvelope{
		Version:     models.CommandEnvelopeVersion,
		CommandID:   "cmd-1",
		CommandType: "command_scenario",
		AgentID:     "abc123deadbeef01",
		RunID:       "run-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(60 * time.Second),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"runId":"run-1"}`),
	}
}

func TestSignEnvelope_ProducesVerifiableSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // small key -- fast test, algorithm-only assertion
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	env := testEnvelope(t)

	sig, err := SignEnvelope(priv, env)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("SignEnvelope returned an empty signature")
	}

	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hash[:], sig); err != nil {
		t.Errorf("signature does not verify against the canonical JSON: %v", err)
	}
}

func TestSignEnvelope_DifferentEnvelopesProduceDifferentSignatures(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	env1 := testEnvelope(t)
	env2 := testEnvelope(t)
	env2.CommandID = "cmd-2"

	sig1, err := SignEnvelope(priv, env1)
	if err != nil {
		t.Fatalf("SignEnvelope env1: %v", err)
	}
	sig2, err := SignEnvelope(priv, env2)
	if err != nil {
		t.Fatalf("SignEnvelope env2: %v", err)
	}
	if string(sig1) == string(sig2) {
		t.Error("two envelopes differing only in CommandID produced identical signatures")
	}
}
