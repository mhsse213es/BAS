package protocol

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

// goldenPublicKeyPEM/goldenCanonicalJSON/goldenSignatureB64 are the agent-
// side half of the final whole-branch review's Important 4 golden
// vector -- see orchestrator/internal/cmdsigning/golden_vector_test.go's
// doc comment for the full rationale and the matching private key. Both
// files carry the IDENTICAL canonical-JSON and signature constants,
// generated once from the same fixed CommandEnvelope and RSA keypair,
// and each independently-defined CommandEnvelope type (two separate Go
// modules) is checked against them here. A change to either type's field
// order or json tags that broke wire-shape agreement fails one of these
// two tests directly, rather than only surfacing as an opaque
// signature-verification failure in production.
const goldenPublicKeyPEM = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAqspGNAJVin5pY74W+BzWW/KlbTrmw/Ohkj9ow0UJTQiLnz2AuCC3
hOZIhdGRUTKEZXU6u6Z/cHu7zGrutdymI1xqE2ySd+dokunvB7nhVMnfSUIs9SHi
9mSSCoERkSJPzRodspB5Phf3ZE3W0y0PLBzI3rmAZPFkYxESS7iU93Sy+palYv5r
xqpUWmhqFrosUuc3zLYPlItXRrmLAuG6nqdrZBRLOdmbi5DE8IfPS5rgOc2xkh+2
h8s6tjMWajgriKQmgbuxHAC+I8yak7nag+Ff6Gw9OKlQMBI7FIhNJTxt5J+YoU0o
/NgsNivJak4NXQ9MlGAPmvNPVmwSpuYZDQIDAQAB
-----END RSA PUBLIC KEY-----
`

const goldenCanonicalJSON = `{"version":1,"commandId":"golden-cmd-0001","commandType":"command_cancel","agentId":"golden0000000001","issuedAt":"2026-01-15T12:00:00Z","expiresAt":"2026-01-15T12:01:00Z","nonce":"golden-nonce-0001","payload":{"reason":"golden vector test"},"executionClass":"non_destructive"}`

const goldenSignatureB64 = `h/ujxSnSpL6wEsP+1h0YHHptT7w/YfR7cn4yhqqOo1A1XG6XUbmombUKhJOKt/XQrfLaW5l6aQb46rZ/GUsllLEMSDqa1grQDFly+fuVjU9ip1OJh+m9vLm1mBu6hGnMR7D0wZGVQIkKZ9yNgShSGpgODXuhPo5yuWzaXlF53YRXun35VjwKgbrr2ZswMNgETJqDsPqdK+4sOydXIRn9dni1DowFL66x00OfWV7dNB3ApzxNTXggR8yo/iHvcG2K2U4LbQ1R9hc2joPv9ij5NADUbQ5uOXs3il3c+MloqeXvn5pJQKIRKVYGhZrCpqe70wrsP8eTTko2HBzoV5shWg==`

func goldenEnvelope(t *testing.T) CommandEnvelope {
	t.Helper()
	issuedAt := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	return CommandEnvelope{
		Version:     CommandEnvelopeVersion,
		CommandID:   "golden-cmd-0001",
		CommandType: "command_cancel",
		AgentID:     "golden0000000001",
		IssuedAt:    issuedAt,
		ExpiresAt:   issuedAt.Add(60 * time.Second),
		Nonce:       "golden-nonce-0001",
		Payload:     json.RawMessage(`{"reason":"golden vector test"}`),
		// New for B5: exercises CommandEnvelope's aggregate execution-class
		// field, in addition to the fields the original B4 golden vector
		// already covered -- see docs/superpowers/specs/
		// 2026-09-29-destructive-action-guardrail-b5-design.md.
		ExecutionClass: "non_destructive",
	}
}

func goldenPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(goldenPublicKeyPEM))
	if block == nil {
		t.Fatal("decode golden public key PEM: no PEM block found")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse golden public key: %v", err)
	}
	return pub
}

// TestGoldenVector_CanonicalJSONMatchesFrozenBytes proves this module's
// CommandEnvelope.CanonicalJSON() produces exactly the same frozen wire
// bytes as orchestrator/internal/models's independently-defined type --
// see that package's sibling test of the same name.
func TestGoldenVector_CanonicalJSONMatchesFrozenBytes(t *testing.T) {
	got, err := goldenEnvelope(t).CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != goldenCanonicalJSON {
		t.Errorf("canonical JSON drifted from the frozen golden vector.\ngot:  %s\nwant: %s", got, goldenCanonicalJSON)
	}
}

// TestGoldenVector_VerifiesFrozenSignature proves this agent's
// verification arithmetic (SHA-256 over CanonicalJSON, RSA PKCS#1v1.5)
// accepts the exact signature the orchestrator's SignEnvelope produced
// for the identical envelope and key -- see the orchestrator-side
// TestGoldenVector_SignEnvelopeMatchesFrozenSignature, which pins the
// producing half of this same fixed pair. This is the cross-module
// round trip: bytes signed by one module's type, verified by the
// other's, both independently derived from the same frozen source, not
// from a live signing call in this test.
func TestGoldenVector_VerifiesFrozenSignature(t *testing.T) {
	sig, err := base64.StdEncoding.DecodeString(goldenSignatureB64)
	if err != nil {
		t.Fatalf("decode golden signature: %v", err)
	}
	canon, err := goldenEnvelope(t).CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	if err := rsa.VerifyPKCS1v15(goldenPublicKey(t), crypto.SHA256, hash[:], sig); err != nil {
		t.Errorf("frozen golden signature failed verification: %v", err)
	}
}
