package cmdsigning

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

// goldenPrivateKeyPEM/goldenCanonicalJSON/goldenSignatureB64 are a fixed,
// pinned RSA keypair, CommandEnvelope, and its expected canonical-JSON and
// signature bytes -- generated once (see the golden_vector_test.go doc
// comment in agent/protocol for the sibling half of this pair) and frozen
// here. agent/protocol/golden_vector_test.go carries the identical
// canonical-JSON and signature constants and verifies them against its
// own, independently-defined CommandEnvelope type: this is the final
// whole-branch review's Important 4 -- proof that the two Go types (two
// separate modules) produce byte-identical wire bytes, checked by
// actually running both, not by re-reading source side by side.
const goldenPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqspGNAJVin5pY74W+BzWW/KlbTrmw/Ohkj9ow0UJTQiLnz2A
uCC3hOZIhdGRUTKEZXU6u6Z/cHu7zGrutdymI1xqE2ySd+dokunvB7nhVMnfSUIs
9SHi9mSSCoERkSJPzRodspB5Phf3ZE3W0y0PLBzI3rmAZPFkYxESS7iU93Sy+pal
Yv5rxqpUWmhqFrosUuc3zLYPlItXRrmLAuG6nqdrZBRLOdmbi5DE8IfPS5rgOc2x
kh+2h8s6tjMWajgriKQmgbuxHAC+I8yak7nag+Ff6Gw9OKlQMBI7FIhNJTxt5J+Y
oU0o/NgsNivJak4NXQ9MlGAPmvNPVmwSpuYZDQIDAQABAoIBAClNUNRngxnCr8hl
8iaOzL0ALUbA0YkuLBLSwEpGsfTd3ewEwtHkYZUjXoL0FvUgpxllE+7I2TVRyuzo
qDE1Or0+7k0jurkB7o1mwr4m0sn/Jr8P4JDoYLtuv02IgH/NYSiLygZCf3uHbrWk
SFEZ6rsje+U2zYi7wqfde0PyD55Wxl18mnaNPKQn+to8j3KpPr7EP9sqiZPCQVN5
Gwght5ZfsNKXSVU77des1JL90unl7YL3WkwB5LEMP/CLeBx4doCruB0eUpUwHEf7
z5MBWsUow8jFS/LN6IkyebucLTV/N3Xg8Rgi9Gw3XEMD7dBxJMRNmgNNS8kIcM6U
tZPT9BECgYEAxatdeNV3/qQJ0y7wVn2fuRn5NidVj2Qyry0/+dSaE4RSKdWrxOID
GVmq3v4Kp9h8oJiV1pD2ygohS5FQyq+RjuQJdeEaqOj6FomK+8L6Gie59si95Ra2
cHyulQEJHwTOvWtJbWrcZJ7xKjL5Dxk4Z+1DfhwzeAOXlJA4pwvFT1ECgYEA3TBb
JeMoz20WxDEgwIqXTtFsYALrPpFaoUNjX4w8cHHZDgpxbReTAVbTCCpg/D7nMYzk
aAtFvKrw1SM0n6KfXBlEfZRZl+8TmgEn0981/BOF1g6T+8tKtfG/HU9XBwrcnmCb
wEGfFHUJWlZhpmw4xVv8qc70HeyA63IrlW7J1v0CgYAsBhJ3SvPCnr4hbp7QZIIi
M4qxaOlBWkt/gFBzT8pQ9nNmJdRvsPaHutS3fVTaNPjsu48Djp2oOcFYlzCrM5bz
gA4rVssdO2YXhuKRV8dj890S/XptfzV6sAoh3W0un198CFz+JYKYVl3XzCp0FmXd
n5YcjCNaY1JrIAO+EH0NQQKBgHdr/Epgc1BK3dffjodmTHtJpvHPoaOOZxhagfS8
ioVLcp2aFdOIvt4iOp5WAzct3zVplIh4TZan1I+/ClKGQvQ+0DPdPOJDOpoTtaU3
Braq87+27z8ra5MAiucQRzSOML9x+aW7yGALMJmNuftYwu4L1Eb6beMaJiD4638q
6d8hAoGBAI1MsKIEsijBagAUvDRo435NBkbvIXuBDo4V4swh63ZWiVtp1vaSpuN8
GkZH6UuSsMlzjgmPMli4XF+clN6bVIT5pvuUdrDIg7NMpVC4yfWE1D2z1k0Y2iqV
TXWZxk4HmIDrmLh7oaD5FVzzAUT5Gq3MkAGVkIBmaFm/Y6j/Y/1O
-----END RSA PRIVATE KEY-----
`

const goldenCanonicalJSON = `{"version":1,"commandId":"golden-cmd-0001","commandType":"command_cancel","agentId":"golden0000000001","issuedAt":"2026-01-15T12:00:00Z","expiresAt":"2026-01-15T12:01:00Z","nonce":"golden-nonce-0001","payload":{"reason":"golden vector test"},"executionClass":"non_destructive"}`

const goldenSignatureB64 = `h/ujxSnSpL6wEsP+1h0YHHptT7w/YfR7cn4yhqqOo1A1XG6XUbmombUKhJOKt/XQrfLaW5l6aQb46rZ/GUsllLEMSDqa1grQDFly+fuVjU9ip1OJh+m9vLm1mBu6hGnMR7D0wZGVQIkKZ9yNgShSGpgODXuhPo5yuWzaXlF53YRXun35VjwKgbrr2ZswMNgETJqDsPqdK+4sOydXIRn9dni1DowFL66x00OfWV7dNB3ApzxNTXggR8yo/iHvcG2K2U4LbQ1R9hc2joPv9ij5NADUbQ5uOXs3il3c+MloqeXvn5pJQKIRKVYGhZrCpqe70wrsP8eTTko2HBzoV5shWg==`

func goldenEnvelope(t *testing.T) models.CommandEnvelope {
	t.Helper()
	issuedAt := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	return models.CommandEnvelope{
		Version:     models.CommandEnvelopeVersion,
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

func goldenPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(goldenPrivateKeyPEM))
	if block == nil {
		t.Fatal("decode golden private key PEM: no PEM block found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse golden private key: %v", err)
	}
	return key
}

// TestGoldenVector_CanonicalJSONMatchesFrozenBytes proves this module's
// CommandEnvelope.CanonicalJSON() still produces exactly the frozen wire
// bytes agent/protocol's golden vector test also asserts against -- a
// change to either type's field order or json tags that broke agreement
// would fail here (or there) rather than only surfacing as an opaque
// signature-verification failure in production.
func TestGoldenVector_CanonicalJSONMatchesFrozenBytes(t *testing.T) {
	got, err := goldenEnvelope(t).CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != goldenCanonicalJSON {
		t.Errorf("canonical JSON drifted from the frozen golden vector.\ngot:  %s\nwant: %s", got, goldenCanonicalJSON)
	}
}

// TestGoldenVector_SignEnvelopeMatchesFrozenSignature proves SignEnvelope
// still produces the exact frozen signature bytes for the frozen key and
// envelope -- RSA PKCS#1v1.5 signing is deterministic (no random padding
// salt, unlike PSS), so a byte-for-byte match is the correct expectation,
// not just successful re-verification.
func TestGoldenVector_SignEnvelopeMatchesFrozenSignature(t *testing.T) {
	key := goldenPrivateKey(t)
	sig, err := SignEnvelope(key, goldenEnvelope(t))
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	gotB64 := base64.StdEncoding.EncodeToString(sig)
	if gotB64 != goldenSignatureB64 {
		t.Errorf("signature drifted from the frozen golden vector.\ngot:  %s\nwant: %s", gotB64, goldenSignatureB64)
	}
}
