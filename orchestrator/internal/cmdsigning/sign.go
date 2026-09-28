package cmdsigning

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/audspect/bas/internal/models"
)

// SignEnvelope signs env's canonical JSON (see
// models.CommandEnvelope.CanonicalJSON) with priv, using the same
// RSA-4096/PKCS#1v1.5/SHA-256 scheme internal/integrity uses for the
// (entirely separate) vendor key -- consistency of algorithm choice only,
// never a shared key or shared code path with that package.
func SignEnvelope(priv *rsa.PrivateKey, env models.CommandEnvelope) ([]byte, error) {
	canon, err := env.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	hash := sha256.Sum256(canon)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}
	return sig, nil
}
