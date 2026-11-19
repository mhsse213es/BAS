package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// GenerateTestKeypair returns a fresh RSA keypair and its PEM-encoded
// public key, for tests that need to exercise VerifiedRead/Check's
// signature verification without the real production private key (which
// never lives in this repository — see packaging/licensing/keygen.sh).
// Callers typically assign the returned PEM to PublicKeyPEM for the
// duration of the test, then restore the original value.
func GenerateTestKeypair() (*rsa.PrivateKey, string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("license: GenerateTestKeypair: %v", err))
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("license: GenerateTestKeypair: %v", err))
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return priv, pubPEM
}

// SignForTest signs lic's canonical payload with priv and returns a copy
// with Signature set. priv is always a test-generated keypair (see
// GenerateTestKeypair), never the real production key, so this cannot be
// used to forge a license any deployed binary would trust.
func SignForTest(priv *rsa.PrivateKey, lic License) License {
	hash := sha256.Sum256([]byte(lic.payload()))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		panic(fmt.Sprintf("license: SignForTest: %v", err))
	}
	lic.Signature = base64.StdEncoding.EncodeToString(sig)
	return lic
}

// SetBuildTierForTest sets the compiled-in build tier for a test and returns the function that restores it. The real
// value is stamped at link time and cannot be changed on a running server.
func SetBuildTierForTest(tier string) (restore func()) {
	old := buildTier
	buildTier = tier
	return func() { buildTier = old }
}
