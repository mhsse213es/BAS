package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/audspect/bas/internal/integrity"
)

// Test-only signing key for campaign definitions. It is generated in memory and
// never written to disk, so the real project key is not needed to run tests.
var (
	killChainKeyOnce sync.Once
	killChainKey     *rsa.PrivateKey
)

func testKillChainKey() *rsa.PrivateKey {
	killChainKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(fmt.Sprintf("killchain test key: %v", err))
		}
		killChainKey = k
		killChainVerifier = integrity.NewKeyVerifier(&k.PublicKey)
	})
	return killChainKey
}

// signDefinition signs the exact bytes of def the way scripts/signer.go does:
// base64 of an RSA PKCS#1 v1.5 signature over the SHA-256 digest.
func signDefinition(priv *rsa.PrivateKey, def string) string {
	h := sha256.Sum256([]byte(def))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		panic(fmt.Sprintf("sign: %v", err))
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// signedEnvelope builds a create body whose signature covers def.
func signedEnvelope(def string) string {
	return `{"definition":` + def + `,"signature":"` + signDefinition(testKillChainKey(), def) + `"}`
}
