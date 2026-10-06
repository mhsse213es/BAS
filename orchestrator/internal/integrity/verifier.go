package integrity

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Verifier checks a scenario artifact's RSA-SHA256 signature. verified is
// true ONLY when a real verification succeeded -- callers must never treat
// a nil error as proof (dev builds return (false, nil)). See TCF Phase 1
// spec §5.1.
type Verifier interface {
	Verify(content, sig []byte) (verified bool, err error)
	SigningEnabled() bool
}

// CompiledVerifier verifies with the compiled-in ScenarioPublicKeyPEM.
type CompiledVerifier struct{}

func (CompiledVerifier) SigningEnabled() bool { return signingEnabled() }

func (CompiledVerifier) Verify(content, sig []byte) (bool, error) {
	return VerifyScenarioBytes(content, sig)
}

// VerifyScenarioBytes verifies raw (already base64-decoded) signature bytes
// against content with the compiled-in key. Dev builds: (false, nil).
func VerifyScenarioBytes(content, sig []byte) (bool, error) {
	if !signingEnabled() {
		return false, nil
	}
	pub, err := parseContentPublicKey()
	if err != nil {
		return false, fmt.Errorf("content public key: %w", err)
	}
	return verifyWith(pub, content, sig)
}

func verifyWith(pub *rsa.PublicKey, content, sig []byte) (bool, error) {
	if len(sig) == 0 {
		return false, ErrUnsigned
	}
	h := sha256.Sum256(content)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return false, fmt.Errorf("signature invalid: %w", err)
	}
	return true, nil
}

type keyVerifier struct{ pub *rsa.PublicKey }

// NewKeyVerifier verifies with an explicit public key (tests; future
// rotated keys). Always reports signing enabled.
func NewKeyVerifier(pub *rsa.PublicKey) Verifier { return keyVerifier{pub: pub} }

func (k keyVerifier) SigningEnabled() bool { return true }
func (k keyVerifier) Verify(content, sig []byte) (bool, error) {
	return verifyWith(k.pub, content, sig)
}

// ReadBuiltinSignature reads path+".sig" (base64, as written by
// scripts/signer.go) and verifies it with v.
//
//   - signing enabled, .sig missing  -> ErrUnsigned
//   - signing enabled, .sig invalid  -> (sig, false, err)
//   - signing disabled (dev build)   -> (sig-or-nil, false, nil)
func ReadBuiltinSignature(v Verifier, path string, content []byte) ([]byte, bool, error) {
	raw, err := os.ReadFile(path + ".sig")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if v.SigningEnabled() {
				return nil, false, fmt.Errorf("%w: %s", ErrUnsigned, path)
			}
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read .sig: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, false, fmt.Errorf("decode signature: %w", err)
	}
	if !v.SigningEnabled() {
		return sig, false, nil
	}
	ok, err := v.Verify(content, sig)
	if err != nil {
		return sig, false, fmt.Errorf("scenario signature invalid for %s -- file may be tampered: %w", path, err)
	}
	return sig, ok, nil
}
