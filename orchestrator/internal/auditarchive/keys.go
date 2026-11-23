package auditarchive

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPrivateKey reads an RSA private key in PKCS#1 PEM form. The key is used only to seal purge batches, and it is
// kept apart from the database and from the application's own secrets.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read archive private key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("archive private key is not PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse archive private key: %w", err)
	}
	if k.N.BitLen() < 2048 {
		return nil, errors.New("archive private key must be at least 2048 bits")
	}
	return k, nil
}

// LoadPublicKey reads the matching RSA public key in PKIX PEM form, used to verify archives.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read archive public key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("archive public key is not PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse archive public key: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("archive public key is not RSA")
	}
	return pub, nil
}
