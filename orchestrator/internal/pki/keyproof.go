package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// CSRKeyFingerprint returns the SHA-256 of a CSR's public key (its DER SubjectPublicKeyInfo), in lowercase hex.
// The CSR's self-signature is verified first, so the fingerprint is only returned for a request that proves
// possession of the matching private key. A fingerprint is recorded when a certificate is issued, and a later
// reinstall that presents a CSR with the same fingerprint is the same identity (see the enrolment handler).
func CSRKeyFingerprint(csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", errors.New("decode CSR PEM: expected a CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal CSR public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
