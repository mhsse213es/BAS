package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
)

// newAgentKey makes a fresh agent key in memory only. Renewal uses it so a renewed certificate never
// carries the old key (audit F-07); nothing is written until the server has issued the certificate.
func newAgentKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func readKeyFile(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

func keyMatchesCert(key *ecdsa.PrivateKey, cert *x509.Certificate) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && key != nil && pub.Equal(&key.PublicKey)
}

// rotateCredentials stores a renewed certificate together with its NEW key. Both are first written
// beside the live files (".new"), then moved into place by recoverPendingRotation. If the process
// dies part-way, the next start finishes or discards the swap, so the stored pair always works.
func rotateCredentials(key *ecdsa.PrivateKey, certPEM []byte) error {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return fmt.Errorf("issued certificate: %w", err)
	}
	if !keyMatchesCert(key, cert) {
		return errors.New("issued certificate's public key does not match the new private key — refusing to persist it")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal new agent key: %w", err)
	}
	dir, _, certPath, keyPath := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	if err := os.WriteFile(keyPath+".new", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return fmt.Errorf("write pending key: %w", err)
	}
	if err := os.WriteFile(certPath+".new", certPEM, 0644); err != nil {
		os.Remove(keyPath + ".new")
		return fmt.Errorf("write pending certificate: %w", err)
	}
	return recoverPendingRotation()
}

// recoverPendingRotation completes or discards a certificate+key swap that rotateCredentials started.
// The pending certificate decides: it is promoted only together with the key it belongs to.
func recoverPendingRotation() error {
	_, _, certPath, keyPath := certPaths()
	certNew, keyNew := certPath+".new", keyPath+".new"
	discard := func() {
		os.Remove(certNew)
		os.Remove(keyNew)
	}

	certPEM, err := os.ReadFile(certNew)
	if err != nil {
		os.Remove(keyNew) // a key without its certificate was never used
		return nil
	}
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		discard()
		return nil
	}
	if cur, err := readKeyFile(keyPath); err == nil && keyMatchesCert(cur, cert) {
		// The key was already swapped (or never changed): only the certificate is left to move.
		os.Remove(keyNew)
		return os.Rename(certNew, certPath)
	}
	if pending, err := readKeyFile(keyNew); err == nil && keyMatchesCert(pending, cert) {
		if err := os.Rename(keyNew, keyPath); err != nil {
			return fmt.Errorf("install new agent key: %w", err)
		}
		return os.Rename(certNew, certPath)
	}
	log.Printf("[!] discarding a pending certificate rotation that matches no key")
	discard()
	return nil
}
