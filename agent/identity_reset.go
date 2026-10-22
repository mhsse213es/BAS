// agent/identity_reset.go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// identityFiles are the enrollment files the agent keeps in its certificate directory.
var identityFiles = []string{"agent-cert.pem", "agent-key.pem", "enrollment-state"}

// clearStaleIdentity moves the agent's enrollment identity aside when its certificate was not
// issued by the deployment CA being installed. The server never accepts a certificate from another
// CA, so keeping one only blocks enrollment. The files are moved, not deleted. It reports whether
// anything was moved. With no identity present, or one that still chains to caPEM, it does nothing.
func clearStaleIdentity(caPEM []byte) (bool, error) {
	dir, _, certPath, _ := certPaths()
	if _, err := os.Stat(certPath); err != nil {
		return false, nil
	}
	if certChainsTo(certPath, caPEM) {
		return false, nil
	}
	backup := dir + ".replaced-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return false, fmt.Errorf("create %s: %w", backup, err)
	}
	for _, name := range identityFiles {
		src := filepath.Join(dir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(backup, name)); err != nil {
			return false, fmt.Errorf("move %s: %w", src, err)
		}
	}
	return true, nil
}

// certChainsTo reports whether the PEM certificate at certPath verifies against the CA in caPEM.
func certChainsTo(certPath string, caPEM []byte) bool {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return false
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}
