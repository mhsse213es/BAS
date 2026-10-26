package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// acceptCARoot handles the signed command that delivers a new deployment CA root during a planned CA
// rotation (audit F-09). The command's signature has already been verified; this adds a second,
// independent condition so that even a signed command cannot widen the agent's trust arbitrarily: the
// new root must be a CA that the root the agent ALREADY pins has vouched for, through a
// cross-certificate for the same key. The new root is appended to the pinned file, never replacing the
// old one, so existing certificates and the old server certificate keep working during the overlap.
// A root is never taken from an enrolment response.
func acceptCARoot(payload []byte) error {
	var p struct {
		RootPEM  string `json:"rootPem"`
		CrossPEM string `json:"crossPem"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("decode CA-root command: %w", err)
	}
	root, err := parseCertificatePEM([]byte(p.RootPEM))
	if err != nil {
		return fmt.Errorf("new CA root: %w", err)
	}
	now := time.Now()
	if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("the offered certificate is not a CA")
	}
	if now.Before(root.NotBefore) || now.After(root.NotAfter) {
		return fmt.Errorf("the offered CA root is outside its validity period")
	}
	cross, err := parseCertificatePEM([]byte(p.CrossPEM))
	if err != nil {
		return fmt.Errorf("cross-certificate: %w", err)
	}
	if !samePublicKey(cross, root) {
		return fmt.Errorf("the cross-certificate does not vouch for the offered root's key")
	}

	_, caPath, _, _ := certPaths()
	pinned, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("no pinned deployment CA to extend: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pinned) {
		return fmt.Errorf("pinned deployment CA is not valid PEM")
	}
	if _, err := cross.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("the offered root is not vouched for by the currently pinned CA: %w", err)
	}

	fp := certFingerprint(root)
	for _, have := range fingerprintsOfPEM(pinned) {
		if have == fp {
			return nil // already trusted
		}
	}
	updated := append(bytes.TrimRight(pinned, "\n"), '\n')
	updated = append(updated, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	tmp := caPath + ".new"
	if err := os.WriteFile(tmp, updated, 0644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, caPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install the extended CA file: %w", err)
	}
	return nil
}

func samePublicKey(a, b *x509.Certificate) bool {
	ka, err1 := x509.MarshalPKIXPublicKey(a.PublicKey)
	kb, err2 := x509.MarshalPKIXPublicKey(b.PublicKey)
	return err1 == nil && err2 == nil && bytes.Equal(ka, kb)
}

func certFingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

func fingerprintsOfPEM(data []byte) []string {
	var out []string
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return out
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			out = append(out, certFingerprint(c))
		}
	}
}

// trustedRootFingerprints are the SHA-256 fingerprints of every CA root in the pinned file, reported in
// heartbeats so the server can see which agents have the new root before it switches issuance.
func trustedRootFingerprints() []string {
	_, caPath, _, _ := certPaths()
	b, err := os.ReadFile(caPath)
	if err != nil {
		return nil
	}
	return fingerprintsOfPEM(b)
}
