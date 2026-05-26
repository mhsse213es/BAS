package license

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type License struct {
	Customer   string   `json:"customer"`
	CustomerID string   `json:"customer_id"`
	IssuedAt   string   `json:"issued_at"`
	ExpiresAt  string   `json:"expires_at"`
	Features   []string `json:"features"`
	Signature  string   `json:"signature"`
}

// payload is the canonical string that is signed — order and format must not change.
func (l *License) payload() string {
	return fmt.Sprintf("%s|%s|%s|%s",
		l.CustomerID,
		l.IssuedAt,
		l.ExpiresAt,
		strings.Join(l.Features, ","),
	)
}

// Check validates the license at licPath.
//   - If PublicKeyPEM is the placeholder (keygen.sh not yet run), skips — dev only.
//   - Otherwise defaults to /etc/bas/bas.lic when licPath is empty.
//   - Missing file, bad signature, or expired date are all fatal errors.
func Check(licPath string) error {
	if PublicKeyPEM == "KEYGEN_REQUIRED" {
		log.Println("[license] WARNING: signing key not initialised — enforcement disabled (run packaging/licensing/keygen.sh)")
		return nil
	}

	if licPath == "" {
		licPath = "/etc/bas/bas.lic"
	}

	data, err := os.ReadFile(licPath)
	if err != nil {
		return fmt.Errorf("license: file not found at %s — place your bas.lic file there or set BAS_LICENSE_PATH. Contact support@audspect.com", licPath)
	}

	var lic License
	if err := json.Unmarshal(data, &lic); err != nil {
		return fmt.Errorf("license: invalid format: %w", err)
	}

	pub, err := parsePublicKey(PublicKeyPEM)
	if err != nil {
		return fmt.Errorf("license: key error: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(lic.Signature)
	if err != nil {
		return errors.New("license: invalid signature encoding")
	}

	hash := sha256.Sum256([]byte(lic.payload()))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sigBytes); err != nil {
		return errors.New("license: signature verification failed — file may be tampered")
	}

	expiry, err := time.Parse("2006-01-02", lic.ExpiresAt)
	if err != nil {
		return fmt.Errorf("license: invalid expiry date: %w", err)
	}
	// Give 24-hour grace period for timezone drift
	if time.Now().UTC().After(expiry.UTC().Add(24 * time.Hour)) {
		return fmt.Errorf("license: expired on %s (customer: %s) — contact support@audspect.com",
			lic.ExpiresAt, lic.Customer)
	}

	log.Printf("[license] Valid — customer: %s, expires: %s", lic.Customer, lic.ExpiresAt)
	return nil
}

func parsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pub, nil
}
