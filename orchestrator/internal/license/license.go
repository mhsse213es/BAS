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
	// Tier is the signed commercial tier. Empty means a pre-tier licence, read as Enterprise.
	Tier      string `json:"tier,omitempty"`
	Signature string `json:"signature"`
}

// payload is the canonical string that is signed. The format must not change for licences that
// have no tier: those keep the original four fields, so they still verify. A tier is appended only
// when set, so it is covered by the signature.
func (l *License) payload() string {
	p := fmt.Sprintf("%s|%s|%s|%s",
		l.CustomerID,
		l.IssuedAt,
		l.ExpiresAt,
		strings.Join(l.Features, ","),
	)
	if l.Tier != "" {
		p += "|tier=" + l.Tier
	}
	return p
}

// Check performs the one-time startup verification gate.
//   - If PublicKeyPEM is the placeholder (keygen.sh not yet run), skips — dev only.
//   - Otherwise defaults to /etc/bas/bas.lic when licPath is empty.
//   - Missing file, bad signature, or a malformed expiry date are fatal errors.
//   - An expired-but-well-formed license is NOT fatal here — grace period and
//     lockout enforcement is Evaluate()'s and the runtime monitor's job (see
//     state.go, monitor.go), not Check()'s. Check() only verifies the file is
//     genuine and parseable.
//
// Check is not the only place this verification runs: VerifiedRead (below)
// is also called by StartMonitor on every tick for as long as the process
// runs, and by the license-info API, so a license is never trusted more
// strongly at any later moment than it is right here at startup.
func Check(licPath string) error {
	if PublicKeyPEM == "KEYGEN_REQUIRED" {
		log.Println("[license] WARNING: signing key not initialised — enforcement disabled (run packaging/licensing/keygen.sh)")
		return nil
	}
	lic, err := VerifiedRead(licPath)
	if err != nil {
		return err
	}
	log.Printf("[license] Valid — customer: %s, expires: %s", lic.Customer, lic.ExpiresAt)
	return nil
}

// VerifiedRead reads licPath and returns its contents ONLY if the RSA
// signature over the canonical payload verifies against PublicKeyPEM.
// Defaults to /etc/bas/bas.lic when licPath is empty. This is the single
// source of truth for "is this license file genuine" — every caller that
// needs to trust a bas.lic's fields (Check at startup, StartMonitor on
// every tick, the Settings → License API) goes through this, never a
// bare file-read-and-parse, so an on-disk edit after the process started
// can never be trusted on the strength of an earlier, now-stale check.
func VerifiedRead(licPath string) (*License, error) {
	if licPath == "" {
		licPath = "/etc/bas/bas.lic"
	}
	data, err := os.ReadFile(licPath)
	if err != nil {
		return nil, fmt.Errorf("license: file not found at %s — place your bas.lic file there or set BAS_LICENSE_PATH. Contact support@audspect.com", licPath)
	}
	return verify(data)
}

// verify parses data as a License and checks its RSA signature over the
// canonical payload (lic.payload()) against PublicKeyPEM. Any field edited
// after signing changes the payload, so the signature no longer verifies —
// there is no way to change ExpiresAt, CustomerID, or Features without
// invalidating the whole license.
func verify(data []byte) (*License, error) {
	var lic License
	if err := json.Unmarshal(data, &lic); err != nil {
		return nil, fmt.Errorf("license: invalid format: %w", err)
	}

	pub, err := parsePublicKey(PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("license: key error: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(lic.Signature)
	if err != nil {
		return nil, errors.New("license: invalid signature encoding")
	}

	hash := sha256.Sum256([]byte(lic.payload()))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sigBytes); err != nil {
		return nil, errors.New("license: signature verification failed — file may be tampered")
	}

	if _, err := time.Parse("2006-01-02", lic.ExpiresAt); err != nil {
		return nil, fmt.Errorf("license: invalid expiry date: %w", err)
	}

	return &lic, nil
}

// Status returns "valid", "expiring_soon" (< 30 days), "expired", or
// "unknown" for a malformed date. Retained for the existing narrower
// three-way contract some callers still expect; GetLicenseInfo now uses
// the richer Current().State instead (see monitor.go).
func Status(expiresAt string) string {
	lic := &License{ExpiresAt: expiresAt}
	info, err := Evaluate(lic, time.Now().UTC())
	if err != nil {
		return "unknown"
	}
	switch info.State {
	case StateValid:
		if info.ExpiresAt.Sub(time.Now().UTC()) < 30*24*time.Hour {
			return "expiring_soon"
		}
		return "valid"
	default: // StateGrace or StateLocked — both were "expired" under the old 3-way contract
		return "expired"
	}
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
