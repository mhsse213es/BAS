// Package deployconfig verifies a server-signed deployment configuration
// (deployment.json) before any of its settings are trusted.
//
// Trust model (Option A in the installer design): the file carries its own
// signing certificate, so the signature alone proves nothing, because anyone who
// can replace the downloaded files can supply their own key. The caller must
// therefore pass the SHA-256 fingerprint of the genuine signing certificate,
// obtained independently (the authenticated dashboard or another trusted
// channel, never merely from the same ZIP). Verification order is:
//
//  1. the expected fingerprint is present and well formed (mandatory),
//  2. the envelope is well formed with no unsupported fields or version,
//  3. the embedded certificate's fingerprint equals the expected one,
//  4. the signature verifies under that certificate,
//  5. only then the configuration fields are read and validated.
//
// On any failure nothing is returned except an error, and errors never echo the
// configuration's content.
//
// A changed signing key changes the fingerprint, so verification fails until an
// administrator approves the new fingerprint through a trusted channel.
package deployconfig

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// SigningDomain is prepended to the config bytes before signing. It keeps a
	// signature made for any other purpose with the same key (the orchestrator's
	// command-signing key signs every dispatched command) from validating as a
	// deployment config. The orchestrator uses the identical constant.
	SigningDomain = "audspect-deployment-config-v1\n"

	// SupportedVersion is the only envelope version this code accepts.
	SupportedVersion = 1

	// MaxEnvelopeBytes bounds the file read from disk.
	MaxEnvelopeBytes = 64 * 1024

	minRSABits    = 3072
	maxClockSkew  = 5 * time.Minute
	fingerprintHx = 64
)

// Config is the verified deployment configuration.
type Config struct {
	ServerURL  string
	EnrollPort string // empty means the default enrollment port
	CARootPEM  string // empty when the server has no PKI configured
	IssuedAt   time.Time
}

type envelope struct {
	Version        int    `json:"version"`
	Config         string `json:"config"` // base64 of the exact bytes that were signed
	SigningCertPEM string `json:"signingCertPem"`
	Signature      string `json:"signature"` // base64
}

type configBody struct {
	ServerURL  string `json:"serverURL"`
	EnrollPort string `json:"enrollPort"`
	CARootPEM  string `json:"caRootPem"`
	IssuedAt   string `json:"issuedAt"`
}

// NormalizeFingerprint accepts a SHA-256 fingerprint in hex, with or without
// colons or spaces and in either case, and returns it as 64 lowercase hex
// characters.
func NormalizeFingerprint(s string) (string, error) {
	cleaned := strings.ToLower(strings.Map(func(r rune) rune {
		if r == ':' || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s))
	if len(cleaned) != fingerprintHx {
		return "", errors.New("the expected signing-key fingerprint must be a 64-character SHA-256 hex value")
	}
	if _, err := hex.DecodeString(cleaned); err != nil {
		return "", errors.New("the expected signing-key fingerprint must be a 64-character SHA-256 hex value")
	}
	return cleaned, nil
}

// Fingerprint returns the SHA-256 fingerprint (64 lowercase hex characters) of
// the single certificate in certPEM.
func Fingerprint(certPEM []byte) (string, error) {
	cert, err := parseSingleCert(certPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func parseSingleCert(certPEM []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the signing certificate is not a PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the signing certificate field must contain exactly one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("the signing certificate could not be parsed")
	}
	return cert, nil
}

// Verify checks an envelope against the independently obtained fingerprint and
// returns the configuration only if every check passes. now is injected so
// tests are deterministic.
func Verify(envelopeJSON []byte, expectedFingerprint string, now time.Time) (Config, error) {
	want, err := NormalizeFingerprint(expectedFingerprint)
	if err != nil {
		return Config{}, err
	}
	if len(envelopeJSON) == 0 || len(envelopeJSON) > MaxEnvelopeBytes {
		return Config{}, errors.New("the deployment configuration file is empty or too large")
	}

	var env envelope
	if err := strictDecode(envelopeJSON, &env); err != nil {
		return Config{}, errors.New("the deployment configuration is malformed or contains unsupported fields")
	}
	if env.Version != SupportedVersion {
		return Config{}, fmt.Errorf("unsupported deployment configuration version %d", env.Version)
	}

	cert, err := parseSingleCert([]byte(env.SigningCertPEM))
	if err != nil {
		return Config{}, err
	}
	sum := sha256.Sum256(cert.Raw)
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return Config{}, errors.New("the signing key fingerprint does not match the expected value: do not trust this configuration until an administrator has approved the key")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < minRSABits {
		return Config{}, fmt.Errorf("the signing key is not an RSA key of at least %d bits", minRSABits)
	}

	configBytes, err := base64.StdEncoding.DecodeString(env.Config)
	if err != nil || len(configBytes) == 0 {
		return Config{}, errors.New("the deployment configuration signature is invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) == 0 {
		return Config{}, errors.New("the deployment configuration signature is invalid")
	}
	digest := sha256.Sum256(append([]byte(SigningDomain), configBytes...))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return Config{}, errors.New("the deployment configuration signature is invalid")
	}

	var body configBody
	if err := strictDecode(configBytes, &body); err != nil {
		return Config{}, errors.New("the deployment configuration contains unsupported fields or is malformed")
	}
	return validate(body, now)
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func validate(b configBody, now time.Time) (Config, error) {
	u, err := url.Parse(b.ServerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return Config{}, errors.New("the configured server URL must be an https URL with a host")
	}
	if u.User != nil {
		return Config{}, errors.New("the configured server URL must not contain credentials")
	}
	if b.EnrollPort != "" {
		n, err := strconv.Atoi(b.EnrollPort)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, errors.New("the configured enrollment port must be a number between 1 and 65535")
		}
	}
	if b.CARootPEM != "" {
		if err := validateCARoots([]byte(b.CARootPEM)); err != nil {
			return Config{}, err
		}
	}
	if b.IssuedAt == "" {
		return Config{}, errors.New("the deployment configuration has no issue time")
	}
	issued, err := time.Parse(time.RFC3339, b.IssuedAt)
	if err != nil {
		return Config{}, errors.New("the deployment configuration issue time is not valid")
	}
	if issued.After(now.Add(maxClockSkew)) {
		return Config{}, errors.New("the deployment configuration was issued in the future: check this machine's clock")
	}
	return Config{ServerURL: b.ServerURL, EnrollPort: b.EnrollPort, CARootPEM: b.CARootPEM, IssuedAt: issued}, nil
}

// validateCARoots requires at least one certificate and that every certificate
// is a CA, so a leaf certificate can never be installed as a trust anchor.
func validateCARoots(p []byte) error {
	n := 0
	for {
		var block *pem.Block
		block, p = pem.Decode(p)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return errors.New("the configured CA bundle contains something that is not a certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("the configured CA certificate could not be parsed")
		}
		if !cert.IsCA {
			return errors.New("the configured CA certificate is not a certificate authority")
		}
		n++
	}
	if n == 0 || len(bytes.TrimSpace(p)) != 0 {
		return errors.New("the configured CA bundle is not valid PEM")
	}
	return nil
}
