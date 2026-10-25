// Package deployconfig builds the signed deployment configuration
// (deployment.json) that accompanies the Windows agent installer.
//
// The installer verifies it with agent/deployconfig, which is a separate Go
// module: the envelope format and SigningDomain are duplicated there and pinned
// by a golden fixture that both modules test against. A drift on either side
// shows up as a test failure.
//
// Trust: the envelope embeds its signing certificate, so a signature alone
// proves nothing. The installer pins the SHA-256 fingerprint of the certificate,
// which the operator obtains from the authenticated dashboard (Fingerprint),
// never from the same ZIP. The signing key is the orchestrator's existing
// command-signing key; the domain prefix keeps a command signature from ever
// validating as a deployment config.
package deployconfig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

const (
	// SigningDomain is prepended to the config bytes before signing. It must be
	// identical to agent/deployconfig.SigningDomain.
	SigningDomain = "audspect-deployment-config-v1\n"

	// Version is the envelope version this package produces.
	Version = 1

	minRSABits = 3072
)

// Config is the deployment configuration handed to the installer. It carries no
// secret: the agent secret is entered at install time and never stored here.
type Config struct {
	ServerURL  string
	EnrollPort string // empty means the default enrollment port
	CARootPEM  string // empty when PKI is not configured
	IssuedAt   time.Time
}

// Signer is the signing key. *cmdsigning.SigningKey satisfies it.
type Signer interface {
	PrivateKey() *rsa.PrivateKey
	CertPEM() []byte
}

type envelope struct {
	Version        int    `json:"version"`
	Config         string `json:"config"`
	SigningCertPEM string `json:"signingCertPem"`
	Signature      string `json:"signature"`
}

type configBody struct {
	ServerURL  string `json:"serverURL"`
	EnrollPort string `json:"enrollPort,omitempty"`
	CARootPEM  string `json:"caRootPem,omitempty"`
	IssuedAt   string `json:"issuedAt"`
}

// Fingerprint returns the SHA-256 fingerprint (64 lowercase hex characters) of
// the signing certificate. This is the value an operator must verify before
// trusting a downloaded configuration.
func Fingerprint(certPEM []byte) (string, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("signing certificate must be exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing certificate: %w", err)
	}
	return cert, nil
}

// Build validates cfg, then signs it. It refuses to sign anything the installer
// would reject, so the server never emits a configuration that is wrong at the
// source.
func Build(s Signer, cfg Config) ([]byte, error) {
	if err := validate(cfg); err != nil {
		return nil, err
	}
	key := s.PrivateKey()
	if key == nil || key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("signing key must be RSA of at least %d bits", minRSABits)
	}
	cert, err := parseCert(s.CertPEM())
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		return nil, errors.New("signing certificate does not match the signing key")
	}

	body, err := json.Marshal(configBody{
		ServerURL: cfg.ServerURL, EnrollPort: cfg.EnrollPort, CARootPEM: cfg.CARootPEM,
		IssuedAt: cfg.IssuedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte(SigningDomain), body...))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign deployment config: %w", err)
	}
	return json.Marshal(envelope{
		Version:        Version,
		Config:         base64.StdEncoding.EncodeToString(body),
		SigningCertPEM: string(s.CertPEM()),
		Signature:      base64.StdEncoding.EncodeToString(sig),
	})
}

func validate(c Config) error {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("server URL must be an https URL with a host")
	}
	if u.User != nil {
		return errors.New("server URL must not contain credentials")
	}
	if c.EnrollPort != "" {
		n, err := strconv.Atoi(c.EnrollPort)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("enrollment port must be a number between 1 and 65535")
		}
	}
	if c.CARootPEM != "" {
		p := []byte(c.CARootPEM)
		n := 0
		for {
			var block *pem.Block
			block, p = pem.Decode(p)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if block.Type != "CERTIFICATE" || err != nil || !cert.IsCA {
				return errors.New("CA root must be one or more CA certificates in PEM form")
			}
			n++
		}
		if n == 0 || len(bytes.TrimSpace(p)) != 0 {
			return errors.New("CA root must be one or more CA certificates in PEM form")
		}
	}
	if c.IssuedAt.IsZero() {
		return errors.New("issue time is required")
	}
	return nil
}
