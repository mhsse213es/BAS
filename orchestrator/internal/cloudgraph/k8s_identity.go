package cloudgraph

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// K8sTLSDialTimeout bounds the TLS handshake used to read the server certificate.
const k8sTLSDialTimeout = 15 * time.Second

// ServerVersion returns the API server's gitVersion from GET /version. Read-only.
func (c *K8sDiscoveryClient) ServerVersion(ctx context.Context) (string, error) {
	body, status, err := c.get(ctx, "/version")
	if err != nil {
		return "", err
	}
	if status == 401 {
		return "", ErrK8sUnauthorized
	}
	if status != 200 {
		return "", fmt.Errorf("kubernetes /version: HTTP %d", status)
	}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.GitVersion == "" {
		return "", errors.New("kubernetes /version: unreadable response")
	}
	return v.GitVersion, nil
}

// CAFingerprint returns the SHA-256 of the first certificate in a PEM CA bundle, in lower-case hex.
func CAFingerprint(caPEM []byte) (string, error) {
	for rest := caPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", errors.New("the cluster CA PEM contains no certificate")
		}
		if block.Type == "CERTIFICATE" {
			sum := sha256.Sum256(block.Bytes)
			return hex.EncodeToString(sum[:]), nil
		}
	}
}

// TLSServerIdentity connects to the API server over TLS, verifies the certificate against the configured CA (or the
// system roots when none is set), and returns the SHA-256 of the leaf certificate's public key info. A certificate
// that does not verify is an error, so an unverified server never produces an identity.
func TLSServerIdentity(ctx context.Context, serverURL string, caPEM []byte) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("the API server must be an https URL")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return "", errors.New("the cluster CA PEM could not be parsed")
		}
		cfg.RootCAs = pool
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: k8sTLSDialTimeout}, Config: cfg}
	ctx, cancel := context.WithTimeout(ctx, k8sTLSDialTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return "", fmt.Errorf("TLS to the API server failed: %w", err)
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", errors.New("unexpected connection type")
	}
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("the API server presented no certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}
