package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// serverCertValidity is how long a server certificate lives. Short enough to rotate routinely,
	// long enough that a missed renewal is noticed well before expiry.
	serverCertValidity = 365 * 24 * time.Hour
	// serverCertRenewBefore: a server certificate is replaced this long before it expires.
	serverCertRenewBefore = 30 * 24 * time.Hour
)

// ServerCertSource provides the orchestrator's TLS identity (audit F-10): its own leaf certificate,
// signed by the deployment CA, with the right names and the server-authentication usage only. The CA
// certificate is no longer presented as the server identity, so the CA key is not used in handshakes
// and the server certificate can change names or be renewed without touching the CA that agents trust.
//
// The leaf is only ever signed by the CA that is loaded. A stored leaf that was signed by another CA,
// is damaged, expires soon, or has different names is replaced; that is always safe, because agents
// trust the CA, not the leaf. Nothing here can introduce a new trust anchor.
type ServerCertSource struct {
	ca   *CA
	dir  string
	sans []string
	now  func() time.Time

	mu       sync.Mutex
	cur      *tls.Certificate
	notAfter time.Time
}

// NewServerCertSource loads the stored server certificate from dir, or issues one, and returns a source
// whose GetCertificate keeps it current for the life of the process.
func NewServerCertSource(ca *CA, dir string, sans []string) (*ServerCertSource, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create PKI dir %s: %w", dir, err)
	}
	s := &ServerCertSource{ca: ca, dir: dir, sans: sans, now: time.Now}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// GetCertificate is a tls.Config.GetCertificate. It renews the certificate inside the renewal window
// without a restart.
func (s *ServerCertSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil || !s.now().Before(s.notAfter.Add(-serverCertRenewBefore)) {
		if err := s.ensureLocked(); err != nil {
			if s.cur != nil && s.now().Before(s.notAfter) {
				log.Printf("[!] could not renew the server certificate, continuing with the current one: %v", err)
				return s.cur, nil
			}
			return nil, err
		}
	}
	return s.cur, nil
}

func (s *ServerCertSource) paths() (certPath, keyPath string) {
	return filepath.Join(s.dir, "server-cert.pem"), filepath.Join(s.dir, "server-key.pem")
}

func (s *ServerCertSource) ensureLocked() error {
	certPath, keyPath := s.paths()
	cert, notAfter, reason := s.loadUsable(certPath, keyPath)
	if cert != nil {
		s.cur, s.notAfter = cert, notAfter
		return nil
	}
	if reason != "" {
		log.Printf("[*] issuing a new server certificate: %s", reason)
	}
	cert, notAfter, err := s.issue(certPath, keyPath)
	if err != nil {
		return err
	}
	s.cur, s.notAfter = cert, notAfter
	return nil
}

// loadUsable returns the stored certificate if it can still be used as is; otherwise nil and why.
func (s *ServerCertSource) loadUsable(certPath, keyPath string) (*tls.Certificate, time.Time, string) {
	if _, err := os.Stat(certPath); err != nil {
		return nil, time.Time{}, "" // first start: nothing to explain
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, time.Time{}, "the stored server certificate or key is missing or damaged"
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, time.Time{}, "the stored server certificate cannot be parsed"
	}
	now := s.now()
	if leaf.IsCA {
		return nil, time.Time{}, "the stored server certificate is a CA certificate"
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.ca.Certificate())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, time.Time{}, "the stored server certificate is not valid under the current CA: " + err.Error()
	}
	if !now.Before(leaf.NotAfter.Add(-serverCertRenewBefore)) {
		return nil, time.Time{}, "the stored server certificate is due for renewal"
	}
	if !sameNames(leaf, s.sans) {
		return nil, time.Time{}, "the server's names changed"
	}
	pair.Leaf = leaf
	return &pair, leaf.NotAfter, ""
}

func splitNames(sans []string) (dns []string, ips []net.IP) {
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, san)
		}
	}
	return dns, ips
}

func sameNames(leaf *x509.Certificate, sans []string) bool {
	wantDNS, wantIPs := splitNames(sans)
	key := func(dns []string, ips []net.IP) string {
		parts := append([]string{}, dns...)
		for _, ip := range ips {
			parts = append(parts, "ip:"+ip.String())
		}
		sort.Strings(parts)
		return strings.Join(parts, "|")
	}
	return key(wantDNS, wantIPs) == key(leaf.DNSNames, leaf.IPAddresses)
}

func (s *ServerCertSource) issue(certPath, keyPath string) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate server certificate serial: %w", err)
	}
	dns, ips := splitNames(s.sans)
	now := s.now()
	notAfter := now.Add(serverCertValidity)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Audspect Orchestrator", Organization: []string{"Audspect"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.cert, &key.PublicKey, s.ca.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign server certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("marshal server key: %w", err)
	}
	// Key first, certificate second: a crash between the two leaves a pair that does not match, which the
	// next start detects and replaces.
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return nil, time.Time{}, err
	}
	if err := writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return nil, time.Time{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, notAfter, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}
