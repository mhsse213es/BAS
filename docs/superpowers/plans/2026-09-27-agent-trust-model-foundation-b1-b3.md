# Agent Trust Model Foundation (B1 + B3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the shared `AgentSecret` standing credential with per-agent mTLS client certificates, issued by a deployment CA the orchestrator generates at first startup, over a properly separated enrollment/operation listener topology.

**Architecture:** Three orchestrator listeners (9443 mandatory mTLS for enrolled agents, 9444 TLS-server-only for initial bootstrap CSR submission, 9000 temporary plaintext for pre-migration agents). Agents generate their own ECDSA P-256 keypair and never transmit a private key. The orchestrator's CA stamps the server-authoritative `AgentID` (unchanged `SHA-256(hostname)[:16]` derivation) into each signed certificate's CommonName/SAN; the WS/HTTP layer reads that identity from the verified TLS connection instead of trusting a client-supplied query parameter.

**Tech Stack:** Go stdlib `crypto/ecdsa`, `crypto/x509`, `crypto/tls`, `encoding/pem`; existing chi router, pgx/Postgres, gorilla/websocket.

**Spec:** `docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md` — this plan implements that spec's Sections 1 and 2 (Listeners; Enrollment & certificate issuance). Section 3 (B4 command signing) is a separate, later plan that depends on this one.

## Global Constraints

- Agent client keypair: ECDSA P-256, generated locally, private key never transmitted (spec Section 2).
- `AgentID` derivation is unchanged: `SHA-256(hostname)[:16]` (`agent/identity.go`) — the CSR's CommonName carries this value as a request; the orchestrator is authoritative and stamps the validated value into the signed certificate.
- Enrollment response returns the signed certificate + CA chain only — never a private key.
- Bootstrap secret is rejected for any `AgentID` that already holds a valid, unexpired certificate (spec Section 2, "Bootstrap reuse limit").
- 9443 stays `tls.RequireAndVerifyClientCert` — never weakened to `VerifyClientCertIfGiven` (spec Section 1, explicit prohibition).
- Agent client certificate lifetime: 1 year. Deployment CA lifetime: 10 years (spec Section 2 defaults).
- All three listeners share the same `api.Mount(...)` handler/business logic — only the per-listener `http.Server`'s TLS config and a thin identity-extraction middleware differ (spec Section 1).
- Out of scope for this plan (do not implement): removing port 9000/legacy auth (B2), RLS/C1, assessment groups D/G/H/I/J, `agent/sched/riskgate.go`, B4 command-bundle signing (separate later plan).

## Review Focus

- **Malformed/hostile CSR submitted to the enrollment endpoint** (bad PEM, non-CSR DER, unparseable ASN.1, or a syntactically valid CSR with an invalid self-signature) — the handler must reject with 400, never panic or 500 the process. Pinned in Task 5.
- **Bootstrap secret reused against an AgentID that already has a valid certificate** — must be rejected even though the secret itself is correct, per the explicit reuse-limit requirement. Pinned in Task 5.
- **`agentId` query parameter on `/ws/agent` disagreeing with the authenticated mTLS certificate's CommonName** — a cert-holding agent must not be able to claim a different agent's identity via the query string. Pinned in Task 6.
- **CA/cert files missing or corrupted on orchestrator restart** (`LoadOrGenerateCA` reading a truncated or non-PEM file) — must fail loudly at startup with a clear error, never silently regenerate a new CA (which would invalidate every already-issued agent certificate without warning). Pinned in Task 2.
- **Agent already holding a still-valid, unexpired local certificate on restart** — must skip bootstrap entirely and reconnect directly via mTLS on 9443, not re-run the CSR flow (wasteful, and would trip the reuse-limit rejection from Task 5). Pinned in Task 10.

---

### Task 1: Orchestrator config — PKI directory and new listener ports

**Files:**
- Modify: `orchestrator/config/config.go:11-106` (Config struct), `:110-124` (defaults), `:138-276` (env overrides)
- Test: `orchestrator/config/config_test.go` (create if it doesn't already exist — check with `ls orchestrator/config/*_test.go` first; if one exists, add to it instead of creating a second file)

**Interfaces:**
- Produces: `Config.PKIDir string` (default `/etc/audspect/pki`, env `PKI_DIR`), `Config.EnrollHTTPPort int` (default `9444`, env `HTTP_PORT_ENROLL`), `Config.LegacyHTTPPort int` (default `9000`, env `HTTP_PORT_LEGACY`) — consumed by Task 7's `main.go` listener wiring.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/config/config_test.go
package config

import (
	"os"
	"testing"
)

func TestLoad_PKIDefaults(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PKIDir != "/etc/audspect/pki" {
		t.Errorf("PKIDir = %q, want /etc/audspect/pki", cfg.PKIDir)
	}
	if cfg.EnrollHTTPPort != 9444 {
		t.Errorf("EnrollHTTPPort = %d, want 9444", cfg.EnrollHTTPPort)
	}
	if cfg.LegacyHTTPPort != 9000 {
		t.Errorf("LegacyHTTPPort = %d, want 9000", cfg.LegacyHTTPPort)
	}
}

func TestLoad_PKIEnvOverrides(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("PKI_DIR", "/custom/pki")
	os.Setenv("HTTP_PORT_ENROLL", "9555")
	os.Setenv("HTTP_PORT_LEGACY", "9001")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("PKI_DIR")
	defer os.Unsetenv("HTTP_PORT_ENROLL")
	defer os.Unsetenv("HTTP_PORT_LEGACY")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PKIDir != "/custom/pki" {
		t.Errorf("PKIDir = %q, want /custom/pki", cfg.PKIDir)
	}
	if cfg.EnrollHTTPPort != 9555 {
		t.Errorf("EnrollHTTPPort = %d, want 9555", cfg.EnrollHTTPPort)
	}
	if cfg.LegacyHTTPPort != 9001 {
		t.Errorf("LegacyHTTPPort = %d, want 9001", cfg.LegacyHTTPPort)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./config/... -run TestLoad_PKI -v`
Expected: FAIL — `cfg.PKIDir undefined (type *Config has no field or method PKIDir)`

- [ ] **Step 3: Add the fields and env loading**

In `orchestrator/config/config.go`, add to the `Config` struct (after `MetricsToken` at line 105):

```go
	// Agent trust model (B1/B3) — deployment CA + per-agent mTLS.
	// See docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md.
	// PKIDir holds the deployment CA's keypair/cert (ca-key.pem, ca-cert.pem),
	// generated on first startup if absent. EnrollHTTPPort serves initial
	// bootstrap CSR submission over TLS with NO client cert required.
	// LegacyHTTPPort is the temporary plaintext listener for pre-migration
	// agents, retired entirely by the separately-scoped B2 work.
	PKIDir          string `json:"pki_dir,omitempty"`
	EnrollHTTPPort  int    `json:"enroll_http_port,omitempty"`
	LegacyHTTPPort  int    `json:"legacy_http_port,omitempty"`
```

In `Load`'s default-value struct literal (around line 111-124), add:

```go
		PKIDir:         "/etc/audspect/pki",
		EnrollHTTPPort: 9444,
		LegacyHTTPPort: 9000,
```

In the env-override section (after the `HTTP_PORT` block around line 148-150), add:

```go
	if v := os.Getenv("PKI_DIR"); v != "" {
		cfg.PKIDir = v
	}
	if v := os.Getenv("HTTP_PORT_ENROLL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.EnrollHTTPPort)
	}
	if v := os.Getenv("HTTP_PORT_LEGACY"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.LegacyHTTPPort)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./config/... -run TestLoad_PKI -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/config/config.go orchestrator/config/config_test.go
git commit -m "feat(config): add PKI dir and enroll/legacy listener port config"
```

---

### Task 2: Deployment CA — generate/load

**Files:**
- Create: `orchestrator/internal/pki/ca.go`
- Test: `orchestrator/internal/pki/ca_test.go`

**Interfaces:**
- Produces: `pki.CA` type, `pki.LoadOrGenerateCA(dir string) (*CA, error)`, `(*CA).RootCertPEM() []byte`, `(*CA).Certificate() *x509.Certificate`, `(*CA).TLSCertificate() (tls.Certificate, error)` (for the 9443/9444 servers' own TLS identity — see Task 7) — consumed by Tasks 3, 6, 7.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/pki/ca_test.go
package pki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateCA_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if ca.Certificate() == nil {
		t.Fatal("Certificate() returned nil")
	}
	if !ca.Certificate().IsCA {
		t.Error("generated certificate is not marked IsCA")
	}
	for _, name := range []string{"ca-key.pem", "ca-cert.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestLoadOrGenerateCA_LoadsExistingOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrGenerateCA: %v", err)
	}
	second, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerateCA: %v", err)
	}
	if first.Certificate().SerialNumber.Cmp(second.Certificate().SerialNumber) != 0 {
		t.Error("second call generated a NEW CA instead of loading the existing one — " +
			"this would invalidate every already-issued agent certificate")
	}
}

func TestLoadOrGenerateCA_CorruptKeyFileFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatalf("initial generate: %v", err)
	}
	// Corrupt the key file to simulate disk corruption / truncated write.
	if err := os.WriteFile(filepath.Join(dir, "ca-key.pem"), []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("corrupt key file: %v", err)
	}
	if _, err := LoadOrGenerateCA(dir); err == nil {
		t.Fatal("expected LoadOrGenerateCA to fail loudly on a corrupt key file, got nil error — " +
			"silently regenerating here would invalidate the whole fleet's certificates without warning")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/pki/... -v`
Expected: FAIL — `no Go files in .../internal/pki`

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/pki/ca.go
// Package pki implements the deployment certificate authority used to issue
// per-agent mTLS client certificates (B1/B3). See
// docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md.
//
// This is a separate trust domain from the command-signing keypair (B4,
// implemented in a later plan) -- the two are never chained together, so
// compromise of one does not automatically compromise the other.
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
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// caValidity is the deployment CA root's lifetime. Long-lived by design --
// air-gapped operators don't want frequent root rotation -- with overlapping
// trust support (documented in the spec) available whenever rotation does
// happen. CA compromise is substantially more consequential than a single
// client-cert compromise (full fleet impersonation vs. one agent), which is
// why the CA private key file is written 0600 and must never leave this host.
const caValidity = 10 * 365 * 24 * time.Hour

// CA holds the deployment certificate authority's keypair and root
// certificate. The private key never leaves the orchestrator host.
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *ecdsa.PrivateKey
}

// LoadOrGenerateCA loads an existing CA keypair from dir, or generates a new
// one if dir contains no ca-key.pem. dir is created if it does not exist.
// A CA that exists but fails to parse (corrupt/truncated file) is a hard
// error -- silently regenerating would invalidate every already-issued
// agent certificate without warning.
func LoadOrGenerateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create PKI dir %s: %w", dir, err)
	}
	keyPath := filepath.Join(dir, "ca-key.pem")
	certPath := filepath.Join(dir, "ca-cert.pem")

	if _, err := os.Stat(keyPath); err == nil {
		return loadCA(keyPath, certPath)
	}
	return generateCA(keyPath, certPath)
}

func generateCA(keyPath, certPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Audspect Deployment CA", Organization: []string{"Audspect"}},
		NotBefore:              time.Now().Add(-5 * time.Minute),
		NotAfter:               time.Now().Add(caValidity),
		KeyUsage:               x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid:  true,
		IsCA:                   true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}
	if err := writeECKeyPEM(keyPath, key); err != nil {
		return nil, err
	}
	if err := writeCertPEM(certPath, certDER); err != nil {
		return nil, err
	}
	return &CA{cert: cert, certDER: certDER, key: key}, nil
}

func loadCA(keyPath, certPath string) (*CA, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode CA key PEM %s: no PEM block found (corrupt or truncated file)", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("decode CA cert PEM %s: no PEM block found (corrupt or truncated file)", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{cert: cert, certDER: certBlock.Bytes, key: key}, nil
}

func writeECKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	// 0600: readable only by the orchestrator process owner. The
	// orchestrator ships as a Linux container (packaging/compose/), so this
	// is a real, enforced restriction, not a Windows no-op.
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func writeCertPEM(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// RootCertPEM returns the CA's root certificate in PEM form, for
// distribution to admins (to bundle into agent installers, Task 6's
// GET /api/config/connection extension) and for the mTLS listeners' own
// ClientCAs pool (Task 7).
func (c *CA) RootCertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
}

// Certificate returns the parsed CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// TLSCertificate returns the CA's own certificate+key as a tls.Certificate,
// used as the orchestrator's server identity on the 9443 and 9444 listeners
// (the CA signs its own server-identity leaf implicitly by presenting itself
// directly -- see Task 7 for why this is sufficient for a single-orchestrator
// on-prem deployment rather than issuing a separate server leaf cert).
func (c *CA) TLSCertificate() (tls.Certificate, error) {
	keyDER, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal CA key for TLS: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/pki/... -v`
Expected: PASS (all three tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/pki/ca.go orchestrator/internal/pki/ca_test.go
git commit -m "feat(pki): deployment CA generation and loading"
```

---

### Task 3: CSR validation and client-certificate issuance

**Files:**
- Create: `orchestrator/internal/pki/issue.go`
- Test: `orchestrator/internal/pki/issue_test.go`

**Interfaces:**
- Consumes: `pki.CA` from Task 2 (`c.cert`, `c.key` fields, same package — no exported accessor needed since this lives in the same `pki` package).
- Produces: `pki.IssuedCert{CertPEM []byte, SerialNumber string, ExpiresAt time.Time}`, `(*CA).IssueClientCertificate(agentID string, csrPEM []byte) (*IssuedCert, error)`, `pki.GenerateTestCSR(commonName string) (csrPEM []byte, err error)` (test helper, exported so Task 5's and Task 9's tests can reuse it) — consumed by Task 5.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/pki/issue_test.go
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

// GenerateTestCSR mirrors what a real agent does in Task 8: generate an
// ECDSA P-256 keypair locally and produce a CSR PEM for it. Exported (not
// _test.go-only) so Task 5's handler test and Task 9's protocol test can
// reuse it without duplicating CSR-construction code.
func TestIssueClientCertificate_ValidCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	csrPEM, err := GenerateTestCSR("requested-cn-is-ignored")
	if err != nil {
		t.Fatalf("GenerateTestCSR: %v", err)
	}

	issued, err := ca.IssueClientCertificate("abc123deadbeef01", csrPEM)
	if err != nil {
		t.Fatalf("IssueClientCertificate: %v", err)
	}
	block, _ := pem.Decode(issued.CertPEM)
	if block == nil {
		t.Fatal("issued cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if cert.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("CommonName = %q, want the server-supplied agentID, not the CSR's requested CN", cert.Subject.CommonName)
	}
	if err := cert.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Errorf("issued cert does not chain to the CA: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Error("SerialNumber is empty")
	}
	if issued.ExpiresAt.Before(cert.NotBefore) {
		t.Error("ExpiresAt is before the certificate's own NotBefore")
	}
}

func TestIssueClientCertificate_RejectsMalformedCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	for name, bad := range map[string][]byte{
		"not PEM at all":       []byte("this is not a CSR"),
		"PEM but wrong type":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}),
		"PEM CSR type but bad DER": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ca.IssueClientCertificate("some-agent-id", bad); err == nil {
				t.Errorf("expected IssueClientCertificate to reject %s, got nil error", name)
			}
		})
	}
}

// GenerateTestCSR generates an ECDSA P-256 keypair and a CSR for it, the
// same shape Task 8's real agent code produces. Exported for reuse by other
// packages' tests (Task 5, Task 9) as well as within this package.
func GenerateTestCSR(commonName string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/pki/... -run TestIssueClientCertificate -v`
Expected: FAIL — `ca.IssueClientCertificate undefined`

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/pki/issue.go
package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// clientCertValidity is the agent client certificate lifetime (spec
// Section 2 default). Renewed at ~75% elapsed or on the next binary
// upgrade's re-enroll, whichever comes first -- see Task 12.
const clientCertValidity = 365 * 24 * time.Hour

// IssuedCert is a newly signed agent client certificate plus the metadata
// the caller (Task 5's enrollment handler) persists in agent_certificates.
type IssuedCert struct {
	CertPEM      []byte
	SerialNumber string
	ExpiresAt    time.Time
}

// IssueClientCertificate parses csrPEM, verifies its self-signature, and
// signs a new mTLS client certificate for agentID using the deployment CA.
//
// agentID -- already validated by the caller against the agents table and
// enrollment policy -- is what gets stamped into the signed certificate's
// Subject.CommonName and DNSNames SAN. The CSR's own requested Subject is
// read only to prove possession of the private key (CheckSignature) and is
// otherwise ignored: per the spec, the orchestrator is authoritative for
// agent identity, not the agent's own assertion.
func (c *CA) IssueClientCertificate(agentID string, csrPEM []byte) (*IssuedCert, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("decode CSR PEM: expected a CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid (does not prove possession of the private key): %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	notBefore := time.Now().Add(-5 * time.Minute) // small clock-skew allowance
	notAfter := notBefore.Add(clientCertValidity)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"Audspect"}},
		DNSNames:     []string{agentID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign client certificate: %w", err)
	}
	return &IssuedCert{
		CertPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		SerialNumber: serial.Text(16),
		ExpiresAt:    notAfter,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/pki/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/pki/issue.go orchestrator/internal/pki/issue_test.go
git commit -m "feat(pki): CSR validation and agent client-certificate issuance"
```

---

### Task 4: DB schema — certificate tracking table

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (the `stmts` slice inside `EnsureSchema`, after the existing `agents` table block ending around line 99)
- Test: `orchestrator/internal/db/postgres_test.go` (check with `ls orchestrator/internal/db/*_test.go` first — add to an existing schema test if one covers `EnsureSchema`, otherwise create)

**Interfaces:**
- Produces: `agent_certificates` table (`serial_number TEXT PRIMARY KEY`, `agent_id TEXT NOT NULL REFERENCES agents(agent_id)`, `issued_at`, `expires_at`, `revoked`, `revoked_at`) — consumed by Task 5's bootstrap-reuse check and Task 12's renewal bookkeeping.

- [ ] **Step 1: Write the failing test**

```go
// Add to orchestrator/internal/db/postgres_test.go (or create it if no
// existing test calls EnsureSchema against a real test database — check
// how other tests in this package obtain a test pool, e.g. a testDSN
// helper or build-tagged integration test, and follow that same pattern
// rather than inventing a new one).
func TestEnsureSchema_CreatesAgentCertificatesTable(t *testing.T) {
	pool := mustTestPool(t) // use this package's existing test-pool helper
	ctx := context.Background()
	if err := EnsureSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_certificates')`,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("query information_schema: %v", err)
	}
	if !exists {
		t.Fatal("agent_certificates table was not created")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureSchema_CreatesAgentCertificatesTable -v`
Expected: FAIL — `agent_certificates table was not created`

- [ ] **Step 3: Add the migration**

In `orchestrator/internal/db/postgres.go`, insert into the `stmts` slice immediately after the last agent-table `ALTER TABLE agents ADD COLUMN IF NOT EXISTS domain_joined boolean` statement (the one preceding `CREATE TABLE IF NOT EXISTS scenario_runs`):

```go
		// Agent trust model (B1/B3) — tracks issued mTLS client certificates
		// per agent. Used by the enrollment handler's bootstrap-reuse check
		// (an AgentID with a valid, unexpired, non-revoked row here must
		// renew via mTLS instead of re-bootstrapping with the shared secret)
		// and by the admin UI's future cert-lifecycle visibility. See
		// docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md.
		`CREATE TABLE IF NOT EXISTS agent_certificates (
			serial_number text        PRIMARY KEY,
			agent_id      text        NOT NULL REFERENCES agents(agent_id),
			issued_at     timestamptz NOT NULL DEFAULT NOW(),
			expires_at    timestamptz NOT NULL,
			revoked       boolean     NOT NULL DEFAULT false,
			revoked_at    timestamptz
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_certificates_agent_id ON agent_certificates(agent_id)`,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureSchema_CreatesAgentCertificatesTable -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/db/postgres_test.go
git commit -m "feat(db): add agent_certificates table for mTLS cert tracking"
```

---

### Task 5: Enrollment CSR handler

**Files:**
- Create: `orchestrator/internal/api/enroll_csr_handlers.go`
- Test: `orchestrator/internal/api/enroll_csr_handlers_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (add `pki *pki.CA` field to `Handler` struct near `agentSecret` at line 88, add `WithPKI` builder method near `WithAgentSecret` at line 226-230)

**Interfaces:**
- Consumes: `pki.CA.IssueClientCertificate` (Task 3), `agent_certificates` table (Task 4), existing `h.db`, `h.agentSecret`, `h.validateAgentAuth` pattern (`handlers.go:232-242`).
- Produces: `(h *Handler) EnrollCSR(w http.ResponseWriter, r *http.Request)`, registered as `POST /api/agents/enroll-csr` — consumed by Task 7's route/listener wiring and Task 9's agent-side client.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/enroll_csr_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/pki"
)

// newTestHandlerWithPKI builds a minimal Handler wired with a real
// pool (see this package's existing handler test helpers — reuse
// whatever newTestHandler()/mustTestPool() helper the existing
// *_test.go files in this package already use rather than duplicating
// pool setup) plus a fresh throwaway CA and a known bootstrap secret.
func newTestHandlerWithPKI(t *testing.T) (*Handler, *pki.CA) {
	t.Helper()
	ca, err := pki.LoadOrGenerateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	h := newTestHandler(t). // existing helper in this package
					WithAgentSecret("test-bootstrap-secret").
					WithPKI(ca)
	return h, ca
}

func TestEnrollCSR_ValidBootstrapSecretIssuesCertificate(t *testing.T) {
	h, _ := newTestHandlerWithPKI(t)
	csrPEM, err := pki.GenerateTestCSR("requested-cn-ignored")
	if err != nil {
		t.Fatalf("GenerateTestCSR: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"agentId": "abc123deadbeef01",
		"csrPem":  string(csrPEM),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec := httptest.NewRecorder()

	h.EnrollCSR(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CertPEM string `json:"certPem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CertPEM == "" {
		t.Error("response did not include a signed certificate")
	}
}

func TestEnrollCSR_WrongBootstrapSecretRejected(t *testing.T) {
	h, _ := newTestHandlerWithPKI(t)
	csrPEM, _ := pki.GenerateTestCSR("cn")
	body, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", "wrong-secret")
	rec := httptest.NewRecorder()

	h.EnrollCSR(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestEnrollCSR_RejectsBootstrapForAlreadyEnrolledAgent(t *testing.T) {
	h, _ := newTestHandlerWithPKI(t)
	csrPEM, _ := pki.GenerateTestCSR("cn")
	body, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": string(csrPEM)})

	// First bootstrap succeeds.
	req1 := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req1.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec1 := httptest.NewRecorder()
	h.EnrollCSR(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first bootstrap: status = %d, body = %s", rec1.Code, rec1.Body.String())
	}

	// Second bootstrap for the SAME agentId, with a fresh CSR, must be
	// rejected -- this identity already holds a valid certificate and must
	// renew via mTLS instead (spec Section 2, "Bootstrap reuse limit").
	csrPEM2, _ := pki.GenerateTestCSR("cn2")
	body2, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": string(csrPEM2)})
	req2 := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body2))
	req2.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec2 := httptest.NewRecorder()
	h.EnrollCSR(rec2, req2)

	if rec2.Code != http.StatusConflict {
		t.Errorf("second bootstrap for an already-enrolled agent: status = %d, want 409", rec2.Code)
	}
}

func TestEnrollCSR_MalformedCSRRejectedWith400(t *testing.T) {
	h, _ := newTestHandlerWithPKI(t)
	body, _ := json.Marshal(map[string]string{"agentId": "abc123deadbeef01", "csrPem": "not a csr"})
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", "test-bootstrap-secret")
	rec := httptest.NewRecorder()

	h.EnrollCSR(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestEnrollCSR -v`
Expected: FAIL — `h.EnrollCSR undefined` / `WithPKI undefined`

- [ ] **Step 3: Add the `pki` field, `WithPKI`, and the handler**

In `orchestrator/internal/api/handlers.go`, add the import `"github.com/audspect/bas/internal/pki"`, then add a field next to `agentSecret` (line 88):

```go
	pki                  *pki.CA // deployment CA for agent mTLS enrollment (B1/B3)
```

Add a builder method next to `WithAgentSecret` (after line 230):

```go
// WithPKI configures the deployment CA used to issue agent mTLS client
// certificates (B1/B3). Nil is valid (pre-migration deployments / tests
// that don't exercise enrollment) -- EnrollCSR returns 503 in that case.
func (h *Handler) WithPKI(ca *pki.CA) *Handler {
	h.pki = ca
	return h
}
```

Create the handler file:

```go
// orchestrator/internal/api/enroll_csr_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"time"
)

// enrollCSRRequest is the wire shape agent/protocol's SubmitCSR (Task 9)
// sends to POST /api/agents/enroll-csr.
type enrollCSRRequest struct {
	AgentID string `json:"agentId"`
	CSRPEM  string `json:"csrPem"`
}

// enrollCSRResponse carries only the signed certificate -- never a private
// key, per the spec's explicit invariant that the private key never
// crosses the enrollment boundary.
type enrollCSRResponse struct {
	CertPEM   string `json:"certPem"`
	CAPEM     string `json:"caPem"`
	ExpiresAt string `json:"expiresAt"`
}

// EnrollCSR handles POST /api/agents/enroll-csr — the bootstrap endpoint
// served on the TLS-server-only, NoClientCert :9444 listener (Task 7).
// Validates the shared bootstrap secret (same X-Agent-Token check as the
// legacy /api/agents/enroll), rejects re-bootstrap for an AgentID that
// already holds a valid unexpired certificate, then signs and returns a
// new client certificate via the deployment CA.
func (h *Handler) EnrollCSR(w http.ResponseWriter, r *http.Request) {
	if h.pki == nil {
		jsonError(w, "PKI not configured on this deployment", http.StatusServiceUnavailable)
		return
	}
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	var req enrollCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" || req.CSRPEM == "" {
		jsonError(w, "invalid request — agentId and csrPem required", http.StatusBadRequest)
		return
	}

	var alreadyValid bool
	err := h.db.QueryRow(r.Context(), `
		SELECT EXISTS (
			SELECT 1 FROM agent_certificates
			 WHERE agent_id = $1 AND revoked = false AND expires_at > NOW()
		)`, req.AgentID).Scan(&alreadyValid)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if alreadyValid {
		jsonError(w, "agent already holds a valid certificate — renew via mTLS instead of re-bootstrapping", http.StatusConflict)
		return
	}

	issued, err := h.pki.IssueClientCertificate(req.AgentID, []byte(req.CSRPEM))
	if err != nil {
		jsonError(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err = h.db.Exec(r.Context(), `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at)
		VALUES ($1, $2, NOW(), $3)`,
		issued.SerialNumber, req.AgentID, issued.ExpiresAt,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respond(w, enrollCSRResponse{
		CertPEM:   string(issued.CertPEM),
		CAPEM:     string(h.pki.RootCertPEM()),
		ExpiresAt: issued.ExpiresAt.Format(time.RFC3339),
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestEnrollCSR -v`
Expected: PASS (all four tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/enroll_csr_handlers.go orchestrator/internal/api/enroll_csr_handlers_test.go
git commit -m "feat(api): enrollment CSR handler with bootstrap-reuse rejection"
```

---

### Task 6: mTLS identity middleware, WS route update, CA-root admin export

**Files:**
- Create: `orchestrator/internal/api/mtls_context.go`
- Modify: `orchestrator/internal/api/routes.go:69-84` (the `/ws/agent` handler)
- Modify: `orchestrator/internal/api/handlers.go` (extend `GetConnectionConfig`, ~line 3320-3327)
- Test: `orchestrator/internal/api/mtls_context_test.go`, extend the existing `/ws/agent` route test if present (check `orchestrator/internal/api/routes_test.go`)

**Interfaces:**
- Produces: `api.WithMTLSIdentity(next http.Handler) http.Handler`, `api.AuthenticatedAgentID(r *http.Request) string` — consumed by Task 7's `main.go` listener wiring.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/mtls_context_test.go
package api

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithMTLSIdentity_AttachesCommonNameFromPeerCert(t *testing.T) {
	var gotID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = AuthenticatedAgentID(r)
	})
	wrapped := WithMTLSIdentity(inner)

	// Build a request whose TLS state carries a peer certificate with a
	// known CommonName, mirroring what net/http populates for a real mTLS
	// connection after a successful client-cert handshake.
	req := httptest.NewRequest(http.MethodGet, "/ws/agent", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "abc123deadbeef01"}}},
	}
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if gotID != "abc123deadbeef01" {
		t.Errorf("AuthenticatedAgentID = %q, want abc123deadbeef01", gotID)
	}
}

func TestWithMTLSIdentity_NoClientCertLeavesEmpty(t *testing.T) {
	var gotID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = AuthenticatedAgentID(r)
	})
	wrapped := WithMTLSIdentity(inner)

	req := httptest.NewRequest(http.MethodGet, "/ws/agent", nil) // req.TLS is nil (plaintext/legacy listener)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if gotID != "" {
		t.Errorf("AuthenticatedAgentID = %q, want empty for a non-mTLS request", gotID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestWithMTLSIdentity|TestWSAgentAuthorized' -v`
Expected: FAIL — `WithMTLSIdentity undefined`

- [ ] **Step 3: Write the middleware, update the WS route, extend the admin endpoint**

```go
// orchestrator/internal/api/mtls_context.go
package api

import (
	"context"
	"net/http"
)

type ctxKey int

const ctxKeyAuthenticatedAgentID ctxKey = iota

// WithMTLSIdentity wraps next so that any request arriving with a verified
// client certificate (i.e. requests on the mTLS-required 9443 listener —
// see Task 7's main.go wiring) has the certificate's CommonName attached to
// its context. That CommonName is the server-authoritative AgentID stamped
// in by pki.IssueClientCertificate (Task 3) at enrollment time.
//
// A request with no client certificate (the enrollment or legacy listeners,
// where req.TLS is nil or carries no PeerCertificates) passes through
// unchanged; AuthenticatedAgentID returns "" for it.
func WithMTLSIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn := r.TLS.PeerCertificates[0].Subject.CommonName
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyAuthenticatedAgentID, cn))
		}
		next.ServeHTTP(w, r)
	})
}

// AuthenticatedAgentID returns the AgentID established by a verified mTLS
// client certificate on this connection, or "" if the request arrived
// without one.
func AuthenticatedAgentID(r *http.Request) string {
	v, _ := r.Context().Value(ctxKeyAuthenticatedAgentID).(string)
	return v
}
```

Add a standalone, directly unit-testable authorization check to `orchestrator/internal/api/mtls_context.go` (same file as `WithMTLSIdentity`/`AuthenticatedAgentID` above), rather than inlining the logic in `routes.go`'s closure where it can't be called from a test without a real WS upgrade:

```go
// wsAgentAuthorized decides whether a /ws/agent request may proceed, before
// any WebSocket upgrade is attempted. An mTLS-authenticated connection
// (mtlsID != "") must have its claimed agentId query param match the
// certificate's identity exactly -- a cert issued for one agent must never
// be usable to claim another's identity. A connection with no mTLS
// identity (enrollment/legacy listeners) falls back to the pre-existing
// agentSecret query param/X-Agent-Token header check, unchanged from
// today. Returns (true, 0, "") to proceed, or (false, statusCode, message)
// to reject.
func wsAgentAuthorized(req *http.Request, agentSecret string) (ok bool, statusCode int, msg string) {
	claimedID := req.URL.Query().Get("agentId")
	if mtlsID := AuthenticatedAgentID(req); mtlsID != "" {
		if claimedID != mtlsID {
			return false, http.StatusUnauthorized, "agentId does not match authenticated certificate"
		}
		return true, 0, ""
	}
	if agentSecret != "" {
		provided := req.URL.Query().Get("agentSecret")
		if provided == "" {
			provided = req.Header.Get("X-Agent-Token")
		}
		if provided != agentSecret {
			return false, http.StatusUnauthorized, "unauthorized"
		}
	}
	return true, 0, ""
}
```

Then replace the `/ws/agent` handler body in `orchestrator/internal/api/routes.go` (lines 69-84) with:

```go
	// WebSocket — agents connect here. See wsAgentAuthorized (mtls_context.go)
	// for the identity-check logic this delegates to.
	r.Get("/ws/agent", func(w http.ResponseWriter, req *http.Request) {
		if license.Current().State == license.StateLocked {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if ok, code, msg := wsAgentAuthorized(req, agentSecret); !ok {
			http.Error(w, msg, code)
			return
		}
		hub.ServeAgentWS(w, req)
	})
```

Add the corresponding unit tests to `orchestrator/internal/api/mtls_context_test.go`:

```go
func TestWSAgentAuthorized_MTLSIdentityMismatchRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=claimed-other-agent", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "real-authenticated-agent"}}},
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAuthenticatedAgentID, "real-authenticated-agent"))

	ok, code, _ := wsAgentAuthorized(req, "")
	if ok {
		t.Error("expected rejection when ?agentId= does not match the authenticated certificate's identity")
	}
	if code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", code)
	}
}

func TestWSAgentAuthorized_MTLSIdentityMatchAccepted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=real-authenticated-agent", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAuthenticatedAgentID, "real-authenticated-agent"))

	ok, _, _ := wsAgentAuthorized(req, "")
	if !ok {
		t.Error("expected acceptance when ?agentId= matches the authenticated certificate's identity")
	}
}

func TestWSAgentAuthorized_LegacyFallbackUnchanged(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=x&agentSecret=correct-secret", nil)
	// No context value set -- simulates the plaintext/legacy listener, where
	// WithMTLSIdentity was never applied.
	if ok, _, _ := wsAgentAuthorized(req, "correct-secret"); !ok {
		t.Error("expected acceptance with the correct legacy agentSecret")
	}
	if ok, code, _ := wsAgentAuthorized(req, "different-secret"); ok || code != http.StatusUnauthorized {
		t.Errorf("expected rejection with a wrong legacy agentSecret, got ok=%v code=%d", ok, code)
	}
}
```

This requires adding `"context"` to `mtls_context_test.go`'s imports.

In `orchestrator/internal/api/handlers.go`, extend `GetConnectionConfig` (around line 3320-3327) so admins can fetch the CA root for installer bundling alongside the existing bootstrap secret:

```go
// GET /api/config/connection — returns the agent bootstrap secret and
// deployment CA root so admins can assemble an agent installer package
// without needing SSH access to the server. The CA root is not secret
// (it's a public certificate) — safe to return here alongside the secret.
func (h *Handler) GetConnectionConfig(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{
		"agentSecret": h.agentSecret,
	}
	if h.pki != nil {
		resp["caRootPem"] = string(h.pki.RootCertPEM())
	}
	respond(w, resp)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestWithMTLSIdentity|TestWSAgentAuthorized|TestEnrollCSR' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/mtls_context.go orchestrator/internal/api/mtls_context_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/handlers.go
git commit -m "feat(api): derive agent identity from verified mTLS cert, not query param"
```

---

### Task 7: Three-listener wiring in main.go

**Files:**
- Modify: `orchestrator/cmd/server/main.go:571-600` (handler builder chain), `:770-793` (the single `srv`/`ListenAndServe` block)

**Interfaces:**
- Consumes: `pki.LoadOrGenerateCA` (Task 2), `Handler.WithPKI` (Task 5), `api.WithMTLSIdentity` (Task 6), `cfg.PKIDir`/`cfg.EnrollHTTPPort`/`cfg.LegacyHTTPPort` (Task 1).
- Produces: three running `http.Server`s — this is the integration point Task 10's/Task 11's agent-side bootstrap and mTLS connect actually talk to.

- [ ] **Step 1: Write the failing test**

This task is an integration wiring change with no unit-testable pure function of its own — verified instead by a real end-to-end handshake test, which doubles as the "no circular dependency" regression test called for in the spec's Testing section.

```go
// orchestrator/cmd/server/listeners_test.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/audspect/bas/internal/pki"
)

// TestThreeListeners_EnrollListenerAcceptsNoClientCert is the regression
// test the spec calls for: a client presenting NO certificate must be able
// to complete a TLS handshake against the enrollment listener (proving the
// circular-dependency bug -- a brand-new agent can't get a cert from a
// listener that requires one -- cannot reoccur), while the same bare
// handshake against the mTLS listener must fail.
func TestThreeListeners_EnrollListenerAcceptsNoClientCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	serverCert, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())

	mtlsSrv := newTLSListenerForTest(t, serverCert, tls.RequireAndVerifyClientCert, pool)
	enrollSrv := newTLSListenerForTest(t, serverCert, tls.NoClientCert, pool)
	defer mtlsSrv.Close()
	defer enrollSrv.Close()

	clientCfg := &tls.Config{RootCAs: pool} // no client certificate presented

	if _, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", enrollSrv.Listener.Addr().String(), clientCfg); err != nil {
		t.Errorf("enrollment listener rejected a no-client-cert handshake (this is the exact circular-dependency bug the 3-listener design fixes): %v", err)
	}
	if _, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", mtlsSrv.Listener.Addr().String(), clientCfg); err == nil {
		t.Error("mTLS listener accepted a no-client-cert handshake — RequireAndVerifyClientCert is not being enforced")
	}
}

// newTLSListenerForTest starts a real TLS listener on 127.0.0.1 with the
// given ClientAuth mode, mirroring the tls.Config shape Task 7's real
// main.go wiring builds for the 9443/9444 servers.
func newTLSListenerForTest(t *testing.T, serverCert tls.Certificate, clientAuth tls.ClientAuthType, clientCAs *x509.CertPool) *httptestServer {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })}
	go srv.Serve(ln)
	return &httptestServer{Listener: ln, srv: srv}
}

type httptestServer struct {
	Listener net.Listener
	srv      *http.Server
}

func (s *httptestServer) Close() { s.srv.Close() }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./cmd/server/... -run TestThreeListeners -v`
Expected: FAIL to compile initially only if `pki` isn't yet importable in this package context — since Task 2 already lands `pki`, this should actually compile and PASS immediately as a standalone TLS-config test (it doesn't yet exercise `main.go`'s real wiring). That's fine: its purpose is to pin the *design property* (enroll listener = NoClientCert must succeed handshake, mTLS listener = RequireAndVerifyClientCert must reject it) before Step 3 wires the real listeners to match it. Confirm it passes as written, then proceed.

- [ ] **Step 3: Wire the three listeners in main.go**

In `orchestrator/cmd/server/main.go`, add the import `"github.com/audspect/bas/internal/pki"` and `"crypto/tls"` and `"crypto/x509"`.

Add the CA load call before the handler builder chain (before line 571):

```go
	ca, err := pki.LoadOrGenerateCA(cfg.PKIDir)
	if err != nil {
		log.Fatalf("[FATAL] load/generate deployment CA: %v", err)
	}
```

Add `.WithPKI(ca)` to the handler builder chain (anywhere among the existing `.With...()` calls, e.g. right after `.WithAgentSecret(cfg.AgentSecret)`):

```go
		WithAgentSecret(cfg.AgentSecret).
		WithPKI(ca).
```

Replace the single `srv := &http.Server{...}` / `ListenAndServe` block (lines 770-793) with:

```go
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(ca.Certificate())
	serverTLSCert, err := ca.TLSCertificate()
	if err != nil {
		log.Fatalf("[FATAL] build server TLS identity from CA: %v", err)
	}

	// 9443 — mandatory mTLS, canonical secure endpoint for enrolled agents
	// (normal operation + certificate renewal). Never weaken this to
	// VerifyClientCertIfGiven -- see spec Section 1.
	mtlsHandler := api.WithMTLSIdentity(router)
	mtlsSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler: mtlsHandler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAPool,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 9444 — TLS server-authenticated only, NO client cert required.
	// Permanent infrastructure for onboarding brand-new agents (not a
	// migration bridge) -- see spec Section 1 for why this listener must
	// exist even after B2 retires the legacy port.
	enrollSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.EnrollHTTPPort),
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientAuth:   tls.NoClientCert,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 9000 — temporary legacy plaintext listener, unchanged behavior, for
	// pre-migration agents only. Retired entirely by the separately-scoped
	// B2 work.
	legacySrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.LegacyHTTPPort),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("[*] BAS Orchestrator mTLS listening on :%d", cfg.HTTPPort)
		if err := mtlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] mTLS listen: %v", err)
		}
	}()
	go func() {
		log.Printf("[*] BAS Orchestrator enrollment listener on :%d", cfg.EnrollHTTPPort)
		if err := enrollSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] enrollment listen: %v", err)
		}
	}()
	go func() {
		log.Printf("[*] BAS Orchestrator legacy listener on :%d (temporary — retired by B2)", cfg.LegacyHTTPPort)
		if err := legacySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] legacy listen: %v", err)
		}
	}()

	// ── Graceful Shutdown ─────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[*] Shutting down gracefully...")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	for _, s := range []*http.Server{mtlsSrv, enrollSrv, legacySrv} {
		if err := s.Shutdown(shutCtx); err != nil {
			log.Printf("[!] shutdown error: %v", err)
		}
	}
	log.Println("[*] Server stopped.")
}
```

Note: `ListenAndServeTLS("", "")` with empty paths uses the certificates already set in `TLSConfig.Certificates` — this is the correct stdlib idiom when certs are loaded programmatically (as here, via `ca.TLSCertificate()`) rather than from disk paths.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./cmd/server/... -v`
Expected: build succeeds, `TestThreeListeners_EnrollListenerAcceptsNoClientCert` passes.

Then a manual smoke check:
```bash
cd orchestrator && go run ./cmd/server &
sleep 2
curl -k https://localhost:9444/api/config/connection  # should connect without a client cert
curl -k https://localhost:9443/api/config/connection  # should fail the TLS handshake (no client cert)
kill %1
```
Expected: the 9444 curl gets an HTTP response (even if 401/403 from auth, the *TLS handshake* succeeds); the 9443 curl fails at the TLS layer (`curl: (35) ... alert certificate required` or similar).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/cmd/server/main.go orchestrator/cmd/server/listeners_test.go
git commit -m "feat(server): serve 9443 mTLS, 9444 enrollment, 9000 legacy listeners"
```

---

### Task 8: Agent certificate store — ECDSA keygen, CSR generation, persistence

**Files:**
- Create: `agent/certstore.go`
- Create: `agent/certstore_windows.go`
- Create: `agent/certstore_posix.go`
- Test: `agent/certstore_test.go`

**Interfaces:**
- Produces: `certPaths() (dir, caPath, certPath, keyPath string)`, `loadOrGenerateAgentKey() (*ecdsa.PrivateKey, error)`, `generateCSR(key *ecdsa.PrivateKey, agentID string) ([]byte, error)`, `saveAgentCertificate(certPEM []byte) error`, `loadAgentCertificate() (*x509.Certificate, error)` (returns `nil, os.ErrNotExist`-wrapping error if none saved yet), `certExpiringSoon(cert *x509.Certificate) bool` (true at ≥75% of lifetime elapsed) — consumed by Task 10 (bootstrap) and Task 12 (renewal).

- [ ] **Step 1: Write the failing test**

```go
// agent/certstore_test.go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrGenerateAgentKey_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir) // test override — see Step 3's certPaths()

	key1, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("first loadOrGenerateAgentKey: %v", err)
	}
	key2, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("second loadOrGenerateAgentKey: %v", err)
	}
	if key1.X.Cmp(key2.X) != 0 || key1.Y.Cmp(key2.Y) != 0 {
		t.Error("second call generated a NEW key instead of loading the persisted one")
	}
}

func TestGenerateCSR_ProducesParsableCSRForAgentID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	csrPEM, err := generateCSR(key, "abc123deadbeef01")
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("generateCSR did not produce a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("CSR CommonName = %q, want abc123deadbeef01", csr.Subject.CommonName)
	}
}

func TestSaveAndLoadAgentCertificate_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	if _, err := loadAgentCertificate(); err == nil {
		t.Fatal("expected an error loading a certificate before one has been saved")
	}

	// A minimal self-signed cert stands in for a CA-issued one here —
	// saveAgentCertificate/loadAgentCertificate only care about PEM
	// round-tripping, not signature validity (that's the CA's/server's job
	// on the way in, and TLS's job on every subsequent handshake).
	certPEM := selfSignedTestCertPEM(t, "abc123deadbeef01")
	if err := saveAgentCertificate(certPEM); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	loaded, err := loadAgentCertificate()
	if err != nil {
		t.Fatalf("loadAgentCertificate: %v", err)
	}
	if loaded.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("loaded cert CommonName = %q, want abc123deadbeef01", loaded.Subject.CommonName)
	}
}

func TestCertExpiringSoon(t *testing.T) {
	now := time.Now()
	fresh := &x509.Certificate{NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(364 * 24 * time.Hour)} // ~0.3% elapsed
	old := &x509.Certificate{NotBefore: now.Add(-300 * 24 * time.Hour), NotAfter: now.Add(65 * 24 * time.Hour)}  // ~82% elapsed

	if certExpiringSoon(fresh) {
		t.Error("a freshly issued certificate should not be reported as expiring soon")
	}
	if !certExpiringSoon(old) {
		t.Error("a certificate at ~82% of its lifetime should be reported as expiring soon (75% threshold)")
	}
}

// selfSignedTestCertPEM builds a throwaway self-signed cert for round-trip
// testing only — not used anywhere outside this test file.
func selfSignedTestCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := loadOrGenerateAgentKey() // reuses BAS_CERT_DIR set by the caller
	if err != nil {
		t.Fatalf("key for self-signed test cert: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(),
		Subject:      x509PkixNameCN(commonName),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(randReaderForTest(), tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed test cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
```

Note: `bigOne()`, `x509PkixNameCN()`, and `randReaderForTest()` above are placeholders for imports you'll actually inline directly (`big.NewInt(1)`, `pkix.Name{CommonName: commonName}`, `rand.Reader` from `crypto/rand`) — write `selfSignedTestCertPEM` using those real stdlib calls directly with the proper imports (`crypto/rand`, `crypto/x509/pkix`, `math/big`) rather than defining wrapper functions.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run 'TestLoadOrGenerateAgentKey|TestGenerateCSR|TestSaveAndLoadAgentCertificate|TestCertExpiringSoon' -v`
Expected: FAIL — undefined functions

- [ ] **Step 3: Write the implementation**

```go
// agent/certstore.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// certExpiringSoonThreshold: renew at 75% of the certificate's lifetime
// elapsed (spec Section 2 default), independent of the re-enroll-on-upgrade
// trigger Task 12 also wires in.
const certExpiringSoonThreshold = 0.75

// certPaths returns the directory holding the agent's cert/key material and
// the individual file paths within it. BAS_CERT_DIR overrides the
// platform default for tests; production installs never set it and get
// certDirPlatform()'s real per-OS path (agent/certstore_windows.go /
// agent/certstore_posix.go).
func certPaths() (dir, caPath, certPath, keyPath string) {
	dir = os.Getenv("BAS_CERT_DIR")
	if dir == "" {
		dir = certDirPlatform()
	}
	return dir, filepath.Join(dir, "deployment-ca.pem"), filepath.Join(dir, "agent-cert.pem"), filepath.Join(dir, "agent-key.pem")
}

// loadOrGenerateAgentKey loads the agent's persisted ECDSA P-256 private
// key, generating and saving a new one on first run. The private key never
// leaves this function's callers' process — it is never transmitted over
// the network (only its public half, embedded in a CSR, is — see
// generateCSR).
func loadOrGenerateAgentKey() (*ecdsa.PrivateKey, error) {
	dir, _, _, keyPath := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decode agent key PEM %s: no PEM block found", keyPath)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal agent key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("write agent key: %w", err)
	}
	if err := hardenCertDirPlatform(dir); err != nil {
		// Non-fatal: log-worthy but the key was still written. Callers in
		// Task 10/11 log this; certstore itself stays a pure storage layer.
		return key, fmt.Errorf("key saved, but directory hardening failed: %w", err)
	}
	return key, nil
}

// generateCSR builds a PEM-encoded PKCS#10 CSR for key, requesting agentID
// as its CommonName. The orchestrator (Task 5's EnrollCSR handler) treats
// this as a REQUEST only — it is the server, not this CSR, that is
// authoritative for what identity ends up in the signed certificate.
func generateCSR(key *ecdsa.PrivateKey, agentID string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: agentID},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// saveAgentCertificate persists a newly issued (or renewed) certificate.
func saveAgentCertificate(certPEM []byte) error {
	dir, _, certPath, _ := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	return os.WriteFile(certPath, certPEM, 0644)
}

// loadAgentCertificate returns the currently persisted certificate, or an
// error wrapping os.ErrNotExist if none has been saved yet (the caller,
// Task 10's bootstrap orchestration, treats that as "run initial bootstrap").
func loadAgentCertificate() (*x509.Certificate, error) {
	_, _, certPath, _ := certPaths()
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err // os.ReadFile already wraps os.ErrNotExist correctly
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode agent cert PEM %s: no PEM block found", certPath)
	}
	return x509.ParseCertificate(block.Bytes)
}

// certExpiringSoon reports whether cert has crossed 75% of its total
// lifetime — the renewal trigger threshold (spec Section 2 default).
func certExpiringSoon(cert *x509.Certificate) bool {
	total := cert.NotAfter.Sub(cert.NotBefore)
	elapsed := time.Since(cert.NotBefore)
	if total <= 0 {
		return true // malformed lifetime — treat as needing renewal rather than trusting it
	}
	return float64(elapsed)/float64(total) >= certExpiringSoonThreshold
}
```

Create the two platform files (mirroring the existing `platform_windows.go`/`platform_posix.go` split):

```go
// agent/certstore_windows.go
//go:build windows

package main

import (
	"os/exec"
)

// certDirPlatform is where the agent's CA root, own certificate, and
// private key are stored on Windows — separate from the DPAPI-encrypted
// registry storage used for the bootstrap AgentSecret (agent/config.go),
// since these are files a real TLS stack needs to read directly, not a
// single decrypted string.
func certDirPlatform() string {
	return `C:\ProgramData\Audspect\certs`
}

// hardenCertDirPlatform restricts the cert directory to SYSTEM and
// Administrators via icacls, matching how the rest of this codebase already
// shells out to Windows-native tools for privileged operations (see
// elevate.go, suppress_windows.go) rather than reimplementing Windows ACL
// APIs directly. Best-effort: a failure here is reported to the caller but
// does not prevent the key from being usable.
func hardenCertDirPlatform(dir string) error {
	cmd := exec.Command("icacls", dir,
		"/inheritance:r",
		"/grant:r", `SYSTEM:(OI)(CI)F`,
		"/grant:r", `*S-1-5-32-544:(OI)(CI)F`, // well-known SID for Administrators
	)
	return cmd.Run()
}
```

```go
// agent/certstore_posix.go
//go:build linux || darwin

package main

// certDirPlatform is where the agent's CA root, own certificate, and
// private key are stored on Linux/macOS.
func certDirPlatform() string {
	return "/etc/audspect/certs"
}

// hardenCertDirPlatform is a no-op on POSIX — loadOrGenerateAgentKey and
// saveAgentCertificate already write with 0700/0600 permissions, which is
// sufficient given the agent already runs as root (see the existing
// elevation checks in platform_posix.go's callers).
func hardenCertDirPlatform(dir string) error { return nil }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test . -run 'TestLoadOrGenerateAgentKey|TestGenerateCSR|TestSaveAndLoadAgentCertificate|TestCertExpiringSoon' -v`
Expected: PASS (run on whichever platform this session is on — Windows per the environment; the posix file simply won't compile into this run's binary, which is correct and expected for `//go:build` split files)

- [ ] **Step 5: Commit**

```bash
git add agent/certstore.go agent/certstore_windows.go agent/certstore_posix.go agent/certstore_test.go
git commit -m "feat(agent): ECDSA keypair, CSR generation, and cert persistence"
```

---

### Task 9: Agent-side CSR submission protocol

**Files:**
- Create: `agent/protocol/csr.go`
- Test: `agent/protocol/csr_test.go`

**Interfaces:**
- Consumes: nothing new (uses `*http.Client` passed in by the caller, mirroring `Enroll`'s signature in `agent/protocol/enroll.go`).
- Produces: `protocol.CSRRequest{AgentID, CSRPEM string}`, `protocol.CSRResponse{CertPEM, CAPEM, ExpiresAt string}`, `protocol.SubmitCSR(ctx context.Context, client *http.Client, enrollURL, bootstrapSecret string, req CSRRequest) (CSRResponse, error)` — consumed by Task 10.

- [ ] **Step 1: Write the failing test**

```go
// agent/protocol/csr_test.go
package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitCSR_SendsBootstrapSecretAndCSR(t *testing.T) {
	var gotToken, gotAgentID, gotCSR string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Agent-Token")
		var body CSRRequest
		json.NewDecoder(r.Body).Decode(&body)
		gotAgentID = body.AgentID
		gotCSR = body.CSRPEM
		json.NewEncoder(w).Encode(CSRResponse{CertPEM: "cert-pem-here", CAPEM: "ca-pem-here", ExpiresAt: "2027-01-01T00:00:00Z"})
	}))
	defer srv.Close()

	resp, err := SubmitCSR(context.Background(), srv.Client(), srv.URL, "bootstrap-secret-123", CSRRequest{
		AgentID: "abc123deadbeef01",
		CSRPEM:  "csr-pem-here",
	})
	if err != nil {
		t.Fatalf("SubmitCSR: %v", err)
	}
	if gotToken != "bootstrap-secret-123" {
		t.Errorf("X-Agent-Token = %q, want bootstrap-secret-123", gotToken)
	}
	if gotAgentID != "abc123deadbeef01" || gotCSR != "csr-pem-here" {
		t.Errorf("request body = {%q, %q}, want the values passed to SubmitCSR", gotAgentID, gotCSR)
	}
	if resp.CertPEM != "cert-pem-here" {
		t.Errorf("resp.CertPEM = %q, want cert-pem-here", resp.CertPEM)
	}
}

func TestSubmitCSR_ServerErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	_, err := SubmitCSR(context.Background(), srv.Client(), srv.URL, "secret", CSRRequest{AgentID: "x", CSRPEM: "y"})
	if err == nil {
		t.Fatal("expected an error on a 409 response, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test ./protocol/... -run TestSubmitCSR -v`
Expected: FAIL — `CSRRequest undefined`

- [ ] **Step 3: Write the implementation**

```go
// agent/protocol/csr.go
package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CSRRequest is sent by the agent to POST /api/agents/enroll-csr — the
// bootstrap CSR-submission endpoint served on the orchestrator's
// TLS-server-only :9444 listener. Mirrors EnrollRequest's role in
// enroll.go, but for the CSR-based mTLS bootstrap flow (spec Section 2)
// rather than the legacy shared-secret enrollment this coexists with
// during migration.
type CSRRequest struct {
	AgentID string `json:"agentId"`
	CSRPEM  string `json:"csrPem"`
}

// CSRResponse is returned by POST /api/agents/enroll-csr. CertPEM is the
// signed agent client certificate; CAPEM is the deployment CA root
// (returned again here as a convenience/consistency check even though the
// agent's installer already has it, per the spec's "never return a private
// key" invariant — only ever public material crosses this boundary).
type CSRResponse struct {
	CertPEM   string `json:"certPem"`
	CAPEM     string `json:"caPem"`
	ExpiresAt string `json:"expiresAt"`
}

// SubmitCSR performs the bootstrap CSR submission against
// POST {enrollURL}/api/agents/enroll-csr, authenticated with
// bootstrapSecret via X-Agent-Token (the same header shape Enroll already
// uses). The single network-calling implementation of this step — Task 10
// (bootstrap.go) and any future loadgen equivalent both call this, neither
// reimplements it.
func SubmitCSR(ctx context.Context, client *http.Client, enrollURL, bootstrapSecret string, req CSRRequest) (CSRResponse, error) {
	var resp CSRResponse
	data, err := json.Marshal(req)
	if err != nil {
		return resp, fmt.Errorf("marshal CSR request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL+"/api/agents/enroll-csr", bytes.NewReader(data))
	if err != nil {
		return resp, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Agent-Token", bootstrapSecret)
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("POST /api/agents/enroll-csr: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("server %d on /api/agents/enroll-csr", httpResp.StatusCode)
	}
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return resp, fmt.Errorf("decode CSR response: %w", err)
	}
	return resp, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test ./protocol/... -run TestSubmitCSR -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/protocol/csr.go agent/protocol/csr_test.go
git commit -m "feat(agent/protocol): CSR bootstrap submission client"
```

---

### Task 10: Agent bootstrap orchestration

**Files:**
- Create: `agent/bootstrap.go`
- Test: `agent/bootstrap_test.go`

**Interfaces:**
- Consumes: `certPaths`, `loadOrGenerateAgentKey`, `generateCSR`, `saveAgentCertificate`, `loadAgentCertificate` (Task 8); `protocol.SubmitCSR`, `protocol.CSRRequest` (Task 9).
- Produces: `(a *Agent) ensureCertificate(ctx context.Context) error` — consumed by Task 11's `main.go` wiring, called before `connectWS`.

- [ ] **Step 1: Write the failing test**

```go
// agent/bootstrap_test.go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"audspect/agent/protocol"
)

func TestEnsureCertificate_SkipsBootstrapWhenValidCertExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	// Seed a still-valid certificate directly, bypassing the network —
	// this pins the "already enrolled agent restarts, does NOT re-bootstrap"
	// Review Focus item.
	certPEM := selfSignedTestCertPEMWithKey(t, key, "abc123deadbeef01")
	if err := saveAgentCertificate(certPEM); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	a := &Agent{cfg: Config{ServerURL: srv.URL, AgentSecret: "secret"}, id: Identity{AgentID: "abc123deadbeef01"}}
	if err := a.ensureCertificate(context.Background()); err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	if called {
		t.Error("ensureCertificate hit the network bootstrap endpoint despite already holding a valid certificate")
	}
}

func TestEnsureCertificate_BootstrapsWhenNoCertExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CSRRequest
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(protocol.CSRResponse{
			CertPEM:   string(selfSignedTestCertPEMForRequestedID(t, req.AgentID)),
			CAPEM:     "ca-pem-placeholder",
			ExpiresAt: "2027-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	a := &Agent{cfg: Config{ServerURL: srv.URL, AgentSecret: "secret"}, id: Identity{AgentID: "abc123deadbeef01"}}
	if err := a.ensureCertificate(context.Background()); err != nil {
		t.Fatalf("ensureCertificate: %v", err)
	}
	cert, err := loadAgentCertificate()
	if err != nil {
		t.Fatalf("loadAgentCertificate after bootstrap: %v", err)
	}
	if cert.Subject.CommonName != "abc123deadbeef01" {
		t.Errorf("persisted cert CommonName = %q, want abc123deadbeef01", cert.Subject.CommonName)
	}
}
```

Add these two test-only helpers to the same `bootstrap_test.go` file (used by this task's tests and referenced again by Task 11 and Task 12 — both are written once, here, and never redefined):

```go
// selfSignedTestCertPEMWithKey builds a throwaway self-signed certificate
// for an EXISTING key -- used wherever a test needs the certificate to
// correspond to a specific already-generated agent key (so
// tls.LoadX509KeyPair-style pairing works in Task 11's tests).
func selfSignedTestCertPEMWithKey(t *testing.T, key *ecdsa.PrivateKey, commonName string) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed test cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// selfSignedTestCertPEMForRequestedID generates a FRESH key and a
// self-signed cert for commonName -- used by the fake-server side of a
// bootstrap test (the mock orchestrator handler), which has no reason to
// share the agent-under-test's own key.
func selfSignedTestCertPEMForRequestedID(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return selfSignedTestCertPEMWithKey(t, key, commonName)
}
```

This requires `bootstrap_test.go` to import `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `crypto/x509`, `crypto/x509/pkix`, `encoding/pem`, `math/big`, and `time` alongside the imports already shown in Step 1.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run TestEnsureCertificate -v`
Expected: FAIL — `a.ensureCertificate undefined`

- [ ] **Step 3: Write the implementation**

```go
// agent/bootstrap.go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"audspect/agent/protocol"
)

// ensureCertificate guarantees the agent holds a valid, unexpired mTLS
// client certificate before connectWS is called. If one already exists and
// isn't expiring soon, this is a fast no-op (Review Focus: an
// already-enrolled agent restarting must never re-bootstrap — that would
// also just get rejected by the orchestrator's reuse-limit check, Task 5).
// Otherwise it performs the CSR bootstrap flow against the enrollment
// listener (:9444 in production, derived from a.cfg.ServerURL below).
func (a *Agent) ensureCertificate(ctx context.Context) error {
	if cert, err := loadAgentCertificate(); err == nil && !certExpiringSoon(cert) {
		return nil
	}

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		return fmt.Errorf("load/generate agent key: %w", err)
	}
	csrPEM, err := generateCSR(key, a.id.AgentID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	enrollURL, err := enrollmentURL(a.cfg.ServerURL)
	if err != nil {
		return fmt.Errorf("derive enrollment URL: %w", err)
	}
	client, err := bootstrapHTTPClient(a.cfg)
	if err != nil {
		return fmt.Errorf("build bootstrap HTTP client: %w", err)
	}

	resp, err := protocol.SubmitCSR(ctx, client, enrollURL, a.cfg.AgentSecret, protocol.CSRRequest{
		AgentID: a.id.AgentID,
		CSRPEM:  string(csrPEM),
	})
	if err != nil {
		return fmt.Errorf("submit CSR: %w", err)
	}
	if err := saveAgentCertificate([]byte(resp.CertPEM)); err != nil {
		return fmt.Errorf("save issued certificate: %w", err)
	}
	log.Printf("[*] certificate issued (expires %s)", resp.ExpiresAt)
	return nil
}

// enrollmentURL rewrites serverURL's port to the enrollment listener's port
// (9444 by default — matches config.EnrollHTTPPort's orchestrator-side
// default from Task 1). BAS_ENROLL_PORT overrides for non-default
// deployments, mirroring how BAS_SERVER_URL itself is already overridable.
func enrollmentURL(serverURL string) (string, error) {
	port := os.Getenv("BAS_ENROLL_PORT")
	if port == "" {
		port = "9444"
	}
	// serverURL is like "https://host:9443" (or "http://host:9000" for a
	// still-legacy-configured agent) — swap only the port.
	idx := strings.LastIndex(serverURL, ":")
	if idx <= strings.Index(serverURL, "//")+2 { // no explicit port present
		return serverURL + ":" + port, nil
	}
	return serverURL[:idx] + ":" + port, nil
}

// bootstrapHTTPClient builds an *http.Client that trusts the deployment CA
// root (bundled by the installer alongside the bootstrap secret — see the
// spec's installer artifacts list) for verifying the orchestrator's TLS
// server certificate during bootstrap, before this agent has any client
// certificate of its own to present.
func bootstrapHTTPClient(cfg Config) (*http.Client, error) {
	_, caPath, _, _ := certPaths()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read deployment CA root %s (expected to be placed by the installer): %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse deployment CA root %s: not a valid PEM certificate", caPath)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:     proxyAwareNetDialContext(cfg),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}, nil
}
```

Note on `loadAgentCertificate`'s PEM decode above: it already returns a parsed `*x509.Certificate` (Task 8), so `certExpiringSoon(cert)` composes directly — no extra decode step needed here.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test . -run TestEnsureCertificate -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/bootstrap.go agent/bootstrap_test.go
git commit -m "feat(agent): bootstrap orchestration — skip when valid cert exists, else CSR flow"
```

---

### Task 11: mTLS-aware HTTP client / WS dialer, wired into main.go

**Files:**
- Modify: `agent/agent.go:100-107` (`newAgent`'s `client` field construction)
- Modify: `agent/protocol/websocket.go` (`DialAgentWSWithDialer` — add an optional `tls.Config`)
- Modify: `agent/main.go:90-93` (call `ensureCertificate` before `connectWS`)
- Test: `agent/agent_mtls_test.go`

**Interfaces:**
- Consumes: Task 8's `certPaths`/`loadAgentCertificate`, Task 10's `ensureCertificate`.
- Produces: `mtlsTLSConfig(cfg Config) (*tls.Config, error)` (nil, nil if no local cert yet — legacy fallback), modified `newAgent` and `DialAgentWSWithDialer` signatures.

- [ ] **Step 1: Write the failing test**

```go
// agent/agent_mtls_test.go
package main

import (
	"testing"
)

func TestMTLSTLSConfig_NilWhenNoCertificatePresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	cfg, err := mtlsTLSConfig(Config{})
	if err != nil {
		t.Fatalf("mtlsTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Error("expected a nil *tls.Config when no local certificate exists yet (legacy fallback path)")
	}
}

func TestMTLSTLSConfig_PopulatedWhenCertificateExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	certPEM := selfSignedTestCertPEMWithKey(t, key, "abc123deadbeef01") // from Task 10's test file
	if err := saveAgentCertificate(certPEM); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	// Also need a CA root on disk for RootCAs -- reuse the same self-signed
	// cert as a stand-in CA for this unit test's purposes.
	if err := writeTestCARoot(t, dir, certPEM); err != nil {
		t.Fatalf("writeTestCARoot: %v", err)
	}

	cfg, err := mtlsTLSConfig(Config{})
	if err != nil {
		t.Fatalf("mtlsTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a populated *tls.Config when a local certificate exists")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(cfg.Certificates))
	}
}
```

Add this helper to `agent/agent_mtls_test.go` (it needs `path/filepath` and `os` imported; `selfSignedTestCertPEMWithKey` is already defined in `agent/bootstrap_test.go`, Task 10, and is visible here since both files are in package `main`):

```go
// writeTestCARoot places pemBytes at the canonical CA-root path within dir,
// standing in for what a real installer places there before first run
// (Task 13). Tests that need AppendCertsFromPEM to succeed for a
// self-signed test cert use this rather than a real CA.
func writeTestCARoot(t *testing.T, dir string, pemBytes []byte) error {
	t.Helper()
	return os.WriteFile(filepath.Join(dir, "deployment-ca.pem"), pemBytes, 0644)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run TestMTLSTLSConfig -v`
Expected: FAIL — `mtlsTLSConfig undefined`

- [ ] **Step 3: Implement `mtlsTLSConfig`, wire it into the client and dialer**

Add to `agent/certstore.go` (it belongs with the other cert-store readers, not a new file, since it only composes existing accessors):

```go
// mtlsTLSConfig builds the *tls.Config an already-enrolled agent uses for
// both its HTTP client and its WS dialer: its own client certificate plus
// the deployment CA root for verifying the orchestrator's server
// certificate. Returns (nil, nil) — not an error — when no local
// certificate exists yet, which callers (newAgent, DialAgentWSWithDialer's
// caller in connectWS) treat as "fall back to the legacy plaintext +
// shared-secret path," since that's the only option available to an agent
// that hasn't completed bootstrap yet.
func mtlsTLSConfig(cfg Config) (*tls.Config, error) {
	cert, err := loadAgentCertificate()
	if err != nil {
		return nil, nil // no cert yet — legacy fallback, not an error
	}
	_, caPath, certPath, keyPath := certPaths()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read deployment CA root: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse deployment CA root: not valid PEM")
	}
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load agent client keypair: %w", err)
	}
	_ = cert // already validated non-expired by ensureCertificate before this is called
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
	}, nil
}
```

This requires adding `"crypto/tls"` to `agent/certstore.go`'s imports.

In `agent/agent.go`, modify `newAgent` (around line 100-107) to use `mtlsTLSConfig` when available:

```go
func newAgent(cfg Config, id Identity) *Agent {
	transport := &http.Transport{DialContext: proxyAwareNetDialContext(cfg), Proxy: nil}
	if tlsCfg, err := mtlsTLSConfig(cfg); err != nil {
		log.Printf("[!] mTLS config unavailable, falling back to legacy auth: %v", err)
	} else if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	a := &Agent{
		cfg:       cfg,
		id:        id,
		status:    "idle",
		client:    &http.Client{Timeout: 30 * time.Second, Transport: transport},
```

(Keep the rest of the existing `newAgent` body unchanged — this only replaces the inline `Transport` literal with the two-line construction above, then reuses `transport` in the same `client:` field assignment that already existed.)

In `agent/protocol/websocket.go`, extend `DialAgentWSWithDialer` to accept an optional TLS config, defaulting to none (fully backward compatible with existing callers):

```go
// DialAgentWSWithDialer is DialAgentWS with an explicit *websocket.Dialer --
// the real agent uses this with a proxy-aware NetDialContext (see
// agent/proxyauth.go's proxyAwareNetDialContext) and, once enrolled via
// mTLS, dialer.TLSClientConfig already carrying the agent's client
// certificate (set by the caller before this function runs — see
// agent/agent.go's connectWS). loadgen and every other caller keeps using
// DialAgentWS with the zero-value dialer, unaffected by this addition.
func DialAgentWSWithDialer(serverURL, agentID, agentSecret string, dialer *websocket.Dialer) (*websocket.Conn, error) {
```

No signature change is actually needed here — `*websocket.Dialer` already carries a `TLSClientConfig *tls.Config` field the caller sets directly before calling this function. Instead, modify `agent/agent.go`'s `connectWS` (around line 1203) at the point it builds its `*websocket.Dialer`, to set `dialer.TLSClientConfig` from `mtlsTLSConfig(a.cfg)` the same way `newAgent` does for the HTTP client:

```go
// Inside connectWS, wherever the *websocket.Dialer is constructed today
// (find the exact current construction with:
//   grep -n "websocket.Dialer{" agent/agent.go
// before editing — this plan does not have that exact line number captured,
// so locate it directly rather than guessing) add:
if tlsCfg, err := mtlsTLSConfig(a.cfg); err == nil && tlsCfg != nil {
	dialer.TLSClientConfig = tlsCfg
}
```

In `agent/main.go`, add the bootstrap call before `connectWS` (line 91-93):

```go
	agent := newAgent(cfg, id)
	if err := agent.ensureCertificate(context.Background()); err != nil {
		log.Printf("[!] certificate bootstrap failed, falling back to legacy auth: %v", err)
	}
	agent.enrollWithServer()

	go agent.connectWS()
```

This requires adding `"context"` to `agent/main.go`'s imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go build . && go test . -run TestMTLSTLSConfig -v`
Expected: build succeeds, both tests PASS

- [ ] **Step 5: Commit**

```bash
git add agent/certstore.go agent/agent.go agent/protocol/websocket.go agent/main.go agent/agent_mtls_test.go
git commit -m "feat(agent): use mTLS client certificate when enrolled, fall back to legacy otherwise"
```

---

### Task 12: Certificate renewal

**Files:**
- Modify: `agent/bootstrap.go` (extend `ensureCertificate`'s renewal path to use mTLS instead of the bootstrap secret when a still-valid-but-expiring cert exists)
- Test: `agent/bootstrap_test.go` (add to the file created in Task 10)

**Interfaces:**
- Consumes: everything from Task 10 plus `mtlsTLSConfig` (Task 11).
- Produces: renewal now authenticates via the agent's own current certificate (mTLS) rather than the bootstrap secret, satisfying the spec's "Renewal via mTLS" requirement and avoiding Task 5's bootstrap-reuse rejection.

- [ ] **Step 1: Write the failing test**

```go
// Add to agent/bootstrap_test.go
func TestEnsureCertificate_RenewsExpiringCertViaMTLSNotBootstrapSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		t.Fatalf("loadOrGenerateAgentKey: %v", err)
	}
	// Seed a cert that's past the 75% renewal threshold.
	expiringSoonCert := selfSignedTestCertPEMWithLifetime(t, key, "abc123deadbeef01",
		-300*24*time.Hour /* NotBefore */, 65*24*time.Hour /* NotAfter, ~82% elapsed */)
	if err := saveAgentCertificate(expiringSoonCert); err != nil {
		t.Fatalf("saveAgentCertificate: %v", err)
	}
	if err := writeTestCARoot(t, dir, expiringSoonCert); err != nil {
		t.Fatalf("writeTestCARoot: %v", err)
	}

	var usedClientCert bool
	var usedBootstrapHeader bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			usedClientCert = true
		}
		if r.Header.Get("X-Agent-Token") != "" {
			usedBootstrapHeader = true
		}
		json.NewEncoder(w).Encode(protocol.CSRResponse{
			CertPEM:   string(selfSignedTestCertPEMForRequestedID(t, "abc123deadbeef01")),
			ExpiresAt: "2027-01-01T00:00:00Z",
		})
	}))
	srv.TLS.ClientAuth = tls.RequireAnyClientCert
	srv.StartTLS()
	defer srv.Close()

	a := &Agent{cfg: Config{ServerURL: srv.URL, AgentSecret: "secret"}, id: Identity{AgentID: "abc123deadbeef01"}}
	if err := a.ensureCertificate(context.Background()); err != nil {
		t.Fatalf("ensureCertificate (renewal): %v", err)
	}
	if !usedClientCert {
		t.Error("renewal request did not present the agent's existing client certificate")
	}
	if usedBootstrapHeader {
		t.Error("renewal request used the bootstrap secret header — should authenticate via mTLS only, per spec Section 2")
	}
}
```

Add this helper to `agent/bootstrap_test.go` (alongside `selfSignedTestCertPEMWithKey` from Task 10, which it otherwise duplicates except for explicit lifetime control):

```go
// selfSignedTestCertPEMWithLifetime is selfSignedTestCertPEMWithKey with
// explicit NotBefore/NotAfter offsets from time.Now(), for tests that need
// to control exactly how far into its lifetime a certificate is (e.g.
// Task 12's ~82%-elapsed renewal-trigger test).
func selfSignedTestCertPEMWithLifetime(t *testing.T, key *ecdsa.PrivateKey, commonName string, notBeforeOffset, notAfterOffset time.Duration) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(notBeforeOffset),
		NotAfter:     time.Now().Add(notAfterOffset),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed test cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run TestEnsureCertificate_RenewsExpiringCertViaMTLS -v`
Expected: FAIL — renewal currently always uses `bootstrapHTTPClient`/the bootstrap secret path (Task 10's implementation doesn't yet branch on "have a cert, just renewing" vs "no cert, first bootstrap")

- [ ] **Step 3: Split `ensureCertificate` into bootstrap vs. renewal paths**

Modify `agent/bootstrap.go`'s `ensureCertificate`:

```go
func (a *Agent) ensureCertificate(ctx context.Context) error {
	existing, loadErr := loadAgentCertificate()
	hasValidCert := loadErr == nil && !certExpiringSoon(existing)
	if hasValidCert {
		return nil
	}

	key, err := loadOrGenerateAgentKey()
	if err != nil {
		return fmt.Errorf("load/generate agent key: %w", err)
	}
	csrPEM, err := generateCSR(key, a.id.AgentID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	renewing := loadErr == nil // a cert exists (just expiring soon) — renew via mTLS, don't re-bootstrap
	var client *http.Client
	var targetURL string
	if renewing {
		// Renewal goes over the normal mTLS listener (9443), authenticated
		// by the agent's own still-valid current certificate — never the
		// bootstrap secret, per spec Section 2. mtlsTLSConfig reads the
		// CURRENT on-disk cert/key, which is still valid at this point
		// (only "expiring soon," not yet expired).
		tlsCfg, err := mtlsTLSConfig(a.cfg)
		if err != nil || tlsCfg == nil {
			return fmt.Errorf("build mTLS config for renewal: %w", err)
		}
		client = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{DialContext: proxyAwareNetDialContext(a.cfg), TLSClientConfig: tlsCfg},
		}
		targetURL = a.cfg.ServerURL // 9443, the normal operational endpoint
	} else {
		client, err = bootstrapHTTPClient(a.cfg)
		if err != nil {
			return fmt.Errorf("build bootstrap HTTP client: %w", err)
		}
		targetURL, err = enrollmentURL(a.cfg.ServerURL) // 9444
		if err != nil {
			return fmt.Errorf("derive enrollment URL: %w", err)
		}
	}

	// The bootstrap secret is only meaningful on the initial-bootstrap
	// path; SubmitCSR still sends whatever's passed for the renewal path
	// too, but the server (Task 5's EnrollCSR) is reached at a different
	// URL/listener during renewal in a fuller implementation — see the
	// note below.
	bootstrapSecret := a.cfg.AgentSecret
	if renewing {
		bootstrapSecret = "" // authenticate via mTLS, not the secret
	}

	resp, err := protocol.SubmitCSR(ctx, client, targetURL, bootstrapSecret, protocol.CSRRequest{
		AgentID: a.id.AgentID,
		CSRPEM:  string(csrPEM),
	})
	if err != nil {
		return fmt.Errorf("submit CSR (renewing=%v): %w", renewing, err)
	}
	if err := saveAgentCertificate([]byte(resp.CertPEM)); err != nil {
		return fmt.Errorf("save issued certificate: %w", err)
	}
	log.Printf("[*] certificate %s (expires %s)", map[bool]string{true: "renewed", false: "issued"}[renewing], resp.ExpiresAt)
	return nil
}
```

Note for the implementer: this task's test posts renewal requests to the same `/api/agents/enroll-csr` path via `targetURL = a.cfg.ServerURL`, which in a real deployment is the 9443 mTLS listener, not 9444. That means the orchestrator's router (shared across all three listeners per Task 7) must also route `POST /api/agents/enroll-csr` on 9443 — confirm this works automatically already, since `api.Mount`'s router is the same `http.Handler` passed to all three `http.Server`s (Task 7), so the route exists on every listener by construction; Task 5's `EnrollCSR` handler itself doesn't need to change, only reachability via 9443 needs confirming. If Task 5's handler ever needs to distinguish "renewal via mTLS" from "bootstrap via secret" behaviorally (e.g., to skip the reuse-limit check specifically for a request that already carries a matching `AuthenticatedAgentID`), add that branch to `EnrollCSR` now: `if api.AuthenticatedAgentID(r) == req.AgentID { /* renewal, skip reuse-limit check */ }` before the existing `alreadyValid` check.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test . -run TestEnsureCertificate -v`
Expected: PASS (all `TestEnsureCertificate*` tests, including the new renewal one)

- [ ] **Step 5: Commit**

```bash
git add agent/bootstrap.go agent/bootstrap_test.go
git commit -m "feat(agent): renew expiring certificates via mTLS instead of the bootstrap secret"
```

---

### Task 13: Installer support — placing the CA root before first run

The spec's installer-artifacts list (Section 2) requires the deployment CA
root to be present on disk before the agent's first run — `bootstrapHTTPClient`
(Task 10) already reads it from `certPaths()`'s fixed canonical location, but
nothing yet places it there. This task closes that gap without touching the
per-OS service-registration internals in `service.go`/`service_linux.go`/
`service_darwin.go` (unread by this plan and out of scope to modify blind) —
it adds a `--ca-root <path>` flag that copies an admin-supplied PEM file
(fetched from the orchestrator's `GET /api/config/connection`, Task 6) to
the canonical location before installation proceeds.

**Files:**
- Modify: `agent/certstore.go` (add `saveDeploymentCARoot`)
- Modify: `agent/main.go:26-56` (`--install` flag handling)
- Test: `agent/certstore_test.go` (add to the file from Task 8)

**Interfaces:**
- Consumes: `certPaths` (Task 8).
- Produces: `saveDeploymentCARoot(pemBytes []byte) error` — called from `main.go`'s `--install` path before `svcInstall`.

- [ ] **Step 1: Write the failing test**

```go
// Add to agent/certstore_test.go
func TestSaveDeploymentCARoot_WritesToCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)

	pem := []byte("-----BEGIN CERTIFICATE-----\nfakedata\n-----END CERTIFICATE-----\n")
	if err := saveDeploymentCARoot(pem); err != nil {
		t.Fatalf("saveDeploymentCARoot: %v", err)
	}
	_, caPath, _, _ := certPaths()
	got, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read back CA root: %v", err)
	}
	if string(got) != string(pem) {
		t.Errorf("written content does not match input")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run TestSaveDeploymentCARoot -v`
Expected: FAIL — `saveDeploymentCARoot undefined`

- [ ] **Step 3: Implement and wire the flag**

Add to `agent/certstore.go`:

```go
// saveDeploymentCARoot writes pemBytes to the canonical CA-root location
// (certPaths()'s caPath) — called during --install (agent/main.go) with a
// PEM an admin fetched from the orchestrator's GET /api/config/connection
// (Task 6) and handed to the installer. Not secret (a public certificate),
// so no permission-hardening beyond the directory's own 0700/icacls
// treatment (already applied by loadOrGenerateAgentKey's MkdirAll +
// hardenCertDirPlatform, called here too in case --install runs before any
// key operation has created the directory yet).
func saveDeploymentCARoot(pemBytes []byte) error {
	dir, caPath, _, _ := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	if err := hardenCertDirPlatform(dir); err != nil {
		return fmt.Errorf("harden cert dir: %w", err)
	}
	return os.WriteFile(caPath, pemBytes, 0644)
}
```

In `agent/main.go`, add the flag (near `flagSecret` at line 30):

```go
	flagCARoot := flag.String("ca-root", "", "Path to the deployment CA root PEM (required for mTLS enrollment; fetch via GET /api/config/connection)")
```

In the `if *flagInstall` block (lines 39-57), before the `svcInstall` call:

```go
		if *flagCARoot != "" {
			pemBytes, err := os.ReadFile(*flagCARoot)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: read --ca-root file: %v\n", err)
				os.Exit(1)
			}
			if err := saveDeploymentCARoot(pemBytes); err != nil {
				fmt.Fprintf(os.Stderr, "error: save CA root: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] deployment CA root installed")
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go build . && go test . -run TestSaveDeploymentCARoot -v`
Expected: build succeeds, test PASSES

- [ ] **Step 5: Commit**

```bash
git add agent/certstore.go agent/main.go agent/certstore_test.go
git commit -m "feat(agent): --ca-root install flag to place the deployment CA root before first run"
```

---

## Known deferral: CA rotation overlap support

The spec's Section 2 calls for the agent trust store to hold "current CA +
next CA" simultaneously during a rotation window. This plan does **not**
implement that — `Task 7`'s `clientCAPool`/agent-side `RootCAs` pool
(Task 10/11) each hold exactly one CA certificate. Given the CA's 10-year
lifetime and that no rotation trigger or admin-facing rotation workflow
exists yet to actually drive a rollover, building overlap support now would
be speculative and untestable against a real rotation scenario. When CA
rotation is actually scheduled, extend `clientCAPool.AddCert` (Task 7) and
the agent's `mtlsTLSConfig`/`bootstrapHTTPClient` CA-loading (Task 10/11) to
read a small directory of CA files instead of one fixed path, and add a
distribution mechanism for the new CA root — this is a natural, contained
follow-up, not a redesign, and should be its own small plan when the need
is concrete rather than spilled into this one now.

## Final Verification

After all 12 tasks:

```bash
cd orchestrator && go build ./... && go test ./...
cd ../agent && go build . && go test ./...
```

Expected: both build and all tests pass. Then a manual staging check (per the spec's Testing section): fresh agent install against a test orchestrator → confirm bootstrap succeeds on :9444 → confirm subsequent WS/heartbeat traffic runs over :9443 with a real client cert (verify via `openssl s_client -connect host:9443 -cert /dev/null` failing, and the real agent succeeding) → confirm a simulated legacy (pre-migration) agent still works unchanged against :9000.
