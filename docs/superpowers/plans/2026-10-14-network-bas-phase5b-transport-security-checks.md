# Network BAS Mastery Phase 5B: Transport Security Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (Native/inline execution, pre-selected for this plan — see Execution Handoff). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and expose two real transport-security checks — cleartext-protocol detection and TLS certificate validation — as a new, independently-triggerable check family with its own run/results persistence and HTTP API, satisfying the transport half of Network BAS Phase 5's definition of done. This is the sibling plan to Phase 5A (DNS security checks) — the two are independent subsystems sharing nothing but the tiny `networksecurity` leaf package, deliberately split so each ships as working, testable software on its own.

**Architecture:** A new leaf package `internal/networksecurity` (zero logic — just `SecurityState` and `SecurityCheckResult`), and a new package `internal/networktransport` holding both check implementations, orchestration, and depending on `internal/networksecurity` read-only. Persistence and the HTTP API mirror Phase 1's `RunDiscovery`/`network_discovery_runs` precedent exactly, the same way Phase 5A's `internal/networkdns` does.

**Tech Stack:** Go, `net`, `crypto/tls`, `crypto/x509` (all standard library — no new dependency), Postgres (`pgxpool`), chi router.

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md` (§3-§6, §8 for this plan's scope; §4.2/§5.1-5.2/the DNS tables belong to the sibling Plan 5A, not this one)

## Global Constraints

- `MaxChecksPerRun = 50`, `DefaultCheckTimeout = 5 * time.Second`, `MaxCheckTimeout = 10 * time.Second`, `maxConcurrency = 10`, `MaxRunDuration = 60 * time.Second` (a `var`, not `const`, so tests can shorten it) — identical values to Phase 5A's own constants, redeclared in this package (the two packages share no code, per the spec's "keep them separate" ruling).
- Every `Target` is explicitly caller-supplied — never auto-discovered.
- No crafted payloads: the cleartext check only ever performs a bare TCP connect and a passive, unprompted read — it never sends a request. The cert check only ever performs a TLS handshake with `InsecureSkipVerify` (to inspect the certificate without the handshake itself failing) — it never attempts an active downgrade (see Task 2's Review Focus note on why a naive TLS-version check would be dead code and must not be built).
- `Secure` means the tested requirement was positively demonstrated; `Insecure` means a specific weakness was positively demonstrated; `Unknown` means the evidence cannot support either conclusion — the one rule every branch of both checks must satisfy.
- Every new struct field gets an explicit, lowerCamelCase `json:` tag from the first draft.
- `isConnRefused`'s platform split is duplicated into this package rather than imported from `internal/networkgraph` (which keeps it unexported) — same "duplicate small logic across domain packages" convention this codebase already uses for CIDR-containment checks across `internal/networktopology`, `internal/networkpolicy`, and `internal/api/networkcontrolverification_handlers.go`.
- The TLS certificate probe's trust-root pool is an **injectable field** (`roots *x509.CertPool`, nil in production = system roots), mirroring Phase 5A's injectable DNSSEC trust-anchor seam for the identical reason: tests must verify against their own self-signed test CA, never against real internet PKI.

## Review Focus

- **A TLS handshake failure and a successful-but-invalid certificate must classify differently** (`Unknown` vs. `Insecure`) — a test that only exercises a fully successful connection would miss that a refused/failed handshake must never be read as "the cert must be bad." Owned by Task 2.
- **Go's TLS client already refuses to negotiate below TLS 1.2 by default** (since Go 1.18) — a probe that adds a separate `state.Version < tls.VersionTLS12` check would be dead code, since a successful handshake under this probe's own dialer can never produce that value; worse, making that branch reachable would require lowering the client's own negotiation floor, which is itself the deferred active-downgrade-testing capability (spec §8). This is a design constraint a runtime test cannot directly exercise (there is no reachable state to assert against) — Task 2's own doc comment on `TLSCertProbe` records the reasoning so a future "helpful" refactor doesn't reintroduce active downgrade probing by accident, and `TestTLSCertProbe_ValidCertSignedByTrustedCA_Secure` already demonstrates that a normal modern handshake classifies `Secure` with no version check at all. Owned by Task 2.
- **The cleartext probe must never send anything after connecting** — a test that inspects what bytes (if any) were written to the server side of the connection, confirming zero bytes were sent, catches a future change that "helpfully" adds a request to speed up banner detection and silently violates the no-crafted-payloads constraint. Owned by Task 1.
- **A connection that succeeds but returns an unrecognized banner must classify as `Unknown`, not `Secure` and not `Insecure`** — the spec is explicit that an ambiguous response is never positive proof of either state; a test with a banner that looks superficially like a redirect (e.g. starting with `"HTTP/1.1 301"` — still fundamentally an HTTP banner) should be checked against the recognizer's actual boundary, not assumed. Owned by Task 1.
- **`RunChecks` must isolate one check's failure from every other check in the same run**, mirroring `networkgraph.RunDiscovery`'s and Phase 5A's own `networkdns.RunChecks`'s isolation guarantee. Owned by Task 3.

---

### Task 1: `networksecurity` Leaf Package + Cleartext Detection Probe

**Files:**
- Create: `orchestrator/internal/networksecurity/types.go`
- Create: `orchestrator/internal/networktransport/cleartext.go`
- Create: `orchestrator/internal/networktransport/refused_windows.go`
- Create: `orchestrator/internal/networktransport/refused_unix.go`
- Test: `orchestrator/internal/networktransport/cleartext_test.go`

**Interfaces:**
- Consumes: `networkgraph.Target` (existing, read-only).
- Produces: `networksecurity.SecurityState` (`Secure`/`Insecure`/`Unknown`), `networksecurity.SecurityCheckResult{Target, State, Reason, Provenance}`, `networktransport.CleartextProbe` interface, `networktransport.TCPCleartextProbe` (the real implementation), `isConnRefused(err error) bool` (unexported, platform-split).

- [ ] **Step 1: Write the leaf types (no test needed — zero logic, pure data)**

```go
// orchestrator/internal/networksecurity/types.go

// Package networksecurity holds the shared result vocabulary for Network
// BAS Phase 5's transport-security checks (cleartext-protocol detection
// and TLS certificate validation, both in internal/networktransport).
// It has no logic of its own. See
// docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md.
package networksecurity

import (
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
)

// SecurityState is the shared rule for every check in this phase: Secure
// means the tested requirement was positively demonstrated; Insecure
// means a specific weakness was positively demonstrated; Unknown means
// the evidence cannot support either conclusion. No check ever promotes
// an absence of bad evidence into Secure.
type SecurityState string

const (
	Secure   SecurityState = "secure"
	Insecure SecurityState = "insecure"
	Unknown  SecurityState = "unknown"
)

type SecurityCheckResult struct {
	Target     networkgraph.Target   `json:"target"`
	State      SecurityState         `json:"state"`
	Reason     string                `json:"reason,omitempty"`
	Provenance cloudgraph.Provenance `json:"provenance"`
}
```

- [ ] **Step 2: Write the failing tests for the cleartext probe**

```go
// orchestrator/internal/networktransport/cleartext_test.go
package networktransport

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

func TestTCPCleartextProbe_RefusedConnection_Secure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing is listening now -- a real, fast, deterministic refusal

	p := TCPCleartextProbe{}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	if state != networksecurity.Secure {
		t.Fatalf("state = %q (reason: %s), want Secure -- nothing is listening, there is genuinely no cleartext path to downgrade to", state, reason)
	}
}

func TestTCPCleartextProbe_UnprompedHTTPBanner_Insecure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var bytesReceivedFromClient []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"))
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := conn.Read(buf) // never errors meaningfully if the client sends nothing; just records what arrived, if anything
		bytesReceivedFromClient = buf[:n]
	}()

	p := TCPCleartextProbe{}
	port := ln.Addr().(*net.TCPAddr).Port
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	<-done
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- an unprompted HTTP banner positively identifies a cleartext protocol", state, reason)
	}
	if len(bytesReceivedFromClient) != 0 {
		t.Fatalf("the probe sent %d bytes to the server -- it must only read a banner, never send anything", len(bytesReceivedFromClient))
	}
}

func TestTCPCleartextProbe_NoBannerWithinWindow_Unknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(2 * time.Second) // never writes anything within the probe's short window
	}()

	p := TCPCleartextProbe{}
	port := ln.Addr().(*net.TCPAddr).Port
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, 200*time.Millisecond)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown -- connecting with no banner at all proves nothing", state, reason)
	}
}

func TestTCPCleartextProbe_UnrecognizedBanner_Unknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("not a recognized protocol greeting"))
	}()

	p := TCPCleartextProbe{}
	port := ln.Addr().(*net.TCPAddr).Port
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown -- an unrecognized response is never positive proof of either state", state, reason)
	}
}

func TestTCPCleartextProbe_DialError_Unknown(t *testing.T) {
	p := TCPCleartextProbe{dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errSimulatedDialFailure
	}}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "10.0.1.5", Port: 80}, time.Second)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown", state, reason)
	}
}
```

Add `var errSimulatedDialFailure = errors.New("simulated dial failure")` and `"errors"` to the import block.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networktransport/... -v`
Expected: FAIL — package/types do not exist yet.

- [ ] **Step 4: Write the probe**

```go
// orchestrator/internal/networktransport/cleartext.go

// Package networktransport adds two transport-security checks --
// cleartext-protocol detection and TLS certificate validation -- as a
// new, independently-triggerable check family. See
// docs/superpowers/specs/2026-10-14-network-bas-phase5-dns-protocol-security-design.md.
package networktransport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

// CleartextProbe tests whether a declared cleartext endpoint (e.g.
// host:80) enforces no plaintext access at all -- see the decision
// table in the design spec's Section 5.3 for every classification rule
// this type implements.
type CleartextProbe interface {
	Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string)
}

// dialFunc matches (*net.Dialer).DialContext's signature -- a seam so
// tests can inject a synthetic dial outcome without sending real traffic.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// maxBannerReadBytes bounds how much of an unprompted banner is read --
// real protocol greetings are a few dozen bytes; this is generous
// without being unbounded.
const maxBannerReadBytes = 512

// TCPCleartextProbe is the only real implementation. It never sends
// anything after connecting -- only a bare connect and a passive,
// bounded read of whatever the service offers unprompted.
type TCPCleartextProbe struct {
	dial dialFunc // nil in production use; set only by tests
}

func (p TCPCleartextProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		if isConnRefused(err) {
			return networksecurity.Secure, "connection actively refused -- nothing is listening at this cleartext endpoint"
		}
		return networksecurity.Unknown, fmt.Sprintf("connection attempt failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, maxBannerReadBytes)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return networksecurity.Unknown, "connection succeeded but no unprompted banner was offered -- inconclusive"
	}
	if protocol, ok := identifyCleartextBanner(buf[:n]); ok {
		return networksecurity.Insecure, fmt.Sprintf("unprompted banner positively identifies %s, a cleartext protocol", protocol)
	}
	return networksecurity.Unknown, "connection succeeded with an unrecognized or ambiguous response -- not proof of cleartext access"
}

// identifyCleartextBanner recognizes the handful of unmistakable
// plaintext protocol greetings a service might offer unprompted. Any
// response not matching one of these is left Unknown, never guessed at.
func identifyCleartextBanner(b []byte) (protocol string, matched bool) {
	s := string(b)
	switch {
	case strings.HasPrefix(s, "HTTP/"):
		return "HTTP", true
	case strings.HasPrefix(s, "220 ") || strings.HasPrefix(s, "220-"):
		return "FTP/SMTP (220 greeting)", true
	case len(b) > 0 && b[0] == 0xFF: // Telnet IAC negotiation byte
		return "Telnet", true
	default:
		return "", false
	}
}
```

```go
// orchestrator/internal/networktransport/refused_windows.go
//go:build windows

package networktransport

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isConnRefused reports whether err is a connection-actively-refused
// dial error. Duplicated from internal/networkgraph's own
// probe_refused_windows.go, which keeps the same function unexported --
// this codebase's established convention for small logic shared across
// independent domain packages (see internal/networktopology's and
// internal/networkpolicy's own duplicated CIDR-containment checks).
func isConnRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
```

```go
// orchestrator/internal/networktransport/refused_unix.go
//go:build !windows

package networktransport

import (
	"errors"
	"syscall"
)

// isConnRefused reports whether err is a connection-actively-refused
// dial error. See refused_windows.go for why Windows needs a different
// constant. Duplicated from internal/networkgraph's own
// probe_refused_unix.go.
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networktransport/... -v`
Expected: PASS — 5/5.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networksecurity/types.go orchestrator/internal/networktransport/cleartext.go orchestrator/internal/networktransport/refused_windows.go orchestrator/internal/networktransport/refused_unix.go orchestrator/internal/networktransport/cleartext_test.go
git commit -m "feat(networktransport): add networksecurity leaf types and cleartext-protocol detection probe"
```

---

### Task 2: TLS Certificate Validation Probe

**Files:**
- Create: `orchestrator/internal/networktransport/cert.go`
- Test: `orchestrator/internal/networktransport/cert_test.go`

**Interfaces:**
- Consumes: `networksecurity.SecurityState`/`SecurityCheckResult` (Task 1), `crypto/tls`, `crypto/x509` (standard library).
- Produces: `networktransport.CertProbe` interface, `networktransport.TLSCertProbe{roots *x509.CertPool}` (the real implementation — `roots` is nil in production, injected by tests).

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networktransport/cert_test.go
package networktransport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

// testCA is a minimal, self-contained certificate authority for tests
// -- entirely deterministic, no dependency on real internet PKI.
type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issueLeaf signs a leaf certificate for name with the given validity
// window, using ca -- or, if selfSigned is true, signs it with its own
// freshly generated key instead (producing a cert the CA pool never
// trusts, for the untrusted-chain test case).
//
// Go's x509.Certificate.VerifyHostname (invoked internally by Verify
// when VerifyOptions.DNSName is set) checks ONLY IPAddresses -- never
// DNSNames -- whenever the name being verified parses as a literal IP.
// Every test server here listens on "127.0.0.1" and the probe dials
// that same literal IP, so a leaf meant to match must carry an
// IPAddresses SAN, not a DNSNames one, or even the happy-path case
// would fail hostname verification for the wrong reason.
func (ca *testCA) issueLeaf(t *testing.T, name string, notBefore, notAfter time.Time, selfSigned bool) tls.Certificate {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	parent, signer := ca.cert, (interface{})(ca.key)
	if selfSigned {
		parent, signer = template, leafKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
}

// startTestTLSServer starts a real local TLS listener presenting cert,
// handshaking every accepted connection and otherwise doing nothing --
// mirrors Phase 1's own real-local-listener pattern, extended to TLS.
func startTestTLSServer(t *testing.T, cert tls.Certificate) (host string, port int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func TestTLSCertProbe_ValidCertSignedByTrustedCA_Secure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "127.0.0.1", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Secure {
		t.Fatalf("state = %q (reason: %s), want Secure", state, reason)
	}
}

func TestTLSCertProbe_ExpiredCert_Insecure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "127.0.0.1", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), false)
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- an expired certificate is a positively demonstrated weakness", state, reason)
	}
}

func TestTLSCertProbe_HostnameMismatch_Insecure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "other-service.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- the cert is for other-service.test, not %s", state, reason, host)
	}
}

func TestTLSCertProbe_UntrustedChain_Insecure(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issueLeaf(t, "127.0.0.1", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), true) // self-signed, not issued by ca
	host, port := startTestTLSServer(t, cert)

	p := TLSCertProbe{roots: ca.pool} // ca's pool never trusts the self-signed leaf
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: host, Port: port}, time.Second)
	if state != networksecurity.Insecure {
		t.Fatalf("state = %q (reason: %s), want Insecure -- a self-signed leaf the trust pool never issued must not verify", state, reason)
	}
}

func TestTLSCertProbe_HandshakeFails_Unknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing is listening -- the handshake can't even start

	p := TLSCertProbe{}
	state, reason := p.Probe(context.Background(), networkgraph.Target{Host: "127.0.0.1", Port: port}, time.Second)
	if state != networksecurity.Unknown {
		t.Fatalf("state = %q (reason: %s), want Unknown -- a failed handshake must never be read as a bad certificate", state, reason)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networktransport/... -run TestTLSCertProbe -v`
Expected: FAIL — `TLSCertProbe` undefined.

- [ ] **Step 3: Write the probe**

```go
// orchestrator/internal/networktransport/cert.go
package networktransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

// CertProbe inspects a target's presented TLS certificate without
// failing the handshake on an invalid cert (InsecureSkipVerify), then
// verifies expiry, hostname match, and chain trust itself via
// x509.Certificate.Verify -- which checks all three atomically and
// produces a specific, already-descriptive error for any failure.
type CertProbe interface {
	Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string)
}

// TLSCertProbe is the only real implementation. roots is nil in
// production (system roots); tests inject their own CA pool, since
// Go's x509.Verify always rejects a cert chain the pool wasn't built
// to trust -- there is no way to make a self-signed test cert
// trusted by the real system root store.
//
// This probe never attempts to negotiate below TLS 1.2: Go's TLS
// client already refuses to do so by default (since Go 1.18), so a
// successful handshake using this probe's own dialer is already
// implicit proof the negotiated version meets that floor. Lowering
// the client's own MinVersion to actively test what a server would
// negotiate down to is the deferred downgrade-testing capability
// (design spec Section 8) and must not be added here.
type TLSCertProbe struct {
	roots *x509.CertPool
}

func (p TLSCertProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return networksecurity.Unknown, fmt.Sprintf("TLS handshake failed: %v", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return networksecurity.Unknown, "dialed connection was not a TLS connection"
	}
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return networksecurity.Unknown, "handshake succeeded but no peer certificate was presented"
	}

	if _, err := peerCerts[0].Verify(x509.VerifyOptions{DNSName: target.Host, Roots: p.roots}); err != nil {
		return networksecurity.Insecure, fmt.Sprintf("certificate is invalid: %v", err)
	}
	return networksecurity.Secure, ""
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networktransport/... -v`
Expected: PASS — 10/10 (5 from Task 1 + 5 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networktransport/cert.go orchestrator/internal/networktransport/cert_test.go
git commit -m "feat(networktransport): add TLS certificate validation probe"
```

---

### Task 3: Orchestration — `RunChecks`

**Files:**
- Create: `orchestrator/internal/networktransport/run.go`
- Test: `orchestrator/internal/networktransport/run_test.go`

**Interfaces:**
- Consumes: `CleartextProbe`/`TCPCleartextProbe` (Task 1), `CertProbe`/`TLSCertProbe` (Task 2), `networksecurity.SecurityCheckResult`, `networkgraph.VantagePoint`/`Target`, `cloudgraph.Provenance`.
- Produces: `CheckType` (`CheckCleartext`, `CheckCert`), `TransportCheckRequest{CheckType, Target}`, `RunStatus` (`RunCompleted`, `RunPartial`), `MaxChecksPerRun`, `DefaultCheckTimeout`, `MaxCheckTimeout`, `MaxRunDuration` (var), `func RunChecks(ctx context.Context, cleartextProbe CleartextProbe, certProbe CertProbe, vp networkgraph.VantagePoint, checks []TransportCheckRequest) (*RunResult, error)`, `RunResult{Status RunStatus, Results []networksecurity.SecurityCheckResult}`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/networktransport/run_test.go
package networktransport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

type stubCleartextProbe struct {
	state  networksecurity.SecurityState
	reason string
}

func (s stubCleartextProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	return s.state, s.reason
}

type stubCertProbe struct {
	state  networksecurity.SecurityState
	reason string
}

func (s stubCertProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	return s.state, s.reason
}

func TestRunChecks_BothCheckTypes_ProduceResults(t *testing.T) {
	checks := []TransportCheckRequest{
		{CheckType: CheckCleartext, Target: networkgraph.Target{Host: "127.0.0.1", Port: 80}},
		{CheckType: CheckCert, Target: networkgraph.Target{Host: "127.0.0.1", Port: 443}},
	}
	result, err := RunChecks(context.Background(),
		stubCleartextProbe{state: networksecurity.Secure},
		stubCertProbe{state: networksecurity.Insecure, reason: "expired"},
		networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(result.Results))
	}
	var sawCleartext, sawCert bool
	for _, r := range result.Results {
		if r.Target.Port == 80 {
			sawCleartext = true
			if r.State != networksecurity.Secure {
				t.Fatalf("cleartext result State = %q, want Secure", r.State)
			}
		}
		if r.Target.Port == 443 {
			sawCert = true
			if r.State != networksecurity.Insecure || r.Reason != "expired" {
				t.Fatalf("cert result = %+v, want Insecure/expired", r)
			}
		}
	}
	if !sawCleartext || !sawCert {
		t.Fatalf("missing a result: cleartext=%v cert=%v", sawCleartext, sawCert)
	}
}

func TestRunChecks_EmptyChecksRejected(t *testing.T) {
	_, err := RunChecks(context.Background(), stubCleartextProbe{}, stubCertProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, nil)
	if err == nil {
		t.Fatal("want an error for zero checks")
	}
}

func TestRunChecks_TooManyChecksRejected(t *testing.T) {
	checks := make([]TransportCheckRequest, MaxChecksPerRun+1)
	for i := range checks {
		checks[i] = TransportCheckRequest{CheckType: CheckCleartext, Target: networkgraph.Target{Host: "127.0.0.1", Port: 80}}
	}
	_, err := RunChecks(context.Background(), stubCleartextProbe{}, stubCertProbe{}, networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err == nil {
		t.Fatal("want an error for exceeding MaxChecksPerRun")
	}
}

func TestRunChecks_OneFailingCheckDoesNotBlockOthers(t *testing.T) {
	checks := []TransportCheckRequest{
		{CheckType: CheckCleartext, Target: networkgraph.Target{Host: "10.0.1.6", Port: 80}},
		{CheckType: CheckCert, Target: networkgraph.Target{Host: "10.0.1.7", Port: 443}},
	}
	result, err := RunChecks(context.Background(),
		failingCleartextProbe{},
		stubCertProbe{state: networksecurity.Secure},
		networkgraph.VantagePoint{ID: "vp1", NetworkPosition: "lab"}, checks)
	if err != nil {
		t.Fatalf("RunChecks: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2 -- one check's failure must not drop the other's result", len(result.Results))
	}
}

type failingCleartextProbe struct{}

func (failingCleartextProbe) Probe(ctx context.Context, target networkgraph.Target, timeout time.Duration) (networksecurity.SecurityState, string) {
	return networksecurity.Unknown, errSimulatedProbeFailure.Error()
}

var errSimulatedProbeFailure = errors.New("simulated probe failure")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/networktransport/... -run TestRunChecks -v`
Expected: FAIL — `RunChecks`, `TransportCheckRequest`, `CheckCleartext` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/networktransport/run.go
package networktransport

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
)

const (
	MaxChecksPerRun     = 50
	DefaultCheckTimeout = 5 * time.Second
	MaxCheckTimeout     = 10 * time.Second
	maxConcurrency      = 10
)

// MaxRunDuration is a var, not a const, so tests can shorten it.
var MaxRunDuration = 60 * time.Second

type CheckType string

const (
	CheckCleartext CheckType = "cleartext"
	CheckCert      CheckType = "cert"
)

type TransportCheckRequest struct {
	CheckType CheckType           `json:"checkType"`
	Target    networkgraph.Target `json:"target"`
}

type RunStatus string

const (
	RunCompleted RunStatus = "completed"
	RunPartial   RunStatus = "partial"
)

type RunResult struct {
	Status  RunStatus
	Results []networksecurity.SecurityCheckResult
}

// RunChecks executes every check with bounded concurrency, isolating
// one check's failure from every other -- mirrors
// networkgraph.RunDiscovery's and networkdns.RunChecks's own isolation
// guarantee.
func RunChecks(ctx context.Context, cleartextProbe CleartextProbe, certProbe CertProbe, vp networkgraph.VantagePoint, checks []TransportCheckRequest) (*RunResult, error) {
	if len(checks) == 0 {
		return nil, fmt.Errorf("networktransport: RunChecks requires at least one check")
	}
	if len(checks) > MaxChecksPerRun {
		return nil, fmt.Errorf("networktransport: too many checks -- got %d, max %d", len(checks), MaxChecksPerRun)
	}

	runCtx, cancel := context.WithTimeout(ctx, MaxRunDuration)
	defer cancel()

	results := make([]networksecurity.SecurityCheckResult, len(checks))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func(i int, check TransportCheckRequest) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-runCtx.Done():
				results[i] = deadlineExceededResult(check)
				return
			}
			results[i] = runOneCheck(runCtx, cleartextProbe, certProbe, check)
		}(i, check)
	}
	wg.Wait()

	status := RunCompleted
	if runCtx.Err() != nil {
		status = RunPartial
	}
	return &RunResult{Status: status, Results: results}, nil
}

func runOneCheck(ctx context.Context, cleartextProbe CleartextProbe, certProbe CertProbe, check TransportCheckRequest) networksecurity.SecurityCheckResult {
	var state networksecurity.SecurityState
	var reason string
	switch check.CheckType {
	case CheckCert:
		state, reason = certProbe.Probe(ctx, check.Target, DefaultCheckTimeout)
	default: // CheckCleartext
		state, reason = cleartextProbe.Probe(ctx, check.Target, DefaultCheckTimeout)
	}
	return networksecurity.SecurityCheckResult{
		Target:     check.Target,
		State:      state,
		Reason:     reason,
		Provenance: cloudgraph.Provenance{ObservedAt: time.Now()},
	}
}

func deadlineExceededResult(check TransportCheckRequest) networksecurity.SecurityCheckResult {
	return networksecurity.SecurityCheckResult{
		Target: check.Target, State: networksecurity.Unknown, Reason: "run deadline exceeded before this check ran",
		Provenance: cloudgraph.Provenance{ObservedAt: time.Now()},
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/networktransport/... -v`
Expected: PASS — 14/14 (10 from Tasks 1-2 + 4 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/networktransport/run.go orchestrator/internal/networktransport/run_test.go
git commit -m "feat(networktransport): add bounded-concurrency check orchestration"
```

---

### Task 4: Persistence

**Files:**
- Create: `orchestrator/internal/db/networktransportcheck_store.go`
- Test: `orchestrator/internal/db/networktransportcheck_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go` (immediately after the `EnsureDNSSecurityCheckSchema` call Phase 5A's Task 5 added — re-grep the exact current line number before editing, since Phase 5A's own execution may have shifted it)
- Modify: `orchestrator/cmd/server/main.go` (same, after `EnsureDNSSecurityCheckSchema`)

**Interfaces:**
- Consumes: `networktransport.TransportCheckRequest`/`CheckType`/`RunStatus` (Task 3), `networksecurity.SecurityCheckResult` (Task 1), the existing `nullableString` helper (`internal/db/networkdiscovery_store.go:78`, same package, reused).
- Produces: `func EnsureTransportSecurityCheckSchema(ctx, pool) error`, `type TransportSecurityCheckRun struct{ID, VantagePointID, RequestedBy, CheckCount, Status, StartedAt, CompletedAt}`, `func InsertTransportSecurityCheckRun(ctx, pool, run *TransportSecurityCheckRun) error`, `func InsertTransportSecurityCheckResults(ctx, pool, runID string, results []networksecurity.SecurityCheckResult) error`, `func GetTransportSecurityCheckRun(ctx, pool, id) (*TransportSecurityCheckRun, error)`, `func ListTransportSecurityCheckRuns(ctx, pool, limit) ([]*TransportSecurityCheckRun, error)`, `func ListTransportSecurityCheckResultsByRun(ctx, pool, runID) ([]networksecurity.SecurityCheckResult, error)`, `func UpdateTransportSecurityCheckRunStatus(ctx, pool, id, status) error`.

Note: `networksecurity.SecurityCheckResult` doesn't carry its own `CheckType` (unlike Phase 5A's tagged-union `DNSCheckResult`) — this store's results table carries `check_type` as its own column, populated from the `TransportCheckRequest` the result was computed for, not from the result struct itself. `InsertTransportSecurityCheckResults` therefore takes parallel `checkTypes []networktransport.CheckType` alongside `results`, one per result in the same order `RunChecks` returned them.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/db/networktransportcheck_store_test.go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
	"github.com/audspect/bas/internal/networktransport"
)

func TestInsertTransportSecurityCheckRun_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		run := &db.TransportSecurityCheckRun{ID: "transrun-roundtrip-1", VantagePointID: "vp1", RequestedBy: "alice", CheckCount: 2, Status: "completed"}
		if err := db.InsertTransportSecurityCheckRun(context.Background(), pool, run); err != nil {
			t.Fatalf("insert run: %v", err)
		}

		results := []networksecurity.SecurityCheckResult{
			{Target: networkgraph.Target{Host: "10.0.1.5", Port: 80}, State: networksecurity.Secure, Provenance: cloudgraph.Provenance{}},
			{Target: networkgraph.Target{Host: "10.0.1.5", Port: 443}, State: networksecurity.Insecure, Reason: "expired", Provenance: cloudgraph.Provenance{}},
		}
		checkTypes := []networktransport.CheckType{networktransport.CheckCleartext, networktransport.CheckCert}
		if err := db.InsertTransportSecurityCheckResults(context.Background(), pool, run.ID, checkTypes, results); err != nil {
			t.Fatalf("insert results: %v", err)
		}

		gotRun, err := db.GetTransportSecurityCheckRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if gotRun.RequestedBy != "alice" || gotRun.CheckCount != 2 {
			t.Fatalf("got %+v, want RequestedBy=alice CheckCount=2", gotRun)
		}

		gotResults, err := db.ListTransportSecurityCheckResultsByRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("list results: %v", err)
		}
		if len(gotResults) != 2 {
			t.Fatalf("got %d results, want 2", len(gotResults))
		}
		var sawCleartext, sawCert bool
		for _, r := range gotResults {
			if r.Target.Port == 80 {
				sawCleartext = true
				if r.State != networksecurity.Secure {
					t.Fatalf("cleartext result round-trip mismatch: %+v", r)
				}
			}
			if r.Target.Port == 443 {
				sawCert = true
				if r.State != networksecurity.Insecure || r.Reason != "expired" {
					t.Fatalf("cert result round-trip mismatch: %+v", r)
				}
			}
		}
		if !sawCleartext || !sawCert {
			t.Fatalf("missing a result type in round-trip: cleartext=%v cert=%v", sawCleartext, sawCert)
		}

		list, err := db.ListTransportSecurityCheckRuns(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == run.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted run should appear in the list")
		}
	})
}

func TestGetTransportSecurityCheckRun_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetTransportSecurityCheckRun(context.Background(), pool, "nonexistent-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/db/...`
Expected: FAIL — `db.TransportSecurityCheckRun`, `db.InsertTransportSecurityCheckRun`, etc. undefined.

- [ ] **Step 3: Implement the store**

```go
// orchestrator/internal/db/networktransportcheck_store.go
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networksecurity"
	"github.com/audspect/bas/internal/networktransport"
)

func EnsureTransportSecurityCheckSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS transport_security_check_runs (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			vantage_point_id text        NOT NULL,
			requested_by     text,
			check_count      int         NOT NULL,
			status           text        NOT NULL,
			started_at       timestamptz NOT NULL DEFAULT NOW(),
			completed_at     timestamptz
		)`)
	if err != nil {
		return fmt.Errorf("transport_security_check_runs: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS transport_security_check_results (
			id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			run_id       text        NOT NULL REFERENCES transport_security_check_runs(id),
			check_type   text        NOT NULL,
			target_host  text        NOT NULL,
			target_port  int         NOT NULL,
			state        text        NOT NULL,
			reason       text,
			observed_at  timestamptz NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("transport_security_check_results: ensure schema: %w", err)
	}
	_, err = pool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_transport_security_check_results_run ON transport_security_check_results (run_id)`)
	if err != nil {
		return fmt.Errorf("transport_security_check_results: ensure index: %w", err)
	}
	return nil
}

type TransportSecurityCheckRun struct {
	ID             string     `json:"id"`
	VantagePointID string     `json:"vantagePointId"`
	RequestedBy    string     `json:"requestedBy,omitempty"`
	CheckCount     int        `json:"checkCount"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"startedAt"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
}

func InsertTransportSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, run *TransportSecurityCheckRun) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO transport_security_check_runs (id, vantage_point_id, requested_by, check_count, status)
		 VALUES ($1,$2,$3,$4,$5)`,
		run.ID, run.VantagePointID, nullableString(run.RequestedBy), run.CheckCount, run.Status)
	if err != nil {
		return fmt.Errorf("transport_security_check_runs: insert %s: %w", run.ID, err)
	}
	return nil
}

func UpdateTransportSecurityCheckRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status string) error {
	_, err := pool.Exec(ctx, `UPDATE transport_security_check_runs SET status = $1, completed_at = NOW() WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("transport_security_check_runs: update status for %s: %w", id, err)
	}
	return nil
}

func scanTransportSecurityCheckRun(row pgx.Row) (*TransportSecurityCheckRun, error) {
	run := &TransportSecurityCheckRun{}
	var requestedBy *string
	if err := row.Scan(&run.ID, &run.VantagePointID, &requestedBy, &run.CheckCount, &run.Status, &run.StartedAt, &run.CompletedAt); err != nil {
		return nil, err
	}
	if requestedBy != nil {
		run.RequestedBy = *requestedBy
	}
	return run, nil
}

func GetTransportSecurityCheckRun(ctx context.Context, pool *pgxpool.Pool, id string) (*TransportSecurityCheckRun, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM transport_security_check_runs WHERE id = $1`, id)
	run, err := scanTransportSecurityCheckRun(row)
	if err != nil {
		return nil, fmt.Errorf("transport_security_check_runs: get %s: %w", id, err)
	}
	return run, nil
}

func ListTransportSecurityCheckRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*TransportSecurityCheckRun, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, vantage_point_id, requested_by, check_count, status, started_at, completed_at
		 FROM transport_security_check_runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("transport_security_check_runs: list: %w", err)
	}
	defer rows.Close()
	var out []*TransportSecurityCheckRun
	for rows.Next() {
		run, err := scanTransportSecurityCheckRun(rows)
		if err != nil {
			return nil, fmt.Errorf("transport_security_check_runs: list scan: %w", err)
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("transport_security_check_runs: list rows: %w", err)
	}
	return out, nil
}

// InsertTransportSecurityCheckResults writes every result for one run in
// a single transaction. checkTypes and results are parallel slices, one
// entry per check, in the same order RunChecks returned them.
func InsertTransportSecurityCheckResults(ctx context.Context, pool *pgxpool.Pool, runID string, checkTypes []networktransport.CheckType, results []networksecurity.SecurityCheckResult) error {
	if len(checkTypes) != len(results) {
		return fmt.Errorf("transport_security_check_results: checkTypes (%d) and results (%d) must be the same length", len(checkTypes), len(results))
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("transport_security_check_results: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for i, r := range results {
		observedAt := r.Provenance.ObservedAt
		if observedAt.IsZero() {
			observedAt = time.Now()
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO transport_security_check_results
			 (run_id, check_type, target_host, target_port, state, reason, observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			runID, string(checkTypes[i]), r.Target.Host, r.Target.Port, string(r.State), nullableString(r.Reason), observedAt)
		if err != nil {
			return fmt.Errorf("transport_security_check_results: insert for run %s: %w", runID, err)
		}
	}
	return tx.Commit(ctx)
}

func ListTransportSecurityCheckResultsByRun(ctx context.Context, pool *pgxpool.Pool, runID string) ([]networksecurity.SecurityCheckResult, error) {
	rows, err := pool.Query(ctx,
		`SELECT target_host, target_port, state, reason, observed_at
		 FROM transport_security_check_results WHERE run_id = $1 ORDER BY observed_at ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("transport_security_check_results: list for run %s: %w", runID, err)
	}
	defer rows.Close()
	var out []networksecurity.SecurityCheckResult
	for rows.Next() {
		var r networksecurity.SecurityCheckResult
		var reason *string
		var state string
		if err := rows.Scan(&r.Target.Host, &r.Target.Port, &state, &reason, &r.Provenance.ObservedAt); err != nil {
			return nil, fmt.Errorf("transport_security_check_results: scan for run %s: %w", runID, err)
		}
		r.State = networksecurity.SecurityState(state)
		if reason != nil {
			r.Reason = *reason
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("transport_security_check_results: rows for run %s: %w", runID, err)
	}
	return out, nil
}
```

Note: `ListTransportSecurityCheckResultsByRun`'s returned `SecurityCheckResult` does not carry `check_type` back (the type itself has no such field) — a caller needing it per-result reads the API response wrapper's own parallel data instead (see Task 5).

- [ ] **Step 4: Wire schema creation into the test pool and server startup**

Re-grep `orchestrator/internal/testutil/testdb.go` and `orchestrator/cmd/server/main.go` for the current exact text of the `EnsureDNSSecurityCheckSchema` call (added by Phase 5A) and add, immediately after each:

In `testdb.go`:
```go
	if err := db.EnsureTransportSecurityCheckSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureTransportSecurityCheckSchema: %w", err)
	}
```

In `main.go`:
```go
	if err := db.EnsureTransportSecurityCheckSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] transport security check schema: %v", err)
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Check memory headroom first: `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` (PowerShell); if free memory is below ~1GB, check for stray Docker testcontainers / orphaned `*.test.exe` processes before proceeding.

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -run 'TestInsertTransportSecurityCheckRun|TestGetTransportSecurityCheckRun' -v`
Expected: PASS — 2/2.

- [ ] **Step 6: Run the full `internal/db` suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/db/... -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/networktransportcheck_store.go orchestrator/internal/db/networktransportcheck_store_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(networktransport): add schema and store layer for transport security check runs"
```

---

### Task 5: HTTP API

**Files:**
- Create: `orchestrator/internal/api/networktransportcheck_handlers.go`
- Test: `orchestrator/internal/api/networktransportcheck_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (re-grep current line numbers for the DNS security check routes Phase 5A added before editing)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (same)

**Interfaces:**
- Consumes: `networktransport.RunChecks`/`TransportCheckRequest`/`TCPCleartextProbe`/`TLSCertProbe`/`MaxChecksPerRun` (Tasks 1-3), `db.InsertTransportSecurityCheckRun`/`InsertTransportSecurityCheckResults`/`GetTransportSecurityCheckRun`/`ListTransportSecurityCheckRuns`/`ListTransportSecurityCheckResultsByRun`/`UpdateTransportSecurityCheckRunStatus` (Task 4), existing `h.networkVantagePoint`, `jsonError`/`respond`/`respondStatus`/`newID`/`auth.ClaimsFrom`/`h.auditLog`, `auth.CanRunScenario` (existing permission, reused — same risk class as Phase 1's and Phase 5A's own trigger endpoints).
- Produces: `func (h *Handler) TriggerTransportSecurityCheckRun(w, r)`, `func (h *Handler) ListTransportSecurityCheckRuns(w, r)`, `func (h *Handler) GetTransportSecurityCheckRun(w, r)`, routes `POST /api/transport-security-checks`, `GET /api/transport-security-checks`, `GET /api/transport-security-checks/{id}`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/networktransportcheck_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networksecurity"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// startRefusingPort returns host/port of an address nothing is
// listening on -- real, fast, deterministic (Secure for cleartext,
// Unknown for cert), mirroring Phase 1's own closedPort pattern.
func startRefusingPort(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	return addr.IP.String(), addr.Port
}

func transportCheckBody(host string, port int) map[string]any {
	return map[string]any{
		"checks": []map[string]any{
			{"checkType": "cleartext", "target": map[string]any{"host": host, "port": port}},
		},
	}
}

func TestTriggerTransportSecurityCheckRun_ValidChecksPersist(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transport-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.RunID == "" {
			t.Fatal("want non-empty runId")
		}
	})
}

func TestTriggerTransportSecurityCheckRun_EmptyChecksRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		body := map[string]any{"checks": []map[string]any{}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "transport-op-empty", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerTransportSecurityCheckRun_UnconfiguredVantagePointReturns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret) // no vantage point configured
		b, _ := json.Marshal(transportCheckBody("10.0.1.5", 80))
		userID := seedUser(t, pool, "transport-op-novp", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetTransportSecurityCheckRun_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transport-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		triggerReq := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		triggerRec := callAuthed(h.TriggerTransportSecurityCheckRun, triggerReq)
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}
		var created struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode trigger: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/transport-security-checks", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListTransportSecurityCheckRuns, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/transport-security-checks/"+created.RunID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.RunID)
		getRec := callAuthed(h.GetTransportSecurityCheckRun, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
		var getResp struct {
			Results []networksecurity.SecurityCheckResult `json:"results"`
		}
		if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if len(getResp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(getResp.Results))
		}
	})
}
```

All four tests exercise the cleartext check (`transportCheckBody` builds a `"cleartext"` request) rather than the cert check — a closed TCP port gives a trivially fast, deterministic refusal for the handler-level round-trip tests, and the cert probe's own classification logic is already fully covered at the package level by Task 2's five tests. The handler only needs to prove request→`RunChecks`→persistence→response wiring, not re-prove either probe's internals.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.TriggerTransportSecurityCheckRun` etc. undefined.

- [ ] **Step 3: Implement the handlers**

```go
// orchestrator/internal/api/networktransportcheck_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networksecurity"
	"github.com/audspect/bas/internal/networktransport"
)

const maxTransportSecurityCheckRequestBytes = 1 << 20

// TriggerTransportSecurityCheckRun -- POST /api/transport-security-checks.
func (h *Handler) TriggerTransportSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	if !h.networkVantagePoint.Configured() {
		jsonError(w, "network discovery vantage point not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Checks []networktransport.TransportCheckRequest `json:"checks"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTransportSecurityCheckRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Checks) == 0 {
		jsonError(w, "at least one check is required", http.StatusBadRequest)
		return
	}
	if len(req.Checks) > networktransport.MaxChecksPerRun {
		jsonError(w, fmt.Sprintf("too many checks — got %d, max %d", len(req.Checks), networktransport.MaxChecksPerRun), http.StatusBadRequest)
		return
	}
	for i, c := range req.Checks {
		if c.Target.Host == "" || c.Target.Port < 1 || c.Target.Port > 65535 {
			jsonError(w, fmt.Sprintf("checks[%d]: a valid target host/port is required", i), http.StatusBadRequest)
			return
		}
	}

	var requestedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		requestedBy = c.UserID
	}

	result, err := networktransport.RunChecks(r.Context(), networktransport.TCPCleartextProbe{}, networktransport.TLSCertProbe{}, h.networkVantagePoint, req.Checks)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	run := &db.TransportSecurityCheckRun{
		ID:             newID(),
		VantagePointID: h.networkVantagePoint.ID,
		RequestedBy:    requestedBy,
		CheckCount:     len(req.Checks),
		Status:         string(result.Status),
	}
	if err := db.InsertTransportSecurityCheckRun(r.Context(), h.db, run); err != nil {
		h.auditLog(r, "networktransport.run", "", map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	checkTypes := make([]networktransport.CheckType, len(req.Checks))
	for i, c := range req.Checks {
		checkTypes[i] = c.CheckType
	}
	if err := db.InsertTransportSecurityCheckResults(r.Context(), h.db, run.ID, checkTypes, result.Results); err != nil {
		_ = db.UpdateTransportSecurityCheckRunStatus(r.Context(), h.db, run.ID, "failed")
		h.auditLog(r, "networktransport.run", run.ID, map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networktransport.run", run.ID, map[string]any{"checkCount": len(req.Checks), "status": string(result.Status)}, "ok")
	respondStatus(w, map[string]any{"runId": run.ID, "status": result.Status}, http.StatusCreated)
}

// ListTransportSecurityCheckRuns -- GET /api/transport-security-checks.
func (h *Handler) ListTransportSecurityCheckRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListTransportSecurityCheckRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*db.TransportSecurityCheckRun{}
	}
	respond(w, runs)
}

// GetTransportSecurityCheckRun -- GET /api/transport-security-checks/{id}.
func (h *Handler) GetTransportSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetTransportSecurityCheckRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "transport security check run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	results, err := db.ListTransportSecurityCheckResultsByRun(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []networksecurity.SecurityCheckResult{}
	}
	respond(w, map[string]any{"run": run, "results": results})
}
```

- [ ] **Step 4: Wire routes and RBAC matrix rows**

Re-grep `orchestrator/internal/api/routes.go` and `orchestrator/internal/api/rbac_matrix_test.go` for the current exact text of the `dns-security-checks` GET/POST lines (added by Phase 5A) before editing. Add, after them in `routes.go`:
```go
		r.Get("/api/transport-security-checks", h.ListTransportSecurityCheckRuns)
		r.Get("/api/transport-security-checks/{id}", h.GetTransportSecurityCheckRun)
```
and:
```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/transport-security-checks", h.TriggerTransportSecurityCheckRun)
```

In `rbac_matrix_test.go`, add the matching GET rows (`tierAny`) and POST row (`tierPermission, auth.CanRunScenario`) at the corresponding anchors.

- [ ] **Step 5: Run tests to verify they pass**

Check memory headroom first (same check as Task 4).

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestTriggerTransportSecurityCheckRun|TestListAndGetTransportSecurityCheckRun|TestRBACMatrix_NoDrift' -v`
Expected: PASS — 5/5.

- [ ] **Step 6: Run the full network+RBAC regression set**

Run: `cd orchestrator && go vet ./... && go test ./internal/api/... -run 'Network|Transport|RBACMatrix' -v`
Expected: PASS — all tests, no regressions.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/networktransportcheck_handlers.go orchestrator/internal/api/networktransportcheck_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networktransport): add transport security check HTTP API"
```

---

## Execution Handoff

This plan uses **Native/inline execution** (pre-selected — standing convention for this session, same as every prior Network BAS Mastery phase, including the sibling Phase 5A plan): implement every task directly in this session, then one fresh reviewer on the most capable model checks the whole branch at the end. Run after Phase 5A (or independently — the two share no code beyond the read-only `networksecurity` leaf package introduced in this plan's own Task 1, so order between the two plans doesn't matter beyond not editing the same `routes.go`/`rbac_matrix_test.go` anchors concurrently).

**REQUIRED SUB-SKILL:** Use superpowers:executing-plans.
