package runner_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/lab"
)

// End-to-end test of the standalone lab binary in TLS mode (apibas-lab -tls). The binary is built and started as a separate
// process. The test then drives the real handshake and the application-layer behaviour over TCP.
//
// Expectations, written before the run:
//   - the server certificate verifies against the CA the binary writes (-tls-ca). A client with an empty root pool fails
//     the handshake (a transport failure, not a control result).
//   - a client with the certificate the binary issues for cust-b (-tls-client-cert) reads cust-b's order in both builds (200).
//   - a self-signed certificate with the subject cust-b reads the order in the vulnerable build (200, trusts the subject)
//     and is refused by the fixed build at the application layer (401, after a completed handshake).
//   - no client certificate: refused at the application layer (401) in both builds. The handshake completes.
//   - TLS 1.1 offered by the client is refused by the server at the handshake.

// buildLabBinary compiles cmd/apibas-lab into the test's temporary directory.
func buildLabBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "apibas-lab.exe")
	cmd := exec.Command("go", "build", "-o", bin, "../../../cmd/apibas-lab")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build apibas-lab: %v\n%s", err, out)
	}
	return bin
}

// freeAddr returns a loopback address with a free port.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// startLab runs the binary in TLS mode and waits until it accepts connections. The process is stopped at cleanup.
func startLab(t *testing.T, bin, mode, addr, dir string) (caPath, certPath, keyPath string) {
	t.Helper()
	caPath = filepath.Join(dir, "ca.pem")
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	cmd := exec.Command(bin,
		"-addr", addr, "-mode", mode, "-tls",
		"-tls-ca", caPath, "-tls-client-cert", certPath, "-tls-client-key", keyPath)
	cmd.Env = append(os.Environ(),
		"APIBAS_CUSTOMER_A_TOKEN=e2e-token-a-"+randomToken(t),
		"APIBAS_CUSTOMER_B_TOKEN=e2e-token-b-"+randomToken(t),
		"APIBAS_LAB_ADMIN_TOKEN=e2e-admin-"+randomToken(t),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start apibas-lab: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("apibas-lab did not listen on %s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return caPath, certPath, keyPath
}

// loadRootPool reads the CA PEM the binary wrote.
func loadRootPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("CA PEM has no certificate")
	}
	return pool
}

// loadClientCert reads the certificate and key the binary issued for cust-b.
func loadClientCert(t *testing.T, certPath, keyPath string) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load client certificate: %v", err)
	}
	return cert
}

// getOrder requests the mTLS order route with the given roots and client certificates. A transport error is returned as err.
func getOrder(addr string, roots *x509.CertPool, certs []tls.Certificate) (int, string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			Certificates: certs,
			MinVersion:   tls.VersionTLS12,
		}},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s/api/mtls/orders/ORD-2001", addr))
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func TestTLS_StandaloneLabEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("standalone TLS lab run skipped in -short mode")
	}
	bin := buildLabBinary(t)
	for _, mode := range []string{"vulnerable", "fixed"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			addr := freeAddr(t)
			caPath, certPath, keyPath := startLab(t, bin, mode, addr, dir)
			roots := loadRootPool(t, caPath)
			trusted := loadClientCert(t, certPath, keyPath)

			// Server certificate verifies against the lab CA; the trusted cust-b certificate reads cust-b's order.
			status, body, err := getOrder(addr, roots, []tls.Certificate{trusted})
			if err != nil {
				t.Fatalf("trusted client: handshake or request failed: %v", err)
			}
			if status != http.StatusOK || !strings.Contains(body, "ORD-2001") {
				t.Errorf("trusted cust-b: status %d, want 200 with ORD-2001", status)
			}

			// A server certificate the client does not trust: the handshake fails at the transport, never a result.
			if _, _, err := getOrder(addr, x509.NewCertPool(), []tls.Certificate{trusted}); err == nil {
				t.Error("client with an empty root pool completed the handshake, want a transport failure")
			}

			// No client certificate: the handshake completes and the application refuses with 401.
			status, _, err = getOrder(addr, roots, nil)
			if err != nil {
				t.Fatalf("no client certificate: handshake failed: %v (want the application to refuse)", err)
			}
			if status != http.StatusUnauthorized {
				t.Errorf("no client certificate: status %d, want 401 from the application", status)
			}

			// A self-signed certificate with the subject cust-b: trusted by the vulnerable build, refused by the fixed one.
			forged, err := lab.SelfSignedClientCert("cust-b")
			if err != nil {
				t.Fatal(err)
			}
			status, _, err = getOrder(addr, roots, []tls.Certificate{forged})
			if err != nil {
				t.Fatalf("forged certificate: handshake failed: %v (the handshake must complete in both builds)", err)
			}
			if mode == "vulnerable" && status != http.StatusOK {
				t.Errorf("forged certificate, vulnerable: status %d, want 200 (subject trusted)", status)
			}
			if mode == "fixed" && status != http.StatusUnauthorized {
				t.Errorf("forged certificate, fixed: status %d, want 401 from the application", status)
			}

			// The server refuses TLS 1.1 at the handshake.
			if conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, MaxVersion: tls.VersionTLS11}); err == nil {
				conn.Close()
				t.Error("TLS 1.1 handshake completed, want the server to refuse it")
			}
		})
	}
}

// Ensure the PEM the binary writes for the CA decodes to a certificate, independent of the pool helper.
func TestTLS_StandaloneLabCAPEMDecodes(t *testing.T) {
	if testing.Short() {
		t.Skip("standalone TLS lab run skipped in -short mode")
	}
	bin := buildLabBinary(t)
	dir := t.TempDir()
	caPath, _, _ := startLab(t, bin, "fixed", freeAddr(t), dir)
	data, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("CA file is not a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("CA certificate does not parse: %v", err)
	}
}
