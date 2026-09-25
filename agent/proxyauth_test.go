package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// fakeConnectProxy is a minimal CONNECT-speaking proxy for tests: it accepts
// one connection, reads a CONNECT request, and replies according to script --
// each entry is either "407" (with the given WWW-Authenticate-style header
// value) or "200" (tunnel established, then the proxy just holds the
// connection open for the test to close).
type fakeConnectProxy struct {
	ln net.Listener
}

func newFakeConnectProxy(t *testing.T, handle func(net.Conn)) *fakeConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fakeConnectProxy{ln: ln}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handle(conn)
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *fakeConnectProxy) addr() string { return p.ln.Addr().String() }

func TestDialThroughProxy_NoAuthRequired_Succeeds(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		time.Sleep(50 * time.Millisecond) // hold open long enough for the client to observe success
	})

	conn, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "", "")
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	conn.Close()
}

func TestDialThroughProxy_BasicChallenge_RetriesAndSucceeds(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		// First CONNECT: unauthenticated -- challenge with Basic.
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))

		// Second CONNECT on the same connection: must carry Basic creds.
		req2, err := http.ReadRequest(br)
		if err != nil || req2.Method != http.MethodConnect {
			return
		}
		auth := req2.Header.Get("Proxy-Authorization")
		if auth != "Basic YnJhbmNoLXVzZXI6czNjcjN0" { // base64("branch-user:s3cr3t")
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		time.Sleep(50 * time.Millisecond)
	})

	conn, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "branch-user", "s3cr3t")
	if err != nil {
		t.Fatalf("dialThroughProxy: %v", err)
	}
	conn.Close()
}

func TestDialThroughProxy_BasicChallenge_WrongCredentialReturnsConfirmedRejection(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, _ := http.ReadRequest(br)
		if req == nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
		req2, _ := http.ReadRequest(br)
		if req2 == nil {
			return
		}
		// Always reject, regardless of what was sent -- simulates a genuinely wrong credential.
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
	})

	_, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "branch-user", "wrong-password")
	if err == nil {
		t.Fatal("dialThroughProxy: want error for rejected credential, got nil")
	}
	if !errors.Is(err, ErrProxyCredentialsRejected) {
		t.Errorf("err = %v, want errors.Is(err, ErrProxyCredentialsRejected)", err)
	}
}

func TestDialThroughProxy_BasicOffered_NoCredentialsConfigured_FailsWithDiagnostic(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, _ := http.ReadRequest(br)
		if req == nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
	})

	_, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "", "")
	if err == nil {
		t.Fatal("dialThroughProxy: want error when no credentials are configured, got nil")
	}
	if errors.Is(err, ErrProxyCredentialsRejected) {
		t.Error("err should NOT be ErrProxyCredentialsRejected -- no attempt was ever made, nothing was rejected")
	}
}

func TestProxyAwareNetDialContext_NoProxyConfigured_DialsDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")

	dial := proxyAwareNetDialContext(Config{})
	conn, err := dial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
}

func TestDialThroughProxy_BasicChallengeWithBody_RetrySucceedsDespiteUndrainedBody(t *testing.T) {
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		// A real proxy's 407 carries a body (e.g. an HTML "access denied"
		// page) -- deliver the headers and body in SEPARATE writes to
		// simulate real TCP segmentation, which is what exposes an
		// undrained-body bug that a single combined write would hide.
		body := "<html><body>Access Denied</body></html>"
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n", len(body))))
		time.Sleep(10 * time.Millisecond)
		conn.Write([]byte(body))

		req2, err := http.ReadRequest(br)
		if err != nil || req2.Method != http.MethodConnect {
			return
		}
		auth := req2.Header.Get("Proxy-Authorization")
		if auth != "Basic YnJhbmNoLXVzZXI6czNjcjN0" { // base64("branch-user:s3cr3t")
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		time.Sleep(50 * time.Millisecond)
	})

	conn, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "branch-user", "s3cr3t")
	if err != nil {
		t.Fatalf("dialThroughProxy: %v (an undrained 407 body would corrupt this retry's response parsing)", err)
	}
	conn.Close()
}

func TestParseProxyAuthenticate_SplitsCommaSeparatedChallengeList(t *testing.T) {
	offered := parseProxyAuthenticate([]string{`NTLM, Basic realm="corp"`})
	if !offered["ntlm"] {
		t.Error(`offered["ntlm"] = false, want true (comma-separated list must still detect NTLM)`)
	}
	if !offered["basic"] {
		t.Error(`offered["basic"] = false, want true (comma-separated list must still detect Basic)`)
	}
}
