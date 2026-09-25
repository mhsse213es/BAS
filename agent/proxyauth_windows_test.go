//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAttemptNTLMProxyAuth_SendsWellFormedType1Message proves the
// NEGOTIATION SHAPE: given a proxy that challenges with NTLM, the handler
// sends a syntactically valid NTLM Type1 message as the first
// Proxy-Authorization attempt. This does not validate real NTLM crypto
// against a genuine authenticating proxy (impractical without a real
// Windows domain) -- see the plan's Task 4 Step 5 for that manual/staging
// verification step.
func TestAttemptNTLMProxyAuth_SendsWellFormedType1Message(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type1Received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		auth := req.Header.Get("Proxy-Authorization")
		type1Received <- auth
		// Reply with a 407 carrying no further challenge -- this test only
		// checks the FIRST message's shape, not a full successful handshake.
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\n\r\n"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	go attemptNTLMProxyAuth(conn, bufio.NewReader(conn), "target.example:9443")

	select {
	case auth := <-type1Received:
		if !strings.HasPrefix(auth, "NTLM ") {
			t.Fatalf("Proxy-Authorization = %q, want prefix 'NTLM '", auth)
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "NTLM "))
		if err != nil {
			t.Fatalf("NTLM payload is not valid base64: %v", err)
		}
		// NTLM messages start with the fixed 8-byte signature "NTLMSSP\x00".
		if len(payload) < 8 || string(payload[:7]) != "NTLMSSP" {
			t.Fatalf("NTLM payload does not start with the NTLMSSP signature: %x", payload[:min(len(payload), 16)])
		}
		// Type1 is message type 1 -- the 4 bytes right after the signature.
		if len(payload) < 12 || payload[8] != 1 {
			t.Fatalf("NTLM payload type = %d, want 1 (Type1)", payload[8])
		}
	case <-timeoutChan(t):
		t.Fatal("timed out waiting for the NTLM Type1 CONNECT")
	}
}

func timeoutChan(t *testing.T) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	go func() {
		// This is a unit test against a local in-process listener -- 5s is
		// generous, not a real network timeout being tuned.
		<-time.After(5 * time.Second)
		close(ch)
	}()
	return ch
}

func TestDialThroughProxy_BothOffered_AttemptsNTLMFirstNoFallbackToBasic(t *testing.T) {
	var authAttempts []string
	proxy := newFakeConnectProxy(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"))

		req2, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		authAttempts = append(authAttempts, req2.Header.Get("Proxy-Authorization"))
		// Deliberately fail the NTLM handshake (no valid Type2 challenge in
		// this response) -- this test only cares about WHICH scheme was
		// attempted first and whether a hard NTLM failure falls back to
		// Basic in the same attempt (it must not), not whether the full
		// handshake succeeds.
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
	})

	_, err := dialThroughProxy(context.Background(), proxy.addr(), "target.example:9443", "branch-user", "s3cr3t")
	if err == nil {
		t.Fatal("dialThroughProxy: want error (NTLM handshake deliberately fails in this test setup), got nil")
	}
	if errors.Is(err, ErrProxyCredentialsRejected) {
		t.Error("a hard NTLM negotiation failure (missing Type2 challenge) must NOT be treated as a confirmed-rejected credential")
	}
	if len(authAttempts) != 1 {
		t.Fatalf("proxy saw %d authenticated CONNECT attempt(s), want exactly 1 (no fallback to Basic in the same attempt)", len(authAttempts))
	}
	if !strings.HasPrefix(authAttempts[0], "NTLM ") {
		t.Fatalf("first Proxy-Authorization = %q, want NTLM prefix -- NTLM must be attempted before Basic when both are offered", authAttempts[0])
	}
}
