package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// ErrProxyCredentialsRejected marks a CONFIRMED-rejected proxy credential: a
// completed NTLM or Basic negotiation the proxy explicitly rejected (a
// 407/403 AFTER a full attempt), not the initial unauthenticated 407 every
// negotiation starts with. connectWS() checks this via errors.Is to select
// the lockout-aware backoff (agent/backoff.go's wsProxyAuthReconnectBackoff)
// instead of the normal one -- retrying a wrong credential against a real
// AD-integrated proxy quickly risks tripping its lockout policy.
var ErrProxyCredentialsRejected = errors.New("proxy rejected the configured credentials")

// attemptNTLMProxyAuth is set by agent/proxyauth_windows.go's init() on
// Windows builds only; nil on every other platform, which is exactly the
// signal dialThroughProxy uses to know NTLM isn't available here. Takes the
// already-connected proxy connection (NTLM is bound to this one TCP
// connection, not stateless like Basic), the shared *bufio.Reader that ALL
// CONNECT attempts on this connection must use (see sendConnect), and the
// CONNECT target; returns the same connection on success (now an
// authenticated tunnel), or an error --
// wrapping ErrProxyCredentialsRejected specifically if the proxy completed
// the handshake and then rejected it, a plain error for any other failure
// (network error, malformed challenge, etc., which uses the standard
// backoff, not the lockout-aware one).
var attemptNTLMProxyAuth func(conn net.Conn, br *bufio.Reader, targetAddr string) (net.Conn, error)

// proxyAwareNetDialContext returns a NetDialContext-shaped function (see
// gorilla/websocket's Dialer.NetDialContext) that resolves whether a proxy
// applies to the target using the same logic http.ProxyFromEnvironment uses
// (so HTTP_PROXY/HTTPS_PROXY/NO_PROXY behave exactly as they do today), and
// if so, owns the full CONNECT negotiation via dialThroughProxy. No proxy
// resolved -> a plain net.Dial, byte-for-byte the same as today's behavior.
func proxyAwareNetDialContext(cfg Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		scheme := "http"
		if strings.HasPrefix(cfg.ServerURL, "https://") {
			scheme = "https"
		}
		targetURL := &url.URL{Scheme: scheme, Host: addr}
		req := &http.Request{URL: targetURL}
		proxyURL, err := http.ProxyFromEnvironment(req)
		if err != nil {
			return nil, fmt.Errorf("resolve proxy: %w", err)
		}
		if proxyURL == nil {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}

		user, password := cfg.ProxyUser, cfg.ProxyPassword
		if user == "" && proxyURL.User != nil {
			// Legacy fallback: credentials embedded directly in HTTP_PROXY/
			// HTTPS_PROXY still work, matching gorilla's old (preemptive-only)
			// behavior -- just no longer the recommended path since it has no
			// at-rest protection.
			user = proxyURL.User.Username()
			password, _ = proxyURL.User.Password()
		}
		return dialThroughProxy(ctx, proxyURL.Host, addr, user, password)
	}
}

// dialThroughProxy performs the full CONNECT negotiation against proxyAddr
// for targetAddr: unauthenticated first, then NTLM (Windows, if offered and
// attemptNTLMProxyAuth is set) or Basic (any platform, if offered and a
// credential is available) on a 407, per the priority rule in the plan's
// Global Constraints. Returns the established tunnel connection, or an error
// -- wrapping ErrProxyCredentialsRejected specifically when a negotiation
// completed and was rejected.
func dialThroughProxy(ctx context.Context, proxyAddr, targetAddr, user, password string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set proxy negotiation deadline: %w", err)
	}

	br := bufio.NewReader(conn)

	resp, err := sendConnect(conn, br, targetAddr, "")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: %w", targetAddr, proxyAddr, err)
	}
	if resp.StatusCode == http.StatusOK {
		return finishTunnel(conn, br)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		drainAndClose(resp)
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: unexpected status %s", targetAddr, proxyAddr, resp.Status)
	}
	drainAndClose(resp)

	offered := parseProxyAuthenticate(resp.Header.Values("Proxy-Authenticate"))

	if offered["ntlm"] && attemptNTLMProxyAuth != nil {
		tunnelConn, err := attemptNTLMProxyAuth(conn, br, targetAddr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("NTLM proxy auth via %s: %w", proxyAddr, err)
		}
		return tunnelConn, nil
	}

	if offered["basic"] && user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		resp2, err := sendConnect(conn, br, targetAddr, "Basic "+cred)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("CONNECT %s via %s (Basic retry): %w", targetAddr, proxyAddr, err)
		}
		if resp2.StatusCode == http.StatusOK {
			return finishTunnel(conn, br)
		}
		drainAndClose(resp2)
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: %w (status %s)", targetAddr, proxyAddr, ErrProxyCredentialsRejected, resp2.Status)
	}

	conn.Close()
	return nil, fmt.Errorf("proxy %s requires authentication (offered: %s); %s",
		proxyAddr, strings.Join(offeredNames(offered), ", "), unavailableReason(offered, user))
}

// sendConnect writes one CONNECT request for targetAddr on conn (optionally
// with a Proxy-Authorization header) and reads the response using the
// SHARED reader br. All CONNECT attempts on one conn (the initial
// unauthenticated probe, NTLM's 3 legs, Basic's single retry) MUST share
// the same *bufio.Reader -- a fresh reader per call silently drops any
// bytes it already buffered past the previous response's headers (e.g. a
// 407's response body), corrupting the next response's framing.
func sendConnect(conn net.Conn, br *bufio.Reader, targetAddr, proxyAuth string) (*http.Response, error) {
	header := make(http.Header)
	if proxyAuth != "" {
		header.Set("Proxy-Authorization", proxyAuth)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: header,
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(br, req)
}

// drainAndClose discards an intermediate (non-final) CONNECT response's
// body -- real proxies send one with a 407 (e.g. an HTML "access denied"
// page), and leaving it unread corrupts the next CONNECT attempt's framing
// on the same connection, since the shared reader still holds those bytes.
//
// Only drains when the body's length is actually bounded (an explicit
// Content-Length, or chunked transfer-encoding, which is self-terminating).
// A response with NEITHER is "close-delimited" per RFC 7230 -- its body has
// no defined end short of the connection actually closing, which will never
// happen here since we're about to reuse this same connection for the next
// CONNECT attempt. Forcibly draining that case would block until our own
// negotiation deadline fires, turning a proxy's harmless bodyless 407 into
// a guaranteed timeout. resp.Body.Close() alone is safe in that case --
// Go's http.Response body wrapper already knows not to force a read to EOF
// when the response is close-delimited (see resp.Close).
func drainAndClose(resp *http.Response) {
	if resp.Body == nil {
		return
	}
	if resp.ContentLength >= 0 || len(resp.TransferEncoding) > 0 {
		io.Copy(io.Discard, resp.Body)
	}
	resp.Body.Close()
}

// finishTunnel returns conn as the established tunnel after clearing the
// negotiation deadline (see dialThroughProxy) and confirming br has no
// leftover buffered bytes. gorilla reads directly from the returned
// net.Conn afterward (bypassing br entirely) for its own TLS handshake and
// WS upgrade -- any bytes still sitting in br would be silently lost,
// corrupting that handshake. A compliant proxy's 200 CONNECT response
// carries no body, so this should never actually trip in practice; it
// turns a would-be mysterious downstream TLS failure into a clear
// diagnostic instead.
func finishTunnel(conn net.Conn, br *bufio.Reader) (net.Conn, error) {
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clear proxy negotiation deadline: %w", err)
	}
	if br.Buffered() > 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy sent %d unexpected byte(s) after the CONNECT response -- cannot establish a clean tunnel", br.Buffered())
	}
	return conn, nil
}

// parseProxyAuthenticate reduces zero or more Proxy-Authenticate header
// values to a lowercase scheme-name set. A single header VALUE can itself
// list multiple challenges separated by commas (RFC 7235) -- e.g.
// "NTLM, Basic realm=\"corp\"" -- so each value is split on commas before
// extracting each challenge's leading scheme token.
func parseProxyAuthenticate(values []string) map[string]bool {
	offered := make(map[string]bool)
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			scheme, _, _ := strings.Cut(strings.TrimSpace(part), " ")
			scheme = strings.ToLower(strings.TrimSpace(scheme))
			if scheme != "" {
				offered[scheme] = true
			}
		}
	}
	return offered
}

func offeredNames(offered map[string]bool) []string {
	names := make([]string, 0, len(offered))
	for name := range offered {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// unavailableReason explains WHY none of the offered mechanisms could be
// used, for the diagnostic error -- this is the piece that turns today's
// generic dial failure into something an operator can actually act on.
func unavailableReason(offered map[string]bool, user string) string {
	var reasons []string
	if offered["ntlm"] && attemptNTLMProxyAuth == nil {
		reasons = append(reasons, "SSPI unavailable on this platform")
	}
	if offered["basic"] && user == "" {
		reasons = append(reasons, "no Basic credentials configured (set BAS_PROXY_USER/BAS_PROXY_PASSWORD)")
	}
	if len(reasons) == 0 {
		return "no supported mechanism was offered"
	}
	return strings.Join(reasons, "; ")
}
