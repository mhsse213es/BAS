package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
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
// connection, not stateless like Basic) and the CONNECT target; returns the
// same connection on success (now an authenticated tunnel), or an error --
// wrapping ErrProxyCredentialsRejected specifically if the proxy completed
// the handshake and then rejected it, a plain error for any other failure
// (network error, malformed challenge, etc., which uses the standard
// backoff, not the lockout-aware one).
var attemptNTLMProxyAuth func(conn net.Conn, targetAddr string) (net.Conn, error)

// proxyAwareNetDialContext returns a NetDialContext-shaped function (see
// gorilla/websocket's Dialer.NetDialContext) that resolves whether a proxy
// applies to the target using the same logic http.ProxyFromEnvironment uses
// (so HTTP_PROXY/HTTPS_PROXY/NO_PROXY behave exactly as they do today), and
// if so, owns the full CONNECT negotiation via dialThroughProxy. No proxy
// resolved -> a plain net.Dial, byte-for-byte the same as today's behavior.
func proxyAwareNetDialContext(cfg Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		targetURL := &url.URL{Scheme: "https", Host: addr}
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

	resp, err := sendConnect(conn, targetAddr, "")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: %w", targetAddr, proxyAddr, err)
	}
	if resp.StatusCode == http.StatusOK {
		return conn, nil
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: unexpected status %s", targetAddr, proxyAddr, resp.Status)
	}

	offered := parseProxyAuthenticate(resp.Header.Values("Proxy-Authenticate"))

	if offered["ntlm"] && attemptNTLMProxyAuth != nil {
		tunnelConn, err := attemptNTLMProxyAuth(conn, targetAddr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("NTLM proxy auth via %s: %w", proxyAddr, err)
		}
		return tunnelConn, nil
	}

	if offered["basic"] && user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		resp2, err := sendConnect(conn, targetAddr, "Basic "+cred)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("CONNECT %s via %s (Basic retry): %w", targetAddr, proxyAddr, err)
		}
		if resp2.StatusCode == http.StatusOK {
			return conn, nil
		}
		conn.Close()
		return nil, fmt.Errorf("CONNECT %s via %s: %w (status %s)", targetAddr, proxyAddr, ErrProxyCredentialsRejected, resp2.Status)
	}

	conn.Close()
	return nil, fmt.Errorf("proxy %s requires authentication (offered: %s); %s",
		proxyAddr, strings.Join(offeredNames(offered), ", "), unavailableReason(offered, user))
}

// sendConnect writes one CONNECT request for targetAddr on conn (optionally
// with a Proxy-Authorization header) and reads the response. NTLM's 3-leg
// handshake and Basic's single retry both reuse this on the same connection
// -- CONNECT is the only method this whole negotiation ever sends.
func sendConnect(conn net.Conn, targetAddr, proxyAuth string) (*http.Response, error) {
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
	br := bufio.NewReader(conn)
	return http.ReadResponse(br, req)
}

// parseProxyAuthenticate reduces zero or more Proxy-Authenticate header
// values (a proxy can offer several) to a lowercase scheme-name set.
func parseProxyAuthenticate(values []string) map[string]bool {
	offered := make(map[string]bool)
	for _, v := range values {
		scheme, _, _ := strings.Cut(v, " ")
		offered[strings.ToLower(strings.TrimSpace(scheme))] = true
	}
	return offered
}

func offeredNames(offered map[string]bool) []string {
	names := make([]string, 0, len(offered))
	for name := range offered {
		names = append(names, name)
	}
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
