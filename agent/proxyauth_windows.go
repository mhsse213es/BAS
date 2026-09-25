//go:build windows

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/alexbrainman/sspi/ntlm"
)

func init() {
	attemptNTLMProxyAuth = sspiAttemptNTLM
}

// sspiAttemptNTLM performs the 3-leg NTLM handshake against a proxy that
// has already replied 407 with a Proxy-Authenticate: NTLM challenge on
// conn (see dialThroughProxy in agent/proxyauth.go, which called this).
// Uses the calling process's own security context -- whatever identity the
// Windows Service runs as (see the plan's Global Constraints on what that
// means for a LocalSystem-run agent) -- no separate credential is
// requested or stored for this path.
func sspiAttemptNTLM(conn net.Conn, br *bufio.Reader, targetAddr string) (net.Conn, error) {
	creds, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("acquire current user credentials: %w", err)
	}
	defer creds.Release()

	secCtx, type1, err := ntlm.NewClientContext(creds)
	if err != nil {
		return nil, fmt.Errorf("build NTLM client context: %w", err)
	}
	defer secCtx.Release()

	resp1, err := sendConnect(conn, br, targetAddr, "NTLM "+base64.StdEncoding.EncodeToString(type1))
	if err != nil {
		return nil, fmt.Errorf("send Type1: %w", err)
	}
	if resp1.StatusCode == http.StatusOK {
		// Some proxies accept after Type1 alone in edge configurations --
		// treat it the same as a normal success.
		return finishTunnel(conn, br)
	}
	if resp1.StatusCode != http.StatusProxyAuthRequired {
		drainAndClose(resp1)
		return nil, fmt.Errorf("unexpected status after Type1: %s", resp1.Status)
	}

	type2 := extractNTLMChallenge(resp1.Header.Values("Proxy-Authenticate"))
	drainAndClose(resp1)
	if type2 == nil {
		return nil, fmt.Errorf("proxy did not return an NTLM Type2 challenge after Type1")
	}

	type3, err := secCtx.Update(type2)
	if err != nil {
		return nil, fmt.Errorf("compute NTLM Type3 response: %w", err)
	}

	resp2, err := sendConnect(conn, br, targetAddr, "NTLM "+base64.StdEncoding.EncodeToString(type3))
	if err != nil {
		return nil, fmt.Errorf("send Type3: %w", err)
	}
	if resp2.StatusCode == http.StatusOK {
		return finishTunnel(conn, br)
	}
	drainAndClose(resp2)
	return nil, fmt.Errorf("%w (status %s)", ErrProxyCredentialsRejected, resp2.Status)
}

// extractNTLMChallenge finds the base64 Type2 payload in a set of
// Proxy-Authenticate header values, or nil if none carries one.
func extractNTLMChallenge(values []string) []byte {
	for _, v := range values {
		scheme, rest, found := strings.Cut(v, " ")
		if !found || !strings.EqualFold(strings.TrimSpace(scheme), "NTLM") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			continue
		}
		return payload
	}
	return nil
}
