// Package preflight checks, before anything is installed, that an agent could
// enroll: the server is reachable on the enrollment port, its certificate is
// vouched for by the supplied deployment CA, and the agent secret is accepted.
//
// It writes nothing, installs nothing and never logs or returns the secret.
//
// Exit codes (Result.Code, also the process exit code of `--preflight`):
//
//	0   OK                the server is reachable and the secret is accepted
//	20  invalid input     bad URL, port or secret (configuration error)
//	21  unreachable       cannot connect, or the server health check failed
//	22  secret rejected   the server answered 401 to the agent secret
//	23  trust failure     the server certificate is not vouched for by the CA
//	24  invalid CA        the supplied CA PEM is not a usable certificate
package preflight

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	CodeOK             = 0
	CodeInvalidInput   = 20
	CodeUnreachable    = 21
	CodeSecretRejected = 22
	CodeTrustFailure   = 23
	CodeInvalidCA      = 24
	// CodeConfigRejected: the signed deployment config failed verification
	// (missing/mismatched fingerprint, bad signature, unsupported or invalid content).
	CodeConfigRejected = 25

	// CodeEnrollmentRejected: the server refused the single-use enrolment token (invalid, expired,
	// already used, or issued for a different agent), or enrolment could not be completed.
	CodeEnrollmentRejected = 26

	// CodeServerUnreachable: enrolment could not be completed because the server could not be reached or
	// failed (network, TLS, 5xx, unexpected response), as opposed to CodeEnrollmentRejected where the server
	// answered and refused the credentials.
	CodeServerUnreachable = 27

	// CodeAlreadyEnrolled: the server answered 409, so it already holds a live identity for this host and will not
	// let a new install replace it on the shared secret alone. An administrator must Force Remove the host in the
	// console or issue an enrolment token for it.
	CodeAlreadyEnrolled = 28
)

const defaultEnrollPort = "9444"

// Params is everything a preflight check needs.
type Params struct {
	ServerURL  string // https URL of the orchestrator; its port is replaced by EnrollPort
	EnrollPort string // enrollment listener port; empty means 9444
	Secret     string // agent secret; never echoed back
	CARootPEM  []byte // deployment CA root; empty means pre-trust (server identity unverified)
}

// Result is the outcome of a preflight check. Message is one line and never
// contains the secret.
type Result struct {
	Code    int
	Message string
}

// OK reports whether the check passed.
func (r Result) OK() bool { return r.Code == CodeOK }

// EnrollmentProbeURL returns serverURL with its port replaced by the
// enrollment port. The enrollment listener, not the mTLS port, is what a new
// agent talks to, so that is what must be reachable before installing.
func EnrollmentProbeURL(serverURL, enrollPort string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}
	if enrollPort == "" {
		enrollPort = defaultEnrollPort
	}
	u.Host = net.JoinHostPort(u.Hostname(), enrollPort)
	return u.String(), nil
}

func fail(code int, format string, a ...any) Result {
	return Result{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Run performs the check. It never contacts the server with the secret unless
// the server's identity has first been confirmed against the supplied CA.
func Run(ctx context.Context, p Params) Result {
	u, err := url.Parse(strings.TrimSpace(p.ServerURL))
	switch {
	case err != nil || u.Scheme != "https" || u.Hostname() == "":
		return fail(CodeInvalidInput, "server URL must be an https URL with a host")
	case u.User != nil:
		return fail(CodeInvalidInput, "server URL must not contain credentials")
	}
	if p.EnrollPort != "" {
		n, perr := strconv.Atoi(p.EnrollPort)
		if perr != nil || n < 1 || n > 65535 {
			return fail(CodeInvalidInput, "enrollment port must be a number between 1 and 65535")
		}
	}
	if p.Secret == "" {
		return fail(CodeInvalidInput, "agent secret is required")
	}
	for _, r := range p.Secret {
		if r < 0x20 || r == 0x7f {
			return fail(CodeInvalidInput, "agent secret contains control characters")
		}
	}

	var pool *x509.CertPool
	if len(p.CARootPEM) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(p.CARootPEM) {
			return fail(CodeInvalidCA, "the deployment CA is not a valid certificate")
		}
	}

	base, err := EnrollmentProbeURL(u.String(), p.EnrollPort)
	if err != nil {
		return fail(CodeInvalidInput, "server URL is not valid")
	}

	client := newClient(pool)

	// Health first, with no secret: this confirms reachability and, when a CA
	// is supplied, that the server is the one the CA vouches for.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
	if err != nil {
		return fail(CodeInvalidInput, "server URL is not valid")
	}
	resp, err := client.Do(req)
	if err != nil {
		if isTrustError(err) {
			return fail(CodeTrustFailure, "the server certificate is not trusted by the supplied deployment CA")
		}
		return fail(CodeUnreachable, "cannot reach the server at %s: check the URL, port and firewall", hostPort(base))
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(CodeUnreachable, "the server health check returned HTTP %d", resp.StatusCode)
	}

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/ws/agent", nil)
	if err != nil {
		return fail(CodeInvalidInput, "server URL is not valid")
	}
	req2.Header.Set("X-Agent-Token", p.Secret)
	resp2, err := client.Do(req2)
	if err != nil {
		if isTrustError(err) {
			return fail(CodeTrustFailure, "the server certificate is not trusted by the supplied deployment CA")
		}
		return fail(CodeUnreachable, "the secret check could not reach %s", hostPort(base))
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusUnauthorized {
		return fail(CodeSecretRejected, "the agent secret was rejected by the server (HTTP 401)")
	}

	if pool == nil {
		return Result{Code: CodeOK, Message: "server reachable and secret accepted (no deployment CA supplied: the server identity was not verified)"}
	}
	return Result{Code: CodeOK, Message: "server reachable, certificate trusted and secret accepted"}
}

func hostPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "the server"
	}
	return u.Host
}

// newClient verifies the server against pool when one is given. Without a CA
// it skips verification: the same pre-trust behaviour the installer has today
// for deployments with no CA available, reported honestly in the result.
func newClient(pool *x509.CertPool) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pool != nil {
		cfg.RootCAs = pool
	} else {
		cfg.InsecureSkipVerify = true //nolint:gosec // pre-trust probe; see doc comment
	}
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: cfg},
	}
}

func isTrustError(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verify *tls.CertificateVerificationError
	return errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &verify)
}
