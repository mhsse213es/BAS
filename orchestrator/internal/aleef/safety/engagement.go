package safety

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/audspect/bas/internal/targetscope"
)

// MaxWindow is the longest engagement validity window accepted.
const MaxWindow = 30 * 24 * time.Hour

// Engagement is the record that authorises a run. Without a valid one nothing
// is sent.
type Engagement struct {
	ID          string `json:"id"`
	Customer    string `json:"customer"`
	Environment string `json:"environment"` // "lab" or "uat"; anything else is refused
	// Hosts are exact origins, for example "https://uat.bank.example:8443".
	Hosts     []string  `json:"hosts"`
	Approver  string    `json:"approver"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Accounts  []string  `json:"accounts,omitempty"`
	// Operations is an allowlist of operation ids. Empty means no restriction
	// for read, setup_safe and reversible operations; money and notifying
	// operations must always be listed.
	Operations    []string `json:"operations,omitempty"`
	MaxRequests   int      `json:"maxRequests"`
	MaxConcurrent int      `json:"maxConcurrent"`
	RPS           float64  `json:"rps"`
	SimulatedRail bool     `json:"simulatedRail,omitempty"`
	// SimulatorBeneficiaries must be non-empty for money operations; the
	// values are not enforced against request bodies in Milestone 1.
	SimulatorBeneficiaries []string `json:"simulatorBeneficiaries,omitempty"`
	TestRecipients         []string `json:"testRecipients,omitempty"`
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrClassRefused, fmt.Sprintf(format, a...))
}

// MarshalJSON encodes the engagement.
func (e Engagement) MarshalJSON() ([]byte, error) {
	type plain Engagement
	return json.Marshal(plain(e))
}

// Parse decodes and validates an engagement. Unknown fields are rejected.
func Parse(b []byte) (Engagement, error) {
	type plain Engagement
	var p plain
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Engagement{}, fmt.Errorf("%w: %v", ErrInvalidEngagement, err)
	}
	if dec.More() {
		return Engagement{}, fmt.Errorf("%w: trailing data", ErrInvalidEngagement)
	}
	e := Engagement(p)
	if err := e.Validate(); err != nil {
		return Engagement{}, err
	}
	return e, nil
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidEngagement, fmt.Sprintf(format, a...))
}

// Validate checks everything that does not depend on the current time or a
// particular request.
func (e Engagement) Validate() error {
	switch e.Environment {
	case "lab", "uat":
	default:
		return invalid("environment %q is not permitted (only lab and uat; production is refused)", e.Environment)
	}
	if strings.TrimSpace(e.Customer) == "" {
		return invalid("customer is required")
	}
	if strings.TrimSpace(e.Approver) == "" {
		return invalid("a named approver is required")
	}
	if e.NotBefore.IsZero() || e.NotAfter.IsZero() || !e.NotAfter.After(e.NotBefore) {
		return invalid("window must have NotAfter after NotBefore")
	}
	if e.NotAfter.Sub(e.NotBefore) > MaxWindow {
		return invalid("window is longer than %d days", int(MaxWindow/(24*time.Hour)))
	}
	if len(e.Hosts) == 0 {
		return invalid("at least one host origin is required")
	}
	for _, h := range e.Hosts {
		if _, err := NormalizeOrigin(h); err != nil {
			return invalid("host %q: %v", h, err)
		}
	}
	if e.MaxRequests <= 0 {
		return invalid("MaxRequests must be positive")
	}
	if e.MaxConcurrent <= 0 {
		return invalid("MaxConcurrent must be positive")
	}
	if !(e.RPS > 0) {
		return invalid("RPS must be positive")
	}
	return nil
}

// InWindow reports whether now is inside [NotBefore, NotAfter).
func (e Engagement) InWindow(now time.Time) error {
	if now.Before(e.NotBefore) || !now.Before(e.NotAfter) {
		return ErrOutsideWindow
	}
	return nil
}

// NormalizeOrigin parses an origin (scheme://host[:port], no userinfo, path,
// query or fragment) and returns its canonical form: lower-case scheme and
// host, default port dropped.
func NormalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return "", fmt.Errorf("not a valid origin")
	}
	return originOf(u, true)
}

// originOf builds the canonical origin of u. strict additionally refuses a
// path, query or fragment (used for engagement hosts).
func originOf(u *url.URL, strict bool) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if u.User != nil {
		return "", fmt.Errorf("userinfo is not allowed")
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return "", fmt.Errorf("host is required")
	}
	if strict && ((u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery) {
		return "", fmt.Errorf("an origin has no path, query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Authorize decides whether a run against origin is permitted at time now.
// It refuses production and unknown environments, a missing approver, a
// window that is invalid, too long or not open at now, an origin that is not
// exactly one of Hosts, and a host the target scope does not cover. A "lab"
// engagement against a loopback host may omit the scope; a "uat" engagement
// always requires one. A scope that is supplied is always enforced.
func (e Engagement) Authorize(origin string, scope *targetscope.TargetScopeImport, now time.Time) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := e.InWindow(now); err != nil {
		return err
	}
	u, err := url.Parse(origin)
	if err != nil || origin == "" {
		return fmt.Errorf("%w: not a valid origin", ErrOriginRefused)
	}
	norm, err := originOf(u, true)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOriginRefused, err)
	}
	found := false
	for _, h := range e.Hosts {
		hn, _ := NormalizeOrigin(h) // validated above
		if hn == norm {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: %s is not an engagement host", ErrNotAuthorized, norm)
	}
	host := u.Hostname()
	switch {
	case scope != nil:
		if !targetscope.IsAuthorized(host, scope) {
			return fmt.Errorf("%w: host %s is outside the target scope", ErrNotAuthorized, host)
		}
	case e.Environment == "lab" && isLoopbackHost(host):
		// lab loopback without a scope is the only scope-free path
	default:
		return fmt.Errorf("%w: a target scope is required for %s", ErrNotAuthorized, host)
	}
	return nil
}
