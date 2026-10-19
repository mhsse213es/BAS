// Package phishscope holds the install-wide target allowlists that bound what a
// phishing run may touch in Microsoft Graph. The installation defines the scope.
// A run selects targets only from inside it. This package does no I/O and makes
// no Graph calls; the executor calls it before any call is made.
package phishscope

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// ErrTargetNotAllowlisted: a requested target, or the allowlist itself, does
	// not permit the request. The whole request is refused, never partly run.
	ErrTargetNotAllowlisted = errors.New("target_not_allowlisted")
	// ErrNoValidTargets: the request named no usable target.
	ErrNoValidTargets = errors.New("no_valid_targets")
)

var (
	guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	upnRe  = regexp.MustCompile(`^[^\s@*]+@[^\s@*]+\.[^\s@*]+$`)
)

// Scope is the installation's allowlist. Users holds user principal names or
// object IDs. ClientIDs holds application (client) IDs.
type Scope struct {
	Users     []string
	ClientIDs []string
}

// ConfiguredUsers reports whether any user target is permitted.
func (s Scope) ConfiguredUsers() bool { return len(s.Users) > 0 }

// ConfiguredClients reports whether any client target is permitted.
func (s Scope) ConfiguredClients() bool { return len(s.ClientIDs) > 0 }

// ParseScope reads the comma-separated setup-config values. Empty means
// unconfigured. A malformed entry is an error, so a typo cannot widen the scope
// silently. Wildcards and whitespace are refused.
func ParseScope(usersCSV, clientIDsCSV string) (Scope, error) {
	var s Scope
	for _, raw := range split(usersCSV) {
		if !guidRe.MatchString(raw) && !upnRe.MatchString(raw) {
			return Scope{}, fmt.Errorf("phishscope: user entry %q is not a user principal name or object ID", raw)
		}
		s.Users = append(s.Users, raw)
	}
	for _, raw := range split(clientIDsCSV) {
		if !guidRe.MatchString(raw) {
			return Scope{}, fmt.Errorf("phishscope: client entry %q is not an application (client) ID", raw)
		}
		s.ClientIDs = append(s.ClientIDs, raw)
	}
	return s, nil
}

func split(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ValidateTargets checks a run's requested targets against an allowlist. An
// empty allowlist permits nothing. A missing, blank, or wildcard target is
// refused as no valid target. Every requested target must be on the allowlist
// (case-insensitive), or the whole request is refused.
func ValidateTargets(allowed []string, requested []string) error {
	if len(requested) == 0 {
		return ErrNoValidTargets
	}
	permitted := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		permitted[strings.ToLower(strings.TrimSpace(a))] = true
	}
	for _, r := range requested {
		t := strings.TrimSpace(r)
		if t == "" || t == "*" {
			return ErrNoValidTargets
		}
		if !permitted[strings.ToLower(t)] {
			return fmt.Errorf("%w: %q is outside the installation's allowlist", ErrTargetNotAllowlisted, t)
		}
	}
	return nil
}
