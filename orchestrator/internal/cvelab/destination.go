// Package cvelab is the lab-execution safety gate for CVE assessments: the
// seam between internal/cvecatalog's catalog entries, internal/cveval's
// verdict contract, and an actual runtime probe against an isolated lab
// target. No real network-sending prober ships in this package yet -- the
// Prober interface is the deferred seam a later lab adapter plugs into,
// matching internal/wafval's own "the lab adapter that produces
// observations is a separate, deferred package" discipline. Building that
// adapter without a real lab to test it against is itself a risk this
// package exists to prevent: every control below (destination allow-list,
// public-address refusal, explicit authorization, timeouts, request
// limits, fail-closed audit) is enforced regardless of whether a Prober is
// ever wired in, so adding one later cannot silently bypass any of it.
package cvelab

import (
	"fmt"
	"net"
	"slices"
)

// AllowedLabTargets is the explicit allow-list of destinations live
// execution may touch. An operator sets this; it is never derived from DNS
// or widened by a prefix/wildcard match. Empty means no live execution is
// possible against anything -- the package's safe default.
type AllowedLabTargets struct {
	Hosts []string // exact "host:port" entries, e.g. "10.50.0.12:8080"
}

// IsAllowed reports whether target is on the explicit allow-list by exact
// string equality only. A typo in an allow-list entry fails closed (the
// target is refused) rather than silently matching something wider.
func (a AllowedLabTargets) IsAllowed(target string) bool {
	return slices.Contains(a.Hosts, target)
}

// IsPublicAddress reports whether target's host is a public IP address.
// target must be "host:port" with host a literal IP address -- a hostname
// is refused outright (not resolved), because resolving DNS here and
// connecting later introduces a TOCTOU window where the resolved address
// could differ from whatever was checked. A non-literal-IP host, or any
// other parse failure, is reported as an error, and the caller must treat
// that the same as "public": refuse to execute.
func IsPublicAddress(target string) (bool, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false, fmt.Errorf("target %q must be \"host:port\": %w", target, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("target host %q is not a literal IP address; hostnames are refused to avoid a DNS-resolution bypass", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false, nil
	}
	return true, nil
}
