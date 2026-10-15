package targetscope

import (
	"net"
	"strings"
	"time"
)

// MaxAuthorizedTargetsPerImport bounds a single TargetScopeImport the
// same way otsafety.MaxSensitiveZonesPerImport bounds a safety
// import -- a defensive cap, not a product limit.
const MaxAuthorizedTargetsPerImport = 500

// AuthorizedTarget declares one entry in a target-authorization
// scope -- either a CIDR range or an exact host, never both. CIDR
// entries are referenced by literal range, never cross-validated
// against a real networktopology.TopologyImport, matching every
// other "name/range is declared, not cross-validated" discipline in
// this initiative.
type AuthorizedTarget struct {
	CIDR string `json:"cidr,omitempty"`
	Host string `json:"host,omitempty"`
	Note string `json:"note,omitempty"`
}

// TargetScopeImport is one auditable, versioned snapshot declaring
// which targets are approved for active network probing (discovery,
// DNS security checks, transport security checks) -- the same shape
// discipline as otsafety.OTSafetyImport.
type TargetScopeImport struct {
	ID                string             `json:"id,omitempty"`
	SourceType        string             `json:"sourceType"`
	ImportedBy        string             `json:"importedBy,omitempty"`
	ImportedAt        time.Time          `json:"importedAt,omitempty"`
	ConfigVersion     string             `json:"configVersion,omitempty"`
	AuthorizedTargets []AuthorizedTarget `json:"authorizedTargets"`
	Limitations       []string           `json:"limitations,omitempty"`
}

// IsAuthorized reports whether host is covered by any entry in scope.
// A CIDR entry matches only when host parses as a literal IP address
// contained within it -- this never resolves a hostname to an IP, so
// it carries no DNS-rebinding risk, but it also never implicitly
// trusts a hostname against a CIDR entry declared for its current
// address. A Host entry matches by case-insensitive exact string
// equality against host as supplied (hostnames are compared
// literally, consistent with DNS's own case-insensitivity).
func IsAuthorized(host string, scope *TargetScopeImport) bool {
	ip := net.ParseIP(host)
	for _, at := range scope.AuthorizedTargets {
		if at.CIDR != "" && ip != nil {
			_, ipNet, err := net.ParseCIDR(at.CIDR)
			if err == nil && ipNet.Contains(ip) {
				return true
			}
		}
		if at.Host != "" && strings.EqualFold(at.Host, host) {
			return true
		}
	}
	return false
}

// UnauthorizedTargets returns every distinct host in hosts not
// covered by scope, in first-seen order. A nil scope means no
// target-scope import has ever been created -- this fails open,
// returning an empty slice, since there is nothing declared to check
// a target against. Once any scope exists, every host must be
// positively covered by it or is reported here; an unresolvable or
// undeclared host is never implicitly authorized -- the opposite
// fail direction from otsafety's sensitive-zone check, because this
// is an allowlist (approved targets), not a blocklist (dangerous
// zones).
func UnauthorizedTargets(hosts []string, scope *TargetScopeImport) []string {
	if scope == nil {
		return nil
	}
	seen := make(map[string]bool, len(hosts))
	var out []string
	for _, h := range hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		if !IsAuthorized(h, scope) {
			out = append(out, h)
		}
	}
	return out
}
