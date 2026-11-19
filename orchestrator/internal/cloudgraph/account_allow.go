package cloudgraph

import (
	"fmt"
	"strings"
)

// AccountAllowList is the server's set of cloud accounts that discovery, scenario
// runs, campaigns and live probes may target. It is configured on the server and
// never taken from a request. An empty list permits nothing, so the check fails
// closed when the list is missing.
type AccountAllowList struct {
	allowed map[string]bool
}

// ParseAccountAllowList parses "provider:accountID" entries separated by commas.
// An empty string yields a list that permits nothing. A malformed entry is an
// error, so a typo cannot silently widen or narrow the scope.
func ParseAccountAllowList(s string) (AccountAllowList, error) {
	list := AccountAllowList{allowed: map[string]bool{}}
	for _, raw := range strings.Split(s, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		provider, account, ok := strings.Cut(entry, ":")
		provider, account = strings.TrimSpace(provider), strings.TrimSpace(account)
		if !ok || provider == "" || account == "" {
			return AccountAllowList{}, fmt.Errorf("cloud allow-list entry %q must be provider:accountId", entry)
		}
		list.allowed[provider+"|"+account] = true
	}
	return list, nil
}

// Permits reports whether the provider and account are on the list.
func (l AccountAllowList) Permits(provider, accountID string) bool {
	return provider != "" && accountID != "" && l.allowed[provider+"|"+accountID]
}

// Accounts returns the listed accounts for one provider, for startup checks.
func (l AccountAllowList) Accounts(provider string) []string {
	var out []string
	for key := range l.allowed {
		if p, acct, ok := strings.Cut(key, "|"); ok && p == provider {
			out = append(out, acct)
		}
	}
	return out
}
