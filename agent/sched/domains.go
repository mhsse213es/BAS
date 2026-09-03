package sched

import (
	"path"
	"strings"
)

// DomainKind fixes how a domain may be addressed. A domain is addressed EITHER
// as a whole or by key, never both.
//
// Mixing the two cannot be made safe with only shared/exclusive locks. These
// three properties cannot hold simultaneously:
//
//  1. two whole-domain readers run concurrently,
//  2. a whole-domain reader excludes a keyed writer beneath it,
//  3. two keyed writers of distinct keys run concurrently.
//
// Any assignment of shared/exclusive that buys (2) costs (1) or (3) -- it is the
// intention-lock problem (S conflicting with IX) that two-mode locks cannot
// express. Fixing granularity per domain removes the need for (2) entirely, so
// (1) and (3) are both kept.
type DomainKind int

const (
	// KindWholeDomain: declarations carry no Key; the lock covers the domain.
	KindWholeDomain DomainKind = iota
	// KindKeyed: declarations must carry a Key; the lock covers that key alone.
	KindKeyed
)

// domainRegistry is the closed vocabulary of resource domains. A domain absent
// from this map is unknown, and an unknown domain escalates to the exclusive
// global barrier rather than being trusted.
//
// Every domain is whole-domain today, mirroring the profiles in
// orchestrator/internal/scenario/resource.go, all of which are observe(domain)
// with no Key. That is what preserves current parallelism: two whole-domain
// readers take shared locks and still overlap. Registering one of these as
// keyed would invalidate every declaration that uses it.
var domainRegistry = map[string]DomainKind{
	"registry":      KindWholeDomain,
	"filesystem":    KindWholeDomain,
	"process":       KindWholeDomain,
	"network":       KindWholeDomain,
	"wmi-secpolicy": KindWholeDomain,
}

// LookupDomain reports the granularity registered for name, and whether name is
// registered at all.
func LookupDomain(name string) (DomainKind, bool) {
	k, ok := domainRegistry[name]
	return k, ok
}

// CanonicaliseKey returns the stable identity of key within domain, or ok=false
// when the key has no stable identity.
//
// Canonicalisation is domain-specific: a single global normaliser would be
// wrong, since a filesystem path, a registry path and a flat identifier have
// different identity rules.
//
// A false result must escalate to the global barrier. A key that cannot be
// canonicalised is never accepted as written -- two spellings of one resource
// that produce different keys would not conflict, which is precisely the
// under-declaration the design forbids.
func CanonicaliseKey(domain, key string) (string, bool) {
	if key == "" {
		return "", false
	}
	// An unexpanded %TEMP% or $HOME resolves differently per host and per user,
	// so it names no fixed resource.
	if strings.ContainsAny(key, "%$") {
		return "", false
	}

	switch domain {
	case "filesystem":
		// Relative paths have no stable identity: the same string denotes
		// different files depending on the step's working directory.
		if !strings.HasPrefix(key, "/") {
			return "", false
		}
		// Reject ".." BEFORE cleaning, not after: path.Clean would resolve it
		// lexically and the check would never fire. Lexical resolution is also
		// unsound -- /a/b/../c is not /a/c when b is a symlink -- so a path
		// containing ".." names no identity we can trust. Same aliasing hazard
		// the spec handles by declaring the domain instead of a key.
		for _, seg := range strings.Split(key, "/") {
			if seg == ".." {
				return "", false
			}
		}
		return path.Clean(key), true

	case "registry":
		// Windows registry paths are case-insensitive; fold so two spellings of
		// one key conflict. Hive-alias normalisation belongs here too once a
		// keyed registry domain exists.
		return strings.ToLower(strings.TrimSpace(key)), true

	default:
		// Flat identifiers (ports, services, users): opaque tokens, compared
		// verbatim after trimming.
		c := strings.TrimSpace(key)
		if c == "" {
			return "", false
		}
		return c, true
	}
}
