package scenario

import "fmt"

// ValidInProcessPolicy reports whether s is an accepted in-process policy.
// Only the exact documented values pass. Any other value is rejected rather than
// normalised, since a guessed policy would decide the verdict. The empty string
// means the policy is not stated.
func ValidInProcessPolicy(s string) bool {
	switch s {
	case "", "restricted", "unrestricted":
		return true
	}
	return false
}

// EffectiveInProcessPolicy resolves the policy a run is judged against. An
// explicit value (request or campaign override) takes precedence, then the
// installation default. If neither is set the result is "" (not stated), which
// keeps the in-process verdict UNVERIFIED. Invalid values from either source
// are an error, never silently replaced.
func EffectiveInProcessPolicy(explicit, installationDefault string) (string, error) {
	if !ValidInProcessPolicy(explicit) {
		return "", fmt.Errorf("invalid in-process policy %q: must be restricted, unrestricted, or empty", explicit)
	}
	if explicit != "" {
		return explicit, nil
	}
	if !ValidInProcessPolicy(installationDefault) {
		return "", fmt.Errorf("invalid installation in-process policy %q: must be restricted, unrestricted, or empty", installationDefault)
	}
	return installationDefault, nil
}
