package scenario

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
