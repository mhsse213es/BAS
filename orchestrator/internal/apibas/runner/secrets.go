package runner

import "fmt"

// MapSecrets is an in-memory SecretResolver. It is for tests and the local
// lab only. Production credentials must come from a secret store behind the
// same interface; that adapter is not built yet.
type MapSecrets map[string]string

// Resolve returns the secret for ref. The value is never included in errors.
func (m MapSecrets) Resolve(ref string) (string, error) {
	v, ok := m[ref]
	if !ok || v == "" {
		return "", fmt.Errorf("runner: no secret for reference %q", ref)
	}
	return v, nil
}
