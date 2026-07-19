package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseUserNameFilter extracts the value from the one supported SCIM
// filter shape: userName eq "value" — the only filter Okta/Azure AD send
// for a Users-only sync, used to check for an existing user before
// creating one. An empty filter string returns ("", nil) — no filter was
// requested. Any other expression returns an error: a SCIM
// misconfiguration should be visible, not silently ignored.
func ParseUserNameFilter(filter string) (string, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", nil
	}
	const prefix = `userName eq "`
	if !strings.HasPrefix(strings.ToLower(filter), strings.ToLower(prefix)) || !strings.HasSuffix(filter, `"`) {
		return "", fmt.Errorf(`unsupported filter expression: only userName eq "value" is supported`)
	}
	value := filter[len(prefix) : len(filter)-1]
	if value == "" {
		return "", fmt.Errorf("unsupported filter expression: empty userName value")
	}
	return value, nil
}

// ParsePatchActive extracts an active:true/false operation from a SCIM
// PatchOp body, tolerating both shapes real IdPs send: a "path":"active"
// operation with a boolean value (Okta), or a path-less operation whose
// "value" object contains "active" (Azure AD). found=false means the body
// contained no active operation — Audspect only implements the
// active-toggle PATCH path, per the spec's Users-only scope.
func ParsePatchActive(body []byte) (active bool, found bool, err error) {
	var op PatchOp
	if err := json.Unmarshal(body, &op); err != nil {
		return false, false, err
	}
	for _, o := range op.Operations {
		if strings.EqualFold(o.Path, "active") {
			var v bool
			if jsonErr := json.Unmarshal(o.Value, &v); jsonErr == nil {
				return v, true, nil
			}
			continue
		}
		if o.Path == "" {
			var obj struct {
				Active *bool `json:"active"`
			}
			if jsonErr := json.Unmarshal(o.Value, &obj); jsonErr == nil && obj.Active != nil {
				return *obj.Active, true, nil
			}
		}
	}
	return false, false, nil
}
