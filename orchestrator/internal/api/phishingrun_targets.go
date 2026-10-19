package api

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/phishscope"
)

// requestedTargets reads a run's target parameter. It accepts either a list of
// strings or one comma-separated string. Anything else is no targets at all.
func requestedTargets(params map[string]any, key string) []string {
	switch v := params[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			} else {
				out = append(out, "")
			}
		}
		return out
	case []string:
		return v
	case string:
		var out []string
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

// refuseUnlessScoped returns a non-nil error when the run's targets are not all
// inside the installation's allowlist. The executor calls it before any Graph
// request, so an out-of-scope run makes no call at all.
func refuseUnlessScoped(allowed, requested []string) error {
	if err := phishscope.ValidateTargets(allowed, requested); err != nil {
		return fmt.Errorf("phishingrun: %w", err)
	}
	return nil
}
