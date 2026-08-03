package remediation

import "strings"

// OSSupported reports whether agentOS (e.g. "windows", "linux", as stored
// on the agents.os_version column) is in entry's supported_os list.
// Case-insensitive; an empty agentOS never matches.
func OSSupported(agentOS string, entry CatalogEntry) bool {
	if agentOS == "" {
		return false
	}
	agentOS = strings.ToLower(agentOS)
	for _, os := range entry.SupportedOS {
		if strings.ToLower(os) == agentOS {
			return true
		}
	}
	return false
}
