//go:build linux || darwin

package main

// Attack-path local-identity collection and SharpHound are Windows/AD concepts.
// On Linux/macOS the agent still contributes reachability edges (the cross-
// platform TCP probes in attackpath.go); these helpers are no-ops.

func collectLocalAdmins() []string { return nil }

func collectSessions(currentUser string) []string {
	if currentUser == "" {
		return nil
	}
	return []string{currentUser}
}

func hostIsDomainJoined() bool { return false }

func runSharpHound(_ *Payload, _ string) ([]byte, error) { return nil, nil }
