package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func getOSVersion() string {
	return fmt.Sprintf("Linux/%s (%s)", runtime.GOARCH, getLinuxVersion())
}

func getLinuxVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			name := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(name, `"`)
		}
	}
	return "unknown"
}

// getDomainJoined: no POSIX collection in this phase (see Phase 0C spec's
// "Explicitly out of scope" -- one fact, Windows-only, to start). nil means
// "not evaluated," which the orchestrator's gate treats as "never skip."
func getDomainJoined() *bool { return nil }
