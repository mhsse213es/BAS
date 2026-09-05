package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func getOSVersion() string {
	return fmt.Sprintf("Darwin/%s (%s)", runtime.GOARCH, getDarwinVersion())
}

func getDarwinVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// getDomainJoined: no POSIX collection in this phase (see Phase 0C spec's
// "Explicitly out of scope" -- one fact, Windows-only, to start). nil means
// "not evaluated," which the orchestrator's gate treats as "never skip."
func getDomainJoined() *bool { return nil }
