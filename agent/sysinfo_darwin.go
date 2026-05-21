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
