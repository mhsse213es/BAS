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
