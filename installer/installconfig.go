package main

import (
	"fmt"
	"os"
	"strings"
)

// writeInstallConfig persists the two values collected from the user (the
// non-privileged phase) to a private temp file for the elevated phase to
// read, so the agent secret never has to be embedded as literal text in a
// shell command string passed through AppleScript's "do shell script" --
// only this file's path crosses that boundary, and the path is one we
// generate, never derived from user input.
func writeInstallConfig(serverURL, secret string) (string, error) {
	f, err := os.CreateTemp("", "bas-install-config-*")
	if err != nil {
		return "", fmt.Errorf("create install config: %w", err)
	}
	path := f.Name()
	f.Close()
	if err := os.Chmod(path, 0600); err != nil {
		return "", fmt.Errorf("chmod install config: %w", err)
	}
	content := serverURL + "\n" + secret + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("write install config: %w", err)
	}
	return path, nil
}

// readInstallConfig reads back the file writeInstallConfig produced.
func readInstallConfig(path string) (serverURL, secret string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read install config: %w", err)
	}
	lines := strings.SplitN(strings.TrimRight(string(data), "\n"), "\n", 2)
	if len(lines) != 2 {
		return "", "", fmt.Errorf("install config %s is malformed (expected 2 lines, got %d)", path, len(lines))
	}
	return lines[0], lines[1], nil
}
