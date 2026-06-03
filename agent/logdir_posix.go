//go:build linux || darwin

package main

// logDir returns the platform log directory.
func logDir() string {
	return "/var/log/bas-agent"
}
