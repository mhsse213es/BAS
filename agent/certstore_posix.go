//go:build linux || darwin

package main

// certDirPlatform is where the agent's CA root, own certificate, and
// private key are stored on Linux/macOS.
func certDirPlatform() string {
	return "/etc/audspect/certs"
}

// hardenCertDirPlatform is a no-op on POSIX — loadOrGenerateAgentKey and
// saveAgentCertificate already write with 0700/0600 permissions, which is
// sufficient given the agent already runs as root (see the existing
// elevation checks in platform_posix.go's callers).
func hardenCertDirPlatform(dir string) error { return nil }
