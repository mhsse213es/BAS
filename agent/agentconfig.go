package main

import "fmt"

// renderPosixAgentConfig builds the EnvironmentFile contents the posix service
// installers (systemd on Linux, launchd on macOS) write to the agent config
// file. It is pure and untagged so it can be unit-tested on any host,
// including the Windows build host.
//
// enrollPort is written only when non-empty. A default-port deployment keeps a
// minimal config and the agent falls back to its built-in 9444 enrollment-port
// default (see bootstrap.go enrollPort()); a deployment that remapped the
// published enrollment port passes it here so CSR bootstrap reaches the right
// host port with no manual config edit.
func renderPosixAgentConfig(serverURL, envLabel, secret, proxyUser, proxyPasswordB64, enrollPort string) string {
	cfg := fmt.Sprintf("BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\nBAS_AGENT_SECRET=%s\nBAS_PROXY_USER=%s\nBAS_PROXY_PASSWORD_B64=%s\n",
		serverURL, envLabel, secret, proxyUser, proxyPasswordB64)
	if enrollPort != "" {
		cfg += fmt.Sprintf("BAS_ENROLL_PORT=%s\n", enrollPort)
	}
	return cfg
}
