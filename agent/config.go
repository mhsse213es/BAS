package main

import (
	"os"
	"strings"
)

type Config struct {
	ServerURL     string
	EnvLabel      string
	AgentSecret   string // shared secret for X-Agent-Token + result HMAC signing
	ProxyUser     string // forward-proxy username, Basic auth only (NTLM needs none)
	ProxyPassword string // forward-proxy password, Basic auth only
	// MTLS is set only by resolveOperationalConfig (bootstrap.go), after
	// ensureCertificate confirmed a usable client certificate and rewrote
	// ServerURL to the orchestrator's mTLS listener. Every client built from
	// a Config (newAgent's HTTP client, the log shipper, the WS dialer)
	// attaches mtlsTLSConfig exactly when this is true.
	MTLS bool
}

func loadConfig() Config {
	serverURL := os.Getenv("BAS_SERVER_URL")
	envLabel := os.Getenv("BAS_ENV_LABEL")
	agentSecret := os.Getenv("BAS_AGENT_SECRET")

	if serverURL == "" || envLabel == "" {
		if u, e := readServiceParams(); u != "" || e != "" {
			if serverURL == "" {
				serverURL = u
			}
			if envLabel == "" {
				envLabel = e
			}
		}
	}
	// Fallback: read DPAPI-encrypted secret from registry (Windows service installs).
	// Env var takes priority so operators can override without reinstalling.
	if agentSecret == "" {
		agentSecret = readEncryptedSecretPlatform()
	}
	proxyUser, proxyPassword := resolveProxyCredentials()
	if serverURL == "" {
		serverURL = "http://localhost:9000"
	}
	if envLabel == "" {
		envLabel = "Production"
	}
	return Config{
		ServerURL:     strings.TrimRight(serverURL, "/"),
		EnvLabel:      envLabel,
		AgentSecret:   agentSecret,
		ProxyUser:     proxyUser,
		ProxyPassword: proxyPassword,
	}
}

// resolveProxyCredentials returns the proxy credentials to use: BAS_PROXY_USER/
// BAS_PROXY_PASSWORD env vars first (matching AgentSecret's own documented
// override behavior -- operators can override without reinstalling), falling
// back to platform-secure storage. Shared by loadConfig (the running-agent
// path) and notifyServerUnenroll (the standalone --uninstall CLI path,
// which has no in-memory Config to read from) so the priority logic can't
// drift between the two.
func resolveProxyCredentials() (user, password string) {
	user = os.Getenv("BAS_PROXY_USER")
	password = os.Getenv("BAS_PROXY_PASSWORD")
	if user == "" && password == "" {
		user, password = readProxyCredentialsPlatform()
	}
	return user, password
}
