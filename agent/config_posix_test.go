//go:build linux || darwin

package main

import "testing"

// clearAgentEnv removes the three variables systemd/launchd would normally
// supply, so the test exercises the file-fallback path a manual run takes.
func clearAgentEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"BAS_SERVER_URL", "BAS_ENV_LABEL", "BAS_AGENT_SECRET"} {
		t.Setenv(k, "")
	}
}

// stubServiceSecret replaces the service-config secret reader for one test.
func stubServiceSecret(t *testing.T, secret string) {
	t.Helper()
	prev := posixReadAgentSecret
	posixReadAgentSecret = func() string { return secret }
	t.Cleanup(func() { posixReadAgentSecret = prev })
}

// The secret must fall back to the service config file, exactly as the server
// URL and env label already do.
//
// Without this, running the agent by hand — rather than under systemd/launchd,
// which supply the values via EnvironmentFile= — produced a config with the
// right server URL and NO secret. Every request then failed 401 and the
// WebSocket upgrade failed with "bad handshake", while the banner printed a
// correct Server: line, making it look like a server or auth fault rather than
// a missing environment variable. Windows never had this: it falls back to the
// DPAPI-encrypted registry value.
func TestLoadConfig_ReadsSecretFromServiceConfigWhenEnvUnset(t *testing.T) {
	clearAgentEnv(t)
	stubServiceSecret(t, "s3cr3t-from-file")

	if got := loadConfig().AgentSecret; got != "s3cr3t-from-file" {
		t.Errorf("AgentSecret = %q, want the value from the service config — a manual run 401s without it", got)
	}
}

// The environment must still win, so an operator can override without
// reinstalling — the same precedence the URL and label already have.
func TestLoadConfig_EnvSecretBeatsServiceConfig(t *testing.T) {
	clearAgentEnv(t)
	stubServiceSecret(t, "from-file")
	t.Setenv("BAS_AGENT_SECRET", "from-env")

	if got := loadConfig().AgentSecret; got != "from-env" {
		t.Errorf("AgentSecret = %q, want the environment value to take precedence", got)
	}
}

// A missing or unreadable config must not invent a secret. Empty is the honest
// result, and the 401 it causes is a true report of "this agent has no
// credentials" rather than a silent half-working state.
func TestLoadConfig_NoServiceConfigYieldsEmptySecret(t *testing.T) {
	clearAgentEnv(t)
	stubServiceSecret(t, "")

	if got := loadConfig().AgentSecret; got != "" {
		t.Errorf("AgentSecret = %q, want empty when there is no config to read", got)
	}
}

func TestLoadConfig_ProxyCredentials_EnvVarTakesPriority(t *testing.T) {
	t.Setenv("BAS_PROXY_USER", "env-user")
	t.Setenv("BAS_PROXY_PASSWORD", "env-pass")
	orig := posixReadProxyCredentials
	posixReadProxyCredentials = func() (string, string) { return "file-user", "file-pass" }
	defer func() { posixReadProxyCredentials = orig }()

	cfg := loadConfig()
	if cfg.ProxyUser != "env-user" || cfg.ProxyPassword != "env-pass" {
		t.Errorf("ProxyUser/ProxyPassword = %q/%q, want env-user/env-pass (env var must win)", cfg.ProxyUser, cfg.ProxyPassword)
	}
}

func TestLoadConfig_ProxyCredentials_FallsBackToPlatformWhenEnvAbsent(t *testing.T) {
	t.Setenv("BAS_PROXY_USER", "")
	t.Setenv("BAS_PROXY_PASSWORD", "")
	orig := posixReadProxyCredentials
	posixReadProxyCredentials = func() (string, string) { return "file-user", "file-pass" }
	defer func() { posixReadProxyCredentials = orig }()

	cfg := loadConfig()
	if cfg.ProxyUser != "file-user" || cfg.ProxyPassword != "file-pass" {
		t.Errorf("ProxyUser/ProxyPassword = %q/%q, want file-user/file-pass (fallback)", cfg.ProxyUser, cfg.ProxyPassword)
	}
}
