//go:build linux || darwin

package main

func registerPlatformFlags()               {}
func platformHandleFlags() bool            { return false }
func platformPreStart()                    {}
func platformPrintBannerExtras(_ Identity) {}

// posixReadAgentSecret reads BAS_AGENT_SECRET from the installed service config
// (see readAgentSecret in service_linux.go / service_darwin.go). Indirected so
// tests can supply a value without touching /etc.
var posixReadAgentSecret = readAgentSecret

// readEncryptedSecretPlatform supplies the agent secret when BAS_AGENT_SECRET is
// absent from the environment. There is nothing encrypted about it on POSIX —
// the name matches the Windows counterpart, which reads a DPAPI-encrypted
// registry value — but the FALLBACK matters:
//
// systemd and launchd inject the secret from the service config via
// EnvironmentFile=, so a service-managed agent always has it. An agent started
// by hand does not. loadConfig already falls back to that same file for
// BAS_SERVER_URL and BAS_ENV_LABEL, so without this the manual run got a
// correct server URL and no credentials: every request 401'd and the WebSocket
// upgrade failed with "bad handshake", while the banner showed a correct
// Server: line and made it look like a server fault.
func readEncryptedSecretPlatform() string { return posixReadAgentSecret() }

// platformRestoreOnShutdown is a no-op on non-Windows.
func platformRestoreOnShutdown() {}
