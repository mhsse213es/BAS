//go:build linux || darwin

package main

func registerPlatformFlags()               {}
func platformHandleFlags() bool            { return false }
func platformPreStart()                    {}
func platformPrintBannerExtras(_ Identity) {}

// readEncryptedSecretPlatform is a no-op on non-Windows — secrets are read
// from BAS_AGENT_SECRET env var or the system service config instead.
func readEncryptedSecretPlatform() string { return "" }
