//go:build !windows

package main

// applyTrayPolicy: only the Windows agent has a tray icon. Linux and macOS agents are headless, so the server's
// tray-visibility policy has nothing to apply there.
func applyTrayPolicy(bool) {}
