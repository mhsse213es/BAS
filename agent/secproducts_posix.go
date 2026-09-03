//go:build !windows && !linux

package main

// enumerateSecurityProducts has real implementations on Windows
// (secproducts_windows.go) and Linux (secproducts_linux.go). Remaining
// platforms -- macOS today -- report no inventory, and the report shows "not
// reported" rather than a false empty claim.
func enumerateSecurityProducts() (products []string, diag []string) { return nil, nil }
