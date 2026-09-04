//go:build !windows && !linux && !darwin

package main

// enumerateSecurityProducts has real implementations on Windows
// (secproducts_windows.go), Linux (secproducts_linux.go) and macOS
// (secproducts_darwin.go). Any remaining platform reports no inventory, and the
// report shows "not reported" rather than a false empty claim.
func enumerateSecurityProducts() (products []string, diag []string) { return nil, nil }
