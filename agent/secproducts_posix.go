//go:build !windows

package main

// enumerateSecurityProducts is Windows-only; non-Windows endpoints report no
// inventory (the report shows "not reported" rather than a false empty claim).
func enumerateSecurityProducts() []string { return nil }
