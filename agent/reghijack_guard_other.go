//go:build !windows

package main

// recoverPendingRestores is the Windows registry restore guard's start-up recovery; there is nothing to recover here.
func recoverPendingRestores() []string { return nil }
