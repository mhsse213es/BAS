//go:build !windows

package main

func inhibitScreenTimeout() {}
func restoreScreenTimeout()  {}
