//go:build !windows

package main

// Stubs for non-Windows builds (the agent is Windows-only but these allow
// the module to be linted/checked on Linux/macOS toolchains).

func enablePrivileges()                        {}
func isElevated() bool                         { return true }
func selfElevate() error                       { return nil }
func isWindowsService() bool                   { return false }
func svcRun() error                            { return nil }
func svcInstall(_, _ string) error             { return nil }
func svcUninstall() error                      { return nil }
func svcUpdate() error                         { return nil }
func readServiceParams() (string, string)      { return "", "" }
func getWindowsVersion() string                { return "unknown" }
