//go:build linux || darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// disableEcho turns terminal echo off and returns a function that restores the previous settings; nil if
// stdin is not a terminal.
func disableEcho(f *os.File) func() {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
		return nil
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }
}
