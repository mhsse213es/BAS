//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// disableEcho turns console echo off and returns a function that restores the previous mode; nil if stdin is
// not a console.
func disableEcho(f *os.File) func() {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }
}
