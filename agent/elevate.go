//go:build windows

package main

import (
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// selfElevate relaunches the current executable via ShellExecute with the
// "runas" verb, which triggers a UAC prompt requesting Administrator rights.
// Call this when isElevated() is false and running interactively (not as svc).
func selfElevate() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)

	var argPtr *uint16
	if args != "" {
		argPtr, _ = syscall.UTF16PtrFromString(args)
	}

	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shellExec := shell32.NewProc("ShellExecuteW")

	// SW_NORMAL = 1
	ret, _, _ := shellExec.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		1,
	)
	// ShellExecuteW returns > 32 on success
	if ret <= 32 {
		return windows.GetLastError()
	}
	return nil
}
