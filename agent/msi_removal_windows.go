//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// msiProductCodeKey is written by the MSI (see packaging/windows-msi/Package.wxs).
const msiProductCodeKey = `Software\Audspect\Agent`

// readMSIProductCode returns the product code of the installed MSI, if this agent was installed
// from one. An agent installed by the legacy setup has no such value.
func readMSIProductCode() (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, msiProductCodeKey, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	code, _, err := k.GetStringValue("ProductCode")
	if err != nil || !validMSIProductCode(code) {
		return "", false
	}
	return code, true
}

// startMSIRemoval launches the detached, delayed `msiexec /x`. It returns once the process is
// started; the removal itself completes after this service has stopped.
func startMSIRemoval(productCode string) error {
	args, err := msiRemovalCommand(productCode)
	if err != nil {
		return err
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start msiexec removal: %w", err)
	}
	_ = cmd.Process.Release()
	return nil
}
