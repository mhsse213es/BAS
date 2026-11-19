//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const systemSID = "S-1-5-18"

// currentUserSID is the SID of the account this process runs as.
func currentUserSID() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}

// settingsBackupPath is where the original values are recorded. It sits in the agent's own data folder, which the
// uninstall removes after restoring.
func settingsBackupPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "BASAgent", "system-settings.json")
}

// systemSettingTargets lists every value suppressSystemDialogs and its helpers change. For per-user values, the
// SYSTEM profile (where the service runs) is recorded as HKU:.DEFAULT so an uninstall run by an administrator
// restores the right hive and not the administrator's own.
func systemSettingTargets() []settingEntry {
	userRoot, owner := "HKCU", ""
	if sid, err := currentUserSID(); err == nil {
		owner = sid
		if sid == systemSID {
			userRoot, owner = "HKU:.DEFAULT", ""
		}
	}
	const wer = `Software\Microsoft\Windows\Windows Error Reporting`
	const ae = `Software\Microsoft\Windows NT\CurrentVersion\AeDebug`
	const pca = `Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`
	const desk = `Control Panel\Desktop`
	return []settingEntry{
		{Root: "HKLM", Key: wer, Name: "DontShowUI", Kind: "dword"},
		{Root: "HKLM", Key: wer, Name: "LoggingDisabled", Kind: "dword"},
		{Root: "HKLM", Key: ae, Name: "Auto", Kind: "string"},
		{Root: "HKLM", Key: pca, Name: "DisablePCA", Kind: "dword"},
		{Root: userRoot, Key: desk, Name: "AutoEndTasks", Kind: "string", Owner: owner},
		{Root: userRoot, Key: desk, Name: "HungAppTimeout", Kind: "string", Owner: owner},
		{Root: userRoot, Key: desk, Name: "WaitToKillAppTimeout", Kind: "string", Owner: owner},
	}
}

// registryStore is the real registry behind settingsStore.
type registryStore struct{}

func resolveRoot(e settingEntry) (registry.Key, string, error) {
	switch {
	case e.Root == "HKLM":
		return registry.LOCAL_MACHINE, e.Key, nil
	case e.Root == "HKU:.DEFAULT":
		return registry.USERS, `.DEFAULT\` + e.Key, nil
	case e.Root == "HKCU":
		sid, err := currentUserSID()
		if err != nil {
			return 0, "", err
		}
		if e.Owner != "" && !strings.EqualFold(e.Owner, sid) {
			return 0, "", fmt.Errorf("value belongs to another user profile (%s)", e.Owner)
		}
		return registry.CURRENT_USER, e.Key, nil
	}
	return 0, "", fmt.Errorf("unknown registry root %q", e.Root)
}

func (registryStore) read(e settingEntry) (settingEntry, error) {
	e.Existed, e.Dword, e.Str = false, 0, "" // report what is there now, not what the caller passed in
	root, key, err := resolveRoot(e)
	if err != nil {
		return e, err
	}
	k, err := registry.OpenKey(root, key, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return e, nil
		}
		return e, err
	}
	defer k.Close()
	switch e.Kind {
	case "dword":
		v, _, err := k.GetIntegerValue(e.Name)
		if err == nil {
			e.Existed, e.Dword = true, uint32(v)
		} else if !errors.Is(err, registry.ErrNotExist) {
			return e, err
		}
	default:
		v, _, err := k.GetStringValue(e.Name)
		if err == nil {
			e.Existed, e.Str = true, v
		} else if !errors.Is(err, registry.ErrNotExist) {
			return e, err
		}
	}
	return e, nil
}

func (registryStore) write(e settingEntry) error {
	root, key, err := resolveRoot(e)
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(root, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if e.Kind == "dword" {
		return k.SetDWordValue(e.Name, e.Dword)
	}
	return k.SetStringValue(e.Name, e.Str)
}

func (registryStore) remove(e settingEntry) error {
	root, key, err := resolveRoot(e)
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(root, key, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(e.Name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
