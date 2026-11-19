package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Machine-wide Windows settings the agent changes while it runs (crash dialogs, hung-app timeouts, the
// compatibility assistant) are recorded the first time, before anything is changed, and put back exactly: a value
// that was not there is removed, one that was is written back as it was. Restoring to made-up "defaults" would
// overwrite an administrator's own choice, and a service that is killed instead of stopped would never restore at
// all, so the record lives in a file the uninstall can read.

// settingEntry is one registry value: where it is, what kind it is, and what it held before the agent.
type settingEntry struct {
	Root    string `json:"root"` // "HKLM", "HKCU", or "HKU:.DEFAULT" for the SYSTEM profile
	Key     string `json:"key"`
	Name    string `json:"name"`
	Kind    string `json:"kind"` // "dword" or "string"
	Owner   string `json:"owner,omitempty"`
	Existed bool   `json:"existed"`
	Dword   uint32 `json:"dword,omitempty"`
	Str     string `json:"str,omitempty"`
}

// settingsStore is the registry as the capture and restore code sees it.
type settingsStore interface {
	read(e settingEntry) (settingEntry, error) // returns e filled with what is there now (Existed false if absent)
	write(e settingEntry) error
	remove(e settingEntry) error
}

// captureSettings records what each target holds now.
func captureSettings(s settingsStore, targets []settingEntry) []settingEntry {
	out := make([]settingEntry, 0, len(targets))
	for _, t := range targets {
		cur, err := s.read(t)
		if err != nil {
			cur = t // unreadable: record as absent so a restore never invents a value
			cur.Existed = false
		}
		out = append(out, cur)
	}
	return out
}

// restoreSettings puts every recorded value back. It returns the settings it could not restore.
func restoreSettings(s settingsStore, saved []settingEntry) (failed []string) {
	for _, e := range saved {
		var err error
		if e.Existed {
			err = s.write(e)
		} else {
			err = s.remove(e)
		}
		if err != nil {
			failed = append(failed, e.Root+`\`+e.Key+`\`+e.Name)
		}
	}
	return failed
}

func saveSettingsBackup(path string, saved []settingEntry) error {
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// loadSettingsBackup returns (nil, false, nil) when there is no backup.
func loadSettingsBackup(path string) ([]settingEntry, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var saved []settingEntry
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, false, err
	}
	return saved, true, nil
}

// ensureSettingsBackup records the originals once. If a backup already exists it is left alone: after a crash the
// values in the registry are the agent's own, and recording them would lose the true originals.
func ensureSettingsBackup(path string, s settingsStore, targets []settingEntry) error {
	if _, ok, err := loadSettingsBackup(path); err == nil && ok {
		return nil
	}
	return saveSettingsBackup(path, captureSettings(s, targets))
}

// restoreSettingsFromBackup restores from the file and, when everything went back, deletes the file. It reports
// whether a backup existed and which settings could not be restored.
func restoreSettingsFromBackup(path string, s settingsStore) (restored bool, failed []string) {
	saved, ok, err := loadSettingsBackup(path)
	if err != nil || !ok {
		return false, nil
	}
	failed = restoreSettings(s, saved)
	if len(failed) == 0 {
		_ = os.Remove(path)
	}
	return true, failed
}
