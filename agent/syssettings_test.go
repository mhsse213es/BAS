package main

import (
	"errors"
	"path/filepath"
	"testing"
)

// fakeSettings is an in-memory stand-in for the registry.
type fakeSettings struct {
	vals    map[string]settingEntry
	failOn  string
	removed []string
}

func key(e settingEntry) string { return e.Root + `\` + e.Key + `\` + e.Name }

func (f *fakeSettings) read(e settingEntry) (settingEntry, error) {
	if v, ok := f.vals[key(e)]; ok {
		e.Existed, e.Dword, e.Str = true, v.Dword, v.Str
	}
	return e, nil
}
func (f *fakeSettings) write(e settingEntry) error {
	if f.failOn == key(e) {
		return errors.New("access denied")
	}
	e.Existed = true
	f.vals[key(e)] = e
	return nil
}
func (f *fakeSettings) remove(e settingEntry) error {
	f.removed = append(f.removed, key(e))
	delete(f.vals, key(e))
	return nil
}

var testTargets = []settingEntry{
	{Root: "HKLM", Key: `Software\Microsoft\Windows\Windows Error Reporting`, Name: "DontShowUI", Kind: "dword"},
	{Root: "HKLM", Key: `Software\Microsoft\Windows NT\CurrentVersion\AeDebug`, Name: "Auto", Kind: "string"},
	{Root: "HKLM", Key: `Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`, Name: "DisablePCA", Kind: "dword"},
}

func TestSettings_TheOriginalValuesAreRecordedBeforeAnythingChanges(t *testing.T) {
	f := &fakeSettings{vals: map[string]settingEntry{
		key(testTargets[0]): {Dword: 1}, // an admin had already set DontShowUI=1
		key(testTargets[1]): {Str: "0"}, // AeDebug Auto present
	}}
	saved := captureSettings(f, testTargets)
	if len(saved) != 3 {
		t.Fatalf("saved %d entries, want 3", len(saved))
	}
	if !saved[0].Existed || saved[0].Dword != 1 {
		t.Errorf("DontShowUI = %+v, want the admin's existing value 1", saved[0])
	}
	if saved[2].Existed {
		t.Errorf("DisablePCA = %+v, want recorded as absent", saved[2])
	}
}

func TestSettings_RestoreBringsBackExactlyWhatWasThereAndRemovesWhatWasNot(t *testing.T) {
	f := &fakeSettings{vals: map[string]settingEntry{
		key(testTargets[0]): {Dword: 1},
		key(testTargets[1]): {Str: "0"},
	}}
	saved := captureSettings(f, testTargets)
	// the agent applies its suppression
	f.vals[key(testTargets[0])] = settingEntry{Dword: 1}
	f.vals[key(testTargets[1])] = settingEntry{Str: "1"}
	f.vals[key(testTargets[2])] = settingEntry{Dword: 1}

	if failed := restoreSettings(f, saved); len(failed) != 0 {
		t.Fatalf("restore failed on %v", failed)
	}
	if got := f.vals[key(testTargets[0])]; got.Dword != 1 {
		t.Errorf("DontShowUI = %d, want the original 1 (not a made-up default)", got.Dword)
	}
	if got := f.vals[key(testTargets[1])]; got.Str != "0" {
		t.Errorf("Auto = %q, want the original \"0\"", got.Str)
	}
	if _, still := f.vals[key(testTargets[2])]; still {
		t.Error("DisablePCA did not exist before the agent, so no trace of it may remain")
	}
}

func TestSettings_AFailedRestoreIsReportedNotSwallowed(t *testing.T) {
	f := &fakeSettings{vals: map[string]settingEntry{key(testTargets[0]): {Dword: 1}}}
	saved := captureSettings(f, testTargets)
	f.failOn = key(testTargets[0])
	failed := restoreSettings(f, saved)
	if len(failed) != 1 || failed[0] != key(testTargets[0]) {
		t.Errorf("failed = %v, want the one setting that could not be put back", failed)
	}
}

func TestSettings_TheBackupIsWrittenOnceAndNeverOverwrittenWithTheAgentsOwnChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system-settings.json")
	f := &fakeSettings{vals: map[string]settingEntry{key(testTargets[0]): {Dword: 1}}}
	if err := ensureSettingsBackup(path, f, testTargets); err != nil {
		t.Fatal(err)
	}
	// the agent runs and changes things, then restarts (crash) without a clean shutdown
	f.vals[key(testTargets[0])] = settingEntry{Dword: 9}
	if err := ensureSettingsBackup(path, f, testTargets); err != nil {
		t.Fatal(err)
	}
	saved, ok, err := loadSettingsBackup(path)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if saved[0].Dword != 1 {
		t.Errorf("backup holds %d, want the true original 1, not the agent's own change", saved[0].Dword)
	}
}

func TestSettings_NoBackupMeansNothingToRestore(t *testing.T) {
	_, ok, err := loadSettingsBackup(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil || ok {
		t.Errorf("ok=%v err=%v, want no backup and no error", ok, err)
	}
}

func TestSettings_RestoreFromBackupFileRemovesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system-settings.json")
	f := &fakeSettings{vals: map[string]settingEntry{key(testTargets[0]): {Dword: 1}}}
	if err := ensureSettingsBackup(path, f, testTargets); err != nil {
		t.Fatal(err)
	}
	f.vals[key(testTargets[2])] = settingEntry{Dword: 1}
	restored, failed := restoreSettingsFromBackup(path, f)
	if !restored || len(failed) != 0 {
		t.Fatalf("restored=%v failed=%v", restored, failed)
	}
	if _, still := f.vals[key(testTargets[2])]; still {
		t.Error("DisablePCA should be gone")
	}
	if _, ok, _ := loadSettingsBackup(path); ok {
		t.Error("the backup file is itself a trace and must be removed after a successful restore")
	}
}
