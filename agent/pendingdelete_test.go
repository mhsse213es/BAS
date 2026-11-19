package main

import (
	"reflect"
	"testing"
)

func TestPendingEntryPath_StripsTheFlagAndNativePrefixes(t *testing.T) {
	for in, want := range map[string]string{
		`*1\??\C:\Program Files\BASAgent\bas_agent.exe`: `C:\Program Files\BASAgent\bas_agent.exe`,
		`\??\C:\x\y.exe`:  `C:\x\y.exe`,
		`!\??\C:\x\y.exe`: `C:\x\y.exe`,
		`C:\plain.exe`:    `C:\plain.exe`,
	} {
		if got := pendingEntryPath(in); got != want {
			t.Errorf("pendingEntryPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDropPendingDeletes_RemovesOnlyTheDeleteOrderForThatPath(t *testing.T) {
	exe := `C:\Program Files\BASAgent\bas_agent.exe`
	in := []string{
		`*1\??\C:\Users\x\AppData\Local\Temp\other.tmp`, ``,
		`*1\??\C:\PROGRAM FILES\basagent\BAS_AGENT.EXE`, ``, // same file, different case
		`\??\C:\Windows\keep.dll`, `\??\C:\Windows\keep.new`, // a rename, not ours
	}
	kept, dropped := dropPendingDeletes(in, exe)
	want := []string{`*1\??\C:\Users\x\AppData\Local\Temp\other.tmp`, ``, `\??\C:\Windows\keep.dll`, `\??\C:\Windows\keep.new`}
	if dropped != 1 || !reflect.DeepEqual(kept, want) {
		t.Errorf("dropped=%d kept=%q, want 1 and %q", dropped, kept, want)
	}
}

func TestDropPendingDeletes_ARenameOfThePathIsNotADeleteAndStays(t *testing.T) {
	exe := `C:\a\b.exe`
	in := []string{`\??\C:\a\b.exe`, `\??\C:\a\b.new`}
	kept, dropped := dropPendingDeletes(in, exe)
	if dropped != 0 || !reflect.DeepEqual(kept, in) {
		t.Errorf("dropped=%d kept=%q: a pending rename of the file must be left alone", dropped, kept)
	}
}

func TestDropPendingDeletes_NothingToDropOrAMalformedListIsReturnedUntouched(t *testing.T) {
	in := []string{`*1\??\C:\other.tmp`, ``}
	if kept, dropped := dropPendingDeletes(in, `C:\a\b.exe`); dropped != 0 || !reflect.DeepEqual(kept, in) {
		t.Errorf("dropped=%d kept=%q", dropped, kept)
	}
	odd := []string{`*1\??\C:\a\b.exe`, ``, `dangling`}
	if kept, dropped := dropPendingDeletes(odd, `C:\a\b.exe`); dropped != 0 || !reflect.DeepEqual(kept, odd) {
		t.Errorf("a list with an odd number of entries is not a list of pairs and must not be edited: dropped=%d", dropped)
	}
	if kept, dropped := dropPendingDeletes(nil, `C:\a\b.exe`); dropped != 0 || len(kept) != 0 {
		t.Errorf("dropped=%d kept=%q", dropped, kept)
	}
}

func TestScheduleExeDelete_TheMSIOwnsItsFileSoNothingIsScheduled(t *testing.T) {
	called := false
	scheduled, err := scheduleExeDelete(`C:\Program Files\BASAgent\bas_agent.exe`, true, func(string) error { called = true; return nil })
	if err != nil || scheduled || called {
		t.Errorf("scheduled=%v called=%v err=%v: an MSI uninstall removes the file itself; a delete order left behind would remove the NEXT install", scheduled, called, err)
	}
}

func TestScheduleExeDelete_AnAgentNotInstalledFromTheMSIStillSchedulesItsOwnDelete(t *testing.T) {
	var got string
	scheduled, err := scheduleExeDelete(`C:\BAS\bas_agent.exe`, false, func(p string) error { got = p; return nil })
	if err != nil || !scheduled || got != `C:\BAS\bas_agent.exe` {
		t.Errorf("scheduled=%v got=%q err=%v", scheduled, got, err)
	}
}

// A data file that was in use at uninstall time is deleted at the next restart; if the agent is reinstalled
// before then, that order would wipe the new install's certificates. Orders for anything inside the agent's own
// folders are cancelled together with the one for the executable.
func TestDropPendingDeletes_AlsoCancelsOrdersForFilesInsideTheAgentsFolders(t *testing.T) {
	in := []string{
		`*1\??\C:\ProgramData\Audspect\certs\agent-key.pem`, ``,
		`*1\??\C:\ProgramData\Audspect\certs`, ``,
		`*1\??\C:\ProgramData\Audspect\certs-old-by-an-admin\agent-key.pem`, ``, // a different folder with a similar name
		`*1\??\C:\ProgramData\Other\x.tmp`, ``,
	}
	kept, dropped := dropPendingDeletes(in, `C:\ProgramData\Audspect\certs`)
	if dropped != 2 {
		t.Errorf("dropped = %d, want the folder's file and the folder itself", dropped)
	}
	want := []string{`*1\??\C:\ProgramData\Audspect\certs-old-by-an-admin\agent-key.pem`, ``, `*1\??\C:\ProgramData\Other\x.tmp`, ``}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %q, want %q (a sibling folder with a similar name must not match)", kept, want)
	}
}

func TestRemovedByMSI_IsTrueOnlyWhenTheInstallerSaysSo(t *testing.T) {
	t.Setenv(msiRemovingEnv, "")
	if removedByMSI() {
		t.Error("not set: the agent is not being removed by the MSI")
	}
	t.Setenv(msiRemovingEnv, "1")
	if !removedByMSI() {
		t.Error("set to 1 by the MSI's uninstall action")
	}
}
