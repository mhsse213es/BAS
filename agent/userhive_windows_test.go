//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// The agent service runs as LocalSystem, so its HKCU is SYSTEM's own hive, not the registry of the person whose
// folders, Run dialog and file types a test can break. These tests pin which hive "HKCU" means.

func stubSIDs(t *testing.T, self string, active string, haveActive bool) {
	t.Helper()
	oldSelf, oldActive := selfSIDFn, activeUserSIDFn
	selfSIDFn = func() string { return self }
	activeUserSIDFn = func() (string, bool) { return active, haveActive }
	resetUserHiveCache()
	t.Cleanup(func() { selfSIDFn, activeUserSIDFn = oldSelf, oldActive; resetUserHiveCache() })
}

func TestUserHive_AProcessRunningAsAUserUsesItsOwnHKCU(t *testing.T) {
	own := realSelfSID()
	stubSIDs(t, own, "S-1-5-21-0-0-0-9999", true) // an "active user" must be ignored: this process IS a user
	if got := userHiveKey(); got != registry.CURRENT_USER {
		t.Fatalf("a user process must use HKEY_CURRENT_USER, got %v", got)
	}
}

func TestUserHive_TheServiceUsesTheLoggedInUsersHive(t *testing.T) {
	own := realSelfSID() // this test user stands in for "the logged-in user" and has a loaded hive under HKEY_USERS
	stubSIDs(t, "S-1-5-18", own, true)
	got := userHiveKey()
	if got == registry.CURRENT_USER || got == 0 {
		t.Fatalf("the service must open the active user's hive under HKEY_USERS, got %v", got)
	}
	// a key written through the real HKCU is visible through the service's view of that user
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\.audspectuserhive`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	defer registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\.audspectuserhive`)
	v, err := registry.OpenKey(got, `Software\Classes\.audspectuserhive`, registry.READ)
	if err != nil {
		t.Fatalf("the service's view of the user's hive must see the user's keys: %v", err)
	}
	v.Close()
}

func TestUserHive_TheServiceWithNobodyLoggedInHasNoHiveAndSoTouchesNothing(t *testing.T) {
	stubSIDs(t, "S-1-5-18", "", false)
	if got := userHiveKey(); got != 0 {
		t.Fatalf("with no user logged in there is no hive to guard (and SYSTEM's own must not be mistaken for it), got %v", got)
	}
	r := guardRoot{"HKCU", `Software\Classes\Folder`}
	if st := captureRoot(r); st.Exists {
		t.Fatal("a root under no hive must not look like it exists")
	}
}

func TestUserHive_GuardRootsUnderHKCUFollowTheActiveUser(t *testing.T) {
	own := realSelfSID()
	stubSIDs(t, "S-1-5-18", own, true)
	r := guardRoot{"HKCU", `Software\Classes\.audspectuserhive2`}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, r.Path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	defer registry.DeleteKey(registry.CURRENT_USER, r.Path)
	if !captureRoot(r).Exists {
		t.Fatal("the guard, running as the service, must see the logged-in user's HKCU keys")
	}
}

func TestUserHive_RunKeyPathsAndStartupFolderFollowTheLoggedInUser(t *testing.T) {
	own := realSelfSID()
	stubSIDs(t, "S-1-5-18", own, true)
	if got, want := hkcuReg(`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`), `HKU\`+own+`\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`; got != want {
		t.Errorf("service view of the Run key = %q, want %q", got, want)
	}
	want := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
	if got := userStartupDir(); !strings.EqualFold(got, want) {
		t.Errorf("the logged-in user's Startup folder = %q, want %q", got, want)
	}
	stubSIDs(t, "S-1-5-18", "", false)
	if hkcuReg(`X`) != "" || userStartupDir() != "" {
		t.Error("with nobody logged in there is nothing to read: both must be empty, never SYSTEM's own")
	}
	stubSIDs(t, own, "", false)
	if got := hkcuReg(`X`); got != `HKCU\X` {
		t.Errorf("a user process uses HKCU, got %q", got)
	}
}
