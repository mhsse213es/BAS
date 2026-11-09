//go:build windows

package main

// Which registry hive "HKCU" means.
//
// The agent service runs as LocalSystem, and a test step runs as the logged-in user. The service's own
// HKEY_CURRENT_USER is SYSTEM's hive, so a guard or a health check that read it would watch the wrong registry and miss
// exactly the keys that break a person's folders, Run dialog and file types. This resolves the logged-in user's hive
// under HKEY_USERS instead. A process that already runs as a user keeps its own HKEY_CURRENT_USER.

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Variables so tests can stand in for the service identity and the logged-in user.
var (
	selfSIDFn       = realSelfSID
	activeUserSIDFn = realActiveUserSID
)

func realSelfSID() string {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return tu.User.Sid.String()
}

func realActiveUserSID() (string, bool) {
	tok, ok := activeUserToken()
	if !ok {
		return "", false
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", false
	}
	return tu.User.Sid.String(), true
}

// isServiceAccountSID reports whether sid is LocalSystem, LocalService or NetworkService: an identity with no person
// behind it, whose HKCU is not a customer's.
func isServiceAccountSID(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20"
}

var userHiveCache = struct {
	mu   sync.Mutex
	sid  string
	hive registry.Key
}{}

func resetUserHiveCache() {
	userHiveCache.mu.Lock()
	defer userHiveCache.mu.Unlock()
	if userHiveCache.hive != 0 {
		userHiveCache.hive.Close()
	}
	userHiveCache.sid, userHiveCache.hive = "", 0
}

// userHiveKey returns the registry key that stands for the person's HKCU: HKEY_CURRENT_USER for a process running as a
// user, the logged-in user's hive under HKEY_USERS for the service, and 0 (nothing to guard) when nobody is logged in.
func userHiveKey() registry.Key {
	self := selfSIDFn()
	if self != "" && !isServiceAccountSID(self) {
		return registry.CURRENT_USER
	}
	sid, ok := activeUserSIDFn()
	if !ok || sid == "" {
		return 0
	}
	userHiveCache.mu.Lock()
	defer userHiveCache.mu.Unlock()
	if userHiveCache.sid == sid && userHiveCache.hive != 0 {
		return userHiveCache.hive
	}
	if userHiveCache.hive != 0 {
		userHiveCache.hive.Close()
		userHiveCache.hive = 0
	}
	// ALL_ACCESS on the hive root is enough to open sub-keys with any right (the service is SYSTEM).
	k, err := registry.OpenKey(registry.USERS, sid, registry.READ)
	if err != nil {
		return 0
	}
	userHiveCache.sid, userHiveCache.hive = sid, k
	return k
}

// userHiveName is the text form of the user's hive root for command-line tools: "HKCU" for a user process, the
// "HKU\<sid>" path for the service, "" when nobody is logged in.
func userHiveName() string {
	self := selfSIDFn()
	if self != "" && !isServiceAccountSID(self) {
		return "HKCU"
	}
	if sid, ok := activeUserSIDFn(); ok && sid != "" {
		return `HKU\` + sid
	}
	return ""
}

// hkcuReg turns a path under HKCU into the text form `reg.exe` should be given: the logged-in user's hive when the
// agent is the service, "" (nothing to read) when nobody is logged in.
func hkcuReg(path string) string {
	h := userHiveName()
	if h == "" {
		return ""
	}
	return h + `\` + path
}

// userStartupDir is the logged-in user's Startup folder. The service's own %APPDATA% is SYSTEM's profile, so for the
// service it is read from the user's hive instead ("" when nobody is logged in).
func userStartupDir() string {
	self := selfSIDFn()
	if self != "" && !isServiceAccountSID(self) {
		return filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
	}
	hive := userHiveKey()
	if hive == 0 {
		return ""
	}
	k, err := registry.OpenKey(hive, `Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("Startup")
	return v
}
