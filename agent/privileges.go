//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows"
)

// agentPrivileges are enabled on startup so all BAS checks have
// the access they need regardless of how the agent was launched.
var agentPrivileges = []string{
	"SeDebugPrivilege",                // process memory access — LSASS dump detection, module inspection
	"SeSecurityPrivilege",             // auditpol read, security event log size queries
	"SeBackupPrivilege",               // read files/registry ignoring ACLs
	"SeRestorePrivilege",              // write access ignoring ACLs
	"SeTakeOwnershipPrivilege",        // take ownership of arbitrary objects
	"SeLoadDriverPrivilege",           // driver load/unload checks
	"SeSystemEnvironmentPrivilege",    // firmware/UEFI variable access
	"SeImpersonatePrivilege",          // impersonate tokens for context checks
	"SeManageVolumePrivilege",         // VSS / BitLocker volume queries
	"SeIncreaseBasePriorityPrivilege", // real-time priority for time-sensitive checks
	"SeCreateSymbolicLinkPrivilege",   // symlink-based path checks
	"SeShutdownPrivilege",             // shutdown/reboot policy verification
}

// enablePrivileges enables every privilege in agentPrivileges on the current
// process token. Privileges not held by the token (e.g. SeTcbPrivilege when
// running as admin rather than SYSTEM) are logged but not fatal — the agent
// works with whatever subset is available.
func enablePrivileges() {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	); err != nil {
		log.Printf("[priv] OpenProcessToken failed: %v — checks may have limited access", err)
		return
	}
	defer token.Close()

	ok, fail := 0, 0
	for _, name := range agentPrivileges {
		if err := setPrivilege(token, name, true); err != nil {
			log.Printf("[priv] %-42s UNAVAILABLE (%v)", name, err)
			fail++
		} else {
			log.Printf("[priv] %-42s ENABLED", name)
			ok++
		}
	}
	log.Printf("[priv] %d/%d privileges enabled (remaining require SYSTEM)", ok, len(agentPrivileges))
}

func setPrivilege(token windows.Token, name string, enable bool) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return err
	}
	attr := uint32(0)
	if enable {
		attr = windows.SE_PRIVILEGE_ENABLED
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: attr}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// isElevated reports whether the current process token has a high integrity
// level (i.e. running as admin or SYSTEM).
func isElevated() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}
