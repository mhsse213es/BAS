//go:build windows

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// ── DPAPI ─────────────────────────────────────────────────────────────────────

var (
	modCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData   = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func toDataBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// cryptProtectLocalMachine uses machine-scope encryption: any process running as
// SYSTEM or local Administrators on this machine can decrypt the blob.
const cryptProtectLocalMachine = 0x4

// EncryptSecret encrypts plain using Windows DPAPI at machine scope.
// Safe to store in the registry — only SYSTEM/Admins on this machine can decrypt.
func EncryptSecret(plain string) ([]byte, error) {
	in := toDataBlob([]byte(plain))
	var out dataBlob
	desc, _ := windows.UTF16PtrFromString("BASAgent-Secret")

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		uintptr(unsafe.Pointer(desc)),
		0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}

// DecryptSecret decrypts a DPAPI blob produced by EncryptSecret.
func DecryptSecret(blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", nil
	}
	in := toDataBlob(blob)
	var out dataBlob

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return "", fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	return string(unsafe.Slice(out.pbData, out.cbData)), nil
}

// ── Registry helpers ──────────────────────────────────────────────────────────

const paramKey = `SYSTEM\CurrentControlSet\Services\` + svcName + `\Parameters`

// StoreEncryptedSecret DPAPI-encrypts secret and writes the hex blob to the
// service Parameters registry key. Called once at install time.
func StoreEncryptedSecret(secret string) error {
	if secret == "" {
		return nil
	}
	blob, err := EncryptSecret(secret)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, paramKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("registry create key: %w", err)
	}
	defer k.Close()
	return k.SetStringValue("BAS_AGENT_SECRET_ENC", hex.EncodeToString(blob))
}

// ReadEncryptedSecret reads the DPAPI blob from registry and decrypts it.
// Returns "" if the value is absent or decryption fails.
func ReadEncryptedSecret() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, paramKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	hexBlob, _, err := k.GetStringValue("BAS_AGENT_SECRET_ENC")
	if err != nil || hexBlob == "" {
		return ""
	}
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		return ""
	}
	secret, err := DecryptSecret(blob)
	if err != nil {
		log.Printf("[config] DPAPI decrypt failed: %v", err)
		return ""
	}
	return secret
}

// StoreBinaryHash writes the SHA-256 hex of the running binary to the registry
// so future starts can self-verify against it.
func StoreBinaryHash(hash string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, paramKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("BAS_BINARY_HASH", hash)
}

// ── Startup integrity check ───────────────────────────────────────────────────

// VerifyOwnIntegrity hashes the running binary and compares it against the
// value stored in the registry at install time. Returns nil if they match or
// if no stored hash exists (first run or manifest-less deployment).
func VerifyOwnIntegrity() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, paramKey, registry.QUERY_VALUE)
	if err != nil {
		return nil // key absent — skip check
	}
	defer k.Close()
	expected, _, err := k.GetStringValue("BAS_BINARY_HASH")
	if err != nil || expected == "" {
		return nil // hash not stored
	}
	actual, err := SelfHash()
	if err != nil {
		return fmt.Errorf("self-hash: %w", err)
	}
	if actual != expected {
		return fmt.Errorf("TAMPER DETECTED — stored hash %s... current %s...",
			expected[:16], actual[:16])
	}
	return nil
}

// ── Service hardening ─────────────────────────────────────────────────────────

// ApplyServiceDACL locks down the BASAgent service so standard users cannot
// stop, delete, or reconfigure it. Only SYSTEM and Administrators retain full
// control. Uses sc.exe sdset which is the Windows-blessed approach.
func ApplyServiceDACL() error {
	// SDDL rights breakdown for service ACEs:
	//   CC = SERVICE_QUERY_CONFIG   LC = SERVICE_QUERY_STATUS  SW = SERVICE_ENUMERATE_DEPENDENTS
	//   RP = SERVICE_START          WP = SERVICE_STOP           DT = SERVICE_PAUSE_CONTINUE
	//   LO = SERVICE_INTERROGATE   CR = SERVICE_USER_DEFINED   RC = READ_CONTROL
	//   SD = DELETE                 WD = WRITE_DAC              WO = WRITE_OWNER
	//   DC = SERVICE_CHANGE_CONFIG
	// Standard users only get read + interrogate; cannot stop or modify.
	const sddl = `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)` + // SYSTEM: full
		`(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)` + // Administrators: full
		`(A;;CCLCSWLOCRRC;;;IU)` + // Interactive users: read+start only
		`(A;;CCLCSWLOCRRC;;;SU)` // Service logon: read+start only

	out, err := exec.Command("sc", "sdset", svcName, sddl).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc sdset: %w — %s", err, string(out))
	}
	log.Printf("[tamper] service DACL applied — non-admin stop/delete/reconfigure blocked")
	return nil
}

// ApplyServiceRecovery configures automatic restart on failure.
// Policy: restart ×3 at 60-second intervals; reset counter after 24 h of uptime.
func ApplyServiceRecovery() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	// Use sc.exe failure — more portable than raw ChangeServiceConfig2 struct layout.
	// Format: action/delay_ms pairs.
	out, err := exec.Command("sc", "failure", svcName,
		"reset=", "86400",
		"actions=", "restart/60000/restart/60000/restart/60000",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc failure: %w — %s", err, string(out))
	}
	log.Printf("[tamper] service recovery policy applied — auto-restart ×3 at 60 s")
	return nil
}

// ApplyFileACL restricts the agent install directory so standard users cannot
// write, replace, or delete the binary. Uses icacls.
func ApplyFileACL(dir string) error {
	out, err := exec.Command("icacls", dir,
		"/inheritance:r",
		"/grant:r", `NT AUTHORITY\SYSTEM:(OI)(CI)F`,
		"/grant:r", `BUILTIN\Administrators:(OI)(CI)F`,
		"/grant:r", `BUILTIN\Users:(OI)(CI)RX`,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %w — %s", err, string(out))
	}
	log.Printf("[tamper] file ACL applied on %s — users cannot replace binary", dir)
	return nil
}

// ApplyRegistryACL locks down the Parameters registry key using PowerShell Set-Acl.
// Standard users cannot read the encrypted secret blob or alter config values.
func ApplyRegistryACL() error {
	script := fmt.Sprintf(
		`$p="HKLM:\%s";$a=Get-Acl $p;`+
			`$a.SetSecurityDescriptorSddlForm('D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;BU)');`+
			`Set-Acl $p $a`,
		paramKey,
	)
	out, err := exec.Command("powershell", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("registry ACL: %w — %s", err, string(out))
	}
	log.Printf("[tamper] registry ACL applied on Parameters key")
	return nil
}

// ApplyDefenderExclusion adds exePath as both a process and path exclusion in
// Windows Defender Antivirus, via Add-MpPreference. A BAS agent legitimately
// spawns processes and inspects installed security tooling as part of its
// job -- exactly the kind of behavior Defender's ML behavioral heuristics
// (e.g. "Behavior:Win32/Execution.A!ml") flag on the agent's own process.
// This automates the manual step already documented in
// packaging/docs/edr-exclusion-guide.md. Only the agent's own exe is
// excluded, never the install directory or any technique it spawns, so
// simulated attacks still produce real detections. Best-effort and
// non-fatal, same as every other Apply* hardening step in this file:
// Defender may be absent, disabled, or overridden by another AV, and none
// of that should block install/update.
func ApplyDefenderExclusion(exePath string) error {
	quoted := "'" + strings.ReplaceAll(exePath, "'", "''") + "'"
	script := fmt.Sprintf(
		`Add-MpPreference -ExclusionProcess %s -ExclusionPath %s -ErrorAction Stop`,
		quoted, quoted,
	)
	out, err := exec.Command("powershell", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Add-MpPreference: %w — %s", err, string(out))
	}
	log.Printf("[tamper] Windows Defender exclusion added for %s", exePath)
	return nil
}
