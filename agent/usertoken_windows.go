//go:build windows

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// userTokenCache holds the last resolved interactive user token so every step
// in a run does not pay the WTS enumeration cost.
var userTokenCache struct {
	mu      sync.Mutex
	token   windows.Token
	fetchAt time.Time
}

const userTokenTTL = 30 * time.Second

// activeUserToken returns the primary token of the first active interactive
// user session on this machine. The agent (running as SYSTEM) can then call
// CreateProcessAsUser with this token to execute steps as the logged-in user.
//
// Returns (token, true) on success; (0, false) if no interactive session
// exists (headless server, locked screen, no user logged in). The caller owns
// the returned token and must close it when done.
//
// SeImpersonatePrivilege must be held by the calling process — the agent
// enables this at startup in privileges.go.
func activeUserToken() (windows.Token, bool) {
	userTokenCache.mu.Lock()
	defer userTokenCache.mu.Unlock()

	if userTokenCache.token != 0 && time.Since(userTokenCache.fetchAt) < userTokenTTL {
		// Duplicate the cached token so each caller gets an independent handle.
		var dup windows.Token
		if err := windows.DuplicateTokenEx(
			userTokenCache.token,
			windows.TOKEN_ALL_ACCESS,
			nil,
			windows.SecurityImpersonation,
			windows.TokenPrimary,
			&dup,
		); err == nil {
			return dup, true
		}
		// Cache token went stale (session ended) — fall through and re-resolve.
		_ = userTokenCache.token.Close()
		userTokenCache.token = 0
	}

	tok, ok := resolveInteractiveUserToken()
	if !ok {
		return 0, false
	}

	// Cache a copy; return a duplicate to the caller.
	var cached windows.Token
	if err := windows.DuplicateTokenEx(
		tok,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&cached,
	); err == nil {
		userTokenCache.token = cached
		userTokenCache.fetchAt = time.Now()
	}

	return tok, true
}

// resolveInteractiveUserToken enumerates WTS sessions and returns the primary
// token for the first active (WTSActive) interactive session. The returned
// token is a primary token suitable for CreateProcessAsUser.
func resolveInteractiveUserToken() (windows.Token, bool) {
	wtsapi32 := windows.NewLazyDLL("wtsapi32.dll")
	enumSessions := wtsapi32.NewProc("WTSEnumerateSessionsW")
	queryUserToken := wtsapi32.NewProc("WTSQueryUserToken")
	freeMem := wtsapi32.NewProc("WTSFreeMemory")

	// WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, Reserved=0, Version=1,
	//                        &pSessionInfo, &count)
	type wtsSessionInfo struct {
		SessionID    uint32
		WinStaName   *uint16
		State        uint32 // WTS_CONNECTSTATE_CLASS
	}
	const wtsCurrentServerHandle uintptr = 0
	const wtsActive uint32 = 0 // WTSActive

	var pSessions *wtsSessionInfo
	var count uint32
	ret, _, _ := enumSessions.Call(
		wtsCurrentServerHandle,
		0, 1,
		uintptr(unsafe.Pointer(&pSessions)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 || pSessions == nil {
		return 0, false
	}
	defer freeMem.Call(uintptr(unsafe.Pointer(pSessions)))

	// Treat the WTS-allocated array as a Go slice — safe because pSessions points
	// to Win32-heap memory that the GC will never move.
	sessions := (*[1 << 16]wtsSessionInfo)(unsafe.Pointer(pSessions))[:count:count]
	for i := uint32(0); i < count; i++ {
		info := &sessions[i]
		if info.State != wtsActive {
			continue
		}
		// WTSQueryUserToken(SessionId, &hToken)
		var tok syscall.Token
		r, _, _ := queryUserToken.Call(
			uintptr(info.SessionID),
			uintptr(unsafe.Pointer(&tok)),
		)
		if r == 0 || tok == 0 {
			continue
		}
		// Convert to windows.Token and duplicate to a primary token.
		wtok := windows.Token(tok)
		var primary windows.Token
		err := windows.DuplicateTokenEx(
			wtok,
			windows.TOKEN_ALL_ACCESS,
			nil,
			windows.SecurityImpersonation,
			windows.TokenPrimary,
			&primary,
		)
		_ = wtok.Close()
		if err != nil {
			continue
		}
		return primary, true
	}
	return 0, false
}

// agentContextFor returns the execution token and privilege label for a step.
//
//   - "" / "user"   → logged-in interactive user token (WTS); falls back to
//     agent context (label "admin") if no session exists.
//   - "admin"       → agent's own elevated context; token=0 means "no switch".
//   - "system"      → agent's own context (already SYSTEM); token=0.
//
// The caller must close a non-zero returned token after the step completes.
// agentContextFor resolves the execution token and the actual-execution label
// for a step based on its RequiresPriv declaration.
//
//   - ""       → legacy: run in the agent's own context, no label recorded.
//               This preserves backward compatibility for all existing unannotated
//               scenarios — they continue to behave exactly as before.
//   - "user"   → attempt WTS interactive-user token. On success returns the token
//               and label "user". If no interactive session exists, returns zero
//               token and label "user→admin" so the fallback is visible in results.
//   - "admin"  → agent's own elevated context; label "admin".
//   - "system" → agent's own context (already SYSTEM); label "system".
func agentContextFor(step ScenarioStep) (windows.Token, string) {
	switch step.RequiresPriv {
	case "":
		// Legacy / unannotated — run in agent's own context, no context label.
		return 0, ""
	case "user":
		tok, ok := activeUserToken()
		if ok {
			return tok, "user"
		}
		// No interactive session — fall back to agent context and record the
		// fallback explicitly so operators can see what actually executed.
		return 0, "user→admin"
	case "admin":
		return 0, "admin"
	case "system":
		return 0, "system"
	default:
		// Unknown value — treat as legacy to avoid breaking unknown content.
		return 0, ""
	}
}

// buildUserEnv constructs the environment block for a user-context process.
// It merges the user's own environment (from their token) with any step-level
// overrides. Falls back to os.Environ() if CreateEnvironmentBlock fails.
func buildUserEnv(tok windows.Token, step ScenarioStep) ([]string, error) {
	userprofile, _ := tok.GetUserProfileDirectory()

	// Start from the agent's own env (captures PATH etc.) then patch user-
	// specific variables so scripts that reference %USERPROFILE%, %APPDATA%, etc.
	// resolve correctly inside the user session.
	env := make([]string, 0, 32)
	for _, e := range syscall.Environ() {
		env = append(env, e)
	}

	// Patch key user-context variables.
	if userprofile != "" {
		env = patchEnv(env, "USERPROFILE", userprofile)
		env = patchEnv(env, "HOMEPATH", userprofile)
		env = patchEnv(env, "HOMEDRIVE", "")
		env = patchEnv(env, "APPDATA", userprofile+`\AppData\Roaming`)
		env = patchEnv(env, "LOCALAPPDATA", userprofile+`\AppData\Local`)
		env = patchEnv(env, "TEMP", userprofile+`\AppData\Local\Temp`)
		env = patchEnv(env, "TMP", userprofile+`\AppData\Local\Temp`)
	}

	// Step-level additions (BAS_PAYLOAD_DIR etc.)
	if step.PayloadDir != "" {
		env = patchEnv(env, "BAS_PAYLOAD_DIR", step.PayloadDir)
	}
	for k, v := range step.Env {
		env = patchEnv(env, k, v)
	}
	return env, nil
}

// launchTrayForActiveSession spawns "<exe> --tray" inside the current
// interactive user session, if one exists. It is a no-op when no user is
// logged in (headless / locked with no session yet).
//
// The service (running as SYSTEM in Session 0) cannot show UI itself, and
// relying solely on the HKLM ...\Run registry entry the installer writes is
// not reliable across every shutdown/power-on cycle — Explorer's processing
// of that key is best-effort and was observed to silently not fire on some
// endpoints, leaving the tray permanently absent until a manual relaunch.
// The service actively (re)asserting the tray here, on its own startup and
// on every session logon/connect event (see service.go), makes the icon's
// presence independent of whether Explorer's Run-key processing happens to
// run. A redundant launch into a session that already has the tray running
// is a harmless no-op — the tray's own session-local singleton mutex
// (trayAlreadyRunning in tray_windows.go) makes the second instance exit
// immediately without disturbing the first icon.
func launchTrayForActiveSession() {
	tok, ok := activeUserToken()
	if !ok {
		return
	}
	defer tok.Close()

	exe, err := os.Executable()
	if err != nil {
		log.Printf("[svc] launch tray: resolve exe path: %v", err)
		return
	}

	// buildUserEnv only needs a token here — PayloadDir/Env are scenario-step
	// concepts that don't apply to launching the tray, so a zero-value step
	// is intentional, not a shortcut.
	env, _ := buildUserEnv(tok, ScenarioStep{})

	cmd := exec.Command(exe, "--tray")
	cmd.Dir = filepath.Dir(exe)
	cmd.Env = env
	// HideWindow + CREATE_NO_WINDOW: bas_agent.exe is a console-subsystem
	// binary (see packaging/windows-build.ps1 — only the separate installer
	// is built -H windowsgui), so without these flags Windows allocates a
	// visible console for this child. The tray icon's entire lifecycle
	// (runTray()'s message loop) runs inside this same process, so a
	// visible console here isn't just cosmetic — closing it kills the
	// process, which kills the tray icon. Matches silentCmd's pattern in
	// executor_windows.go.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(tok),
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[svc] launch tray: %v", err)
		return
	}
	_ = cmd.Process.Release() // tray runs independently; we don't wait on it
}

// patchEnv replaces the first occurrence of key=… in env, or appends if absent.
func patchEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}
