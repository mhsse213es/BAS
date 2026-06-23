//go:build windows

package main

import (
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
func agentContextFor(step ScenarioStep) (windows.Token, string) {
	switch step.RequiresPriv {
	case "", "user":
		tok, ok := activeUserToken()
		if ok {
			return tok, "user"
		}
		// No interactive session — fall through to agent context.
		return 0, "admin"
	case "admin":
		return 0, "admin"
	case "system":
		return 0, "system"
	default:
		return 0, "admin"
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
