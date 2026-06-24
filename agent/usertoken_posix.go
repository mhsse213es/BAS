//go:build linux || darwin

package main

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// posixUserCtx holds the resolved identity of the active interactive user.
type posixUserCtx struct {
	uid      uint32
	gid      uint32
	groups   []uint32
	username string
	home     string
}

var posixUserCache struct {
	mu      sync.Mutex
	ctx     *posixUserCtx
	fetchAt time.Time
}

const posixUserTTL = 30 * time.Second

// activeUserCtx returns the interactive user context for this machine.
// Mirrors Windows activeUserToken — same TTL, same fallback semantics.
func activeUserCtx() (posixUserCtx, bool) {
	posixUserCache.mu.Lock()
	defer posixUserCache.mu.Unlock()

	if posixUserCache.ctx != nil && time.Since(posixUserCache.fetchAt) < posixUserTTL {
		return *posixUserCache.ctx, true
	}

	ctx, ok := resolveInteractiveUser()
	if !ok {
		return posixUserCtx{}, false
	}
	posixUserCache.ctx = &ctx
	posixUserCache.fetchAt = time.Now()
	return ctx, true
}

// resolveInteractiveUser tries to find the active interactive user.
// Strategy: parse 'who' output first, then fall back to SUDO_USER.
// root is never used as the target user — the agent already runs as root.
func resolveInteractiveUser() (posixUserCtx, bool) {
	if name := firstInteractiveUser(); name != "" && name != "root" {
		if ctx, ok := userCtxFromName(name); ok {
			return ctx, true
		}
	}
	// Fallback: agent launched via sudo — SUDO_USER holds the original user.
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if ctx, ok := userCtxFromName(name); ok {
			return ctx, true
		}
	}
	return posixUserCtx{}, false
}

// firstInteractiveUser returns the first non-empty username from 'who' output.
// Works on both Linux (pts/0, :0 sessions) and macOS (console, s000 sessions).
func firstInteractiveUser() string {
	out, err := exec.Command("who").Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] != "" {
			return fields[0]
		}
	}
	return ""
}

// userCtxFromName resolves UID, GID, supplementary groups, and home directory
// for the given username using the standard library (handles NSS, LDAP, etc.).
func userCtxFromName(name string) (posixUserCtx, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return posixUserCtx{}, false
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return posixUserCtx{}, false
	}
	gid64, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return posixUserCtx{}, false
	}

	var groups []uint32
	if gids, err := u.GroupIds(); err == nil {
		for _, g := range gids {
			if n, err := strconv.ParseUint(g, 10, 32); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}

	return posixUserCtx{
		uid:      uint32(uid64),
		gid:      uint32(gid64),
		groups:   groups,
		username: u.Username,
		home:     u.HomeDir,
	}, true
}

// buildPosixUserEnv constructs the environment for a user-context process.
// Starts from the agent's own environment and patches user-specific variables,
// mirroring what buildUserEnv does on Windows.
func buildPosixUserEnv(ctx posixUserCtx, step ScenarioStep) []string {
	env := make([]string, 0, 32)
	for _, e := range os.Environ() {
		env = append(env, e)
	}
	if ctx.home != "" {
		env = patchPosixEnv(env, "HOME", ctx.home)
	}
	env = patchPosixEnv(env, "USER", ctx.username)
	env = patchPosixEnv(env, "LOGNAME", ctx.username)
	// Drop SUDO_* so the child does not inherit escalated context hints.
	for _, k := range []string{"SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"} {
		env = dropPosixEnv(env, k)
	}
	if step.PayloadDir != "" {
		env = patchPosixEnv(env, "BAS_PAYLOAD_DIR", step.PayloadDir)
	}
	for k, v := range step.Env {
		env = patchPosixEnv(env, k, v)
	}
	return env
}

func patchPosixEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}

func dropPosixEnv(env []string, key string) []string {
	prefix := key + "="
	out := env[:0]
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}
