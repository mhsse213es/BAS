package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Windows attack-path collection helpers. All recon-only: enumeration of local
// group membership and sessions, and running the operator-supplied SharpHound
// collector. No exploitation, no propagation.

// collectLocalAdmins returns the members of the local Administrators group —
// principals that hold local-admin (an "admin-to this host" edge). Domain
// principals appear as "DOMAIN\name".
func collectLocalAdmins() []string {
	out, err := exec.Command("net", "localgroup", "Administrators").Output()
	if err != nil {
		return nil
	}
	var members []string
	inList := false
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "----") {
			inList = true
			continue
		}
		if !inList {
			continue
		}
		if l == "" || strings.HasPrefix(strings.ToLower(l), "the command completed") {
			continue
		}
		members = append(members, l)
	}
	return members
}

// collectSessions returns the user accounts with an interactive session on this
// host (their credentials are harvestable here). Falls back to the agent's own
// user when enumeration is unavailable.
func collectSessions(currentUser string) []string {
	out, err := exec.Command("query", "user").Output()
	if err != nil {
		if currentUser != "" {
			return []string{currentUser}
		}
		return nil
	}
	seen := map[string]bool{}
	var users []string
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 { // header
			continue
		}
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), ">"))
		if l == "" {
			continue
		}
		name := strings.Fields(l)[0]
		if name != "" && !seen[name] {
			seen[name] = true
			users = append(users, name)
		}
	}
	if len(users) == 0 && currentUser != "" {
		return []string{currentUser}
	}
	return users
}

// hostIsDomainJoined reports whether this host is joined to an AD domain.
func hostIsDomainJoined() bool {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).PartOfDomain").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "true")
}

// runSharpHound stages the supplied SharpHound binary, runs it, and returns the
// raw output zip bytes. The agent does not parse the result — the server does.
func runSharpHound(payload *Payload, args string) ([]byte, error) {
	if payload == nil || payload.Name == "" {
		return nil, nil
	}
	dir, err := attackPathTempDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	if err := StagePayloads([]Payload{*payload}, dir); err != nil {
		return nil, err
	}
	exe := filepath.Join(dir, payload.Name)
	if strings.TrimSpace(args) == "" {
		args = "-c All --outputdirectory . --zipfilename bas.zip --nosavecache"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, strings.Fields(args)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sharphound exec: %w (%s)", err, truncateOut(out))
	}

	zips, _ := filepath.Glob(filepath.Join(dir, "*.zip"))
	if len(zips) == 0 {
		return nil, fmt.Errorf("sharphound produced no zip in %s", dir)
	}
	// Pick the most recently modified zip.
	newest, newestMod := zips[0], time.Time{}
	for _, z := range zips {
		if fi, e := os.Stat(z); e == nil && fi.ModTime().After(newestMod) {
			newest, newestMod = z, fi.ModTime()
		}
	}
	return os.ReadFile(newest)
}

// attackPathTempDir returns a fresh temp directory for SharpHound output.
func attackPathTempDir() (string, error) {
	return os.MkdirTemp("", "bas-ap-*")
}

func truncateOut(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
