//go:build windows

package main

// Endpoint health: the "Verify" stage after an assessment's "Restore".
//
// The registry guard puts recorded keys back, but the question that matters to the customer is not "were the keys
// restored" but "does Windows still open things the way it did". So this asks Windows itself what a file type or folder
// opens with (the lookup Explorer and the Run dialog use, AssocQueryString) before the run and again after, and reports
// any difference. It also reports a user-level shell override that was already there at the start, so a leak from an
// earlier run is named instead of being accepted as the normal state.

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// healthAssocs are the file types and shell objects whose "open" handler decides what Run, Explorer and a double-click
// start. A variable so tests can point it at a scratch type.
var healthAssocs = []string{
	"Folder", "Directory", "Drive", "ms-settings",
	".exe", ".bat", ".cmd", ".com", ".scr", ".lnk", ".cpl", ".msc", ".hta", ".ps1", ".vbs", ".js", ".txt",
}

// cmdSig is the "open" command registered for name in one classes hive, plus a DelegateExecute marker: a key with an
// empty command and a DelegateExecute value is how a UAC-bypass hijack looks, and it overrides the machine's handler.
func cmdSig(hive registry.Key, base, name string) (string, bool) {
	if hive == 0 {
		return "", false
	}
	k, err := registry.OpenKey(hive, base+`\`+name+`\shell\open\command`, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	cmd, _, _ := k.GetStringValue("")
	if d, _, err := k.GetStringValue("DelegateExecute"); err == nil {
		cmd += "|DelegateExecute=" + d
	}
	return cmd, true
}

func classDefault(hive registry.Key, base, name string) string {
	if hive == 0 {
		return ""
	}
	k, err := registry.OpenKey(hive, base+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("")
	return v
}

// openSig looks name up the way Windows does: the logged-in user's classes shadow the machine's.
func openSig(name string) (string, bool) {
	if c, ok := cmdSig(userHiveKey(), `Software\Classes`, name); ok {
		return c, true
	}
	return cmdSig(registry.LOCAL_MACHINE, `SOFTWARE\Classes`, name)
}

// assocCommand returns what Windows would run to "open" assoc for the logged-in user ("" when it has no handler):
// the type's own open verb, or its ProgID's. It reads the registry directly, because the service's own view of HKCU
// (what the shell API would use) is SYSTEM's, not the person's.
func assocCommand(assoc string) string {
	if c, ok := openSig(assoc); ok {
		return c
	}
	if strings.HasPrefix(assoc, ".") {
		prog := classDefault(userHiveKey(), `Software\Classes`, assoc)
		if prog == "" {
			prog = classDefault(registry.LOCAL_MACHINE, `SOFTWARE\Classes`, assoc)
		}
		if prog != "" {
			if c, ok := openSig(prog); ok {
				return c
			}
		}
	}
	return ""
}

// explorerRunning is a variable so a test can fake it.
var explorerRunning = func() bool {
	out, err := snapCmd("tasklist", "/fi", "imagename eq explorer.exe", "/nh")
	return err == nil && strings.Contains(strings.ToLower(string(out)), "explorer.exe")
}

// defaultActionVerbs are the shell verbs that replace what a double-click, Run or "Run as administrator" does. A user's
// extra context-menu entry (another verb, such as a disk-usage tool's) changes nothing about how things open.
var defaultActionVerbs = map[string]bool{"open": true, "explore": true, "runas": true}

// hkcuShellOverrides lists the user-level default-action verbs that exist for each assoc. Such a key shadows the
// machine-wide handler for that user, which is exactly what a UAC-bypass or association hijack writes.
func hkcuShellOverrides(assocs []string) []string {
	var out []string
	for _, a := range assocs {
		base := `Software\Classes\` + a + `\shell`
		hive := userHiveKey()
		if hive == 0 {
			return nil
		}
		k, err := registry.OpenKey(hive, base, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		verbs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, v := range verbs {
			if !defaultActionVerbs[strings.ToLower(v)] {
				continue
			}
			if c, err := registry.OpenKey(hive, base+`\`+v+`\command`, registry.QUERY_VALUE); err == nil {
				c.Close()
				out = append(out, `HKCU\`+base+`\`+v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// healthState is what Windows resolved at one moment.
type healthState struct {
	Handlers   map[string]string `json:"handlers"`
	Overrides  []string          `json:"overrides"`
	ExplorerUp bool              `json:"explorerUp"`
}

func captureHealth() *healthState {
	h := &healthState{Handlers: map[string]string{}, ExplorerUp: explorerRunning()}
	for _, a := range healthAssocs {
		h.Handlers[a] = assocCommand(a)
	}
	h.Overrides = hkcuShellOverrides(healthAssocs)
	return h
}

// baselineProblems names what is already wrong at the start of a run, before any test has touched anything.
func (h *healthState) baselineProblems() []string {
	var out []string
	for _, o := range h.Overrides {
		out = append(out, "a user-level shell override was already present before this run (left by an earlier run or another tool): "+o)
	}
	return out
}

// verify compares the machine now with the recorded state and returns one line per difference.
func (h *healthState) verify() []string {
	var out []string
	now := map[string]string{}
	for _, a := range healthAssocs {
		now[a] = assocCommand(a)
	}
	keys := make([]string, 0, len(now))
	for a := range now {
		keys = append(keys, a)
	}
	sort.Strings(keys)
	for _, a := range keys {
		if before, had := h.Handlers[a]; had && before != now[a] {
			out = append(out, fmt.Sprintf("health: %q now opens with %q (was %q)", a, now[a], before))
		} else if !had && now[a] != "" {
			out = append(out, fmt.Sprintf("health: %q now opens with %q (had no handler)", a, now[a]))
		}
	}
	if h.ExplorerUp && !explorerRunning() {
		out = append(out, "health: Windows Explorer was running before the run and is not now")
	}
	return out
}
