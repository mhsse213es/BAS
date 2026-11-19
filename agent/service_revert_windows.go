//go:build windows

package main

import (
	"strings"
)

// serviceRemovable decides, from `sc qc` output, whether a service that appeared during a run may be deleted rather
// than only stopped and disabled. Only a user-mode service whose program is not an installed product or an operating
// system component qualifies: a test creates one that points at cmd.exe or a temp binary, whereas a driver, a service
// in Program Files, a servicing component or a shared svchost group may belong to something the machine legitimately
// installed while the run was going on.
func serviceRemovable(qcOutput string) bool {
	var typ, path string
	for _, line := range strings.Split(qcOutput, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "TYPE"):
			typ = strings.ToUpper(l[strings.Index(l, ":")+1:])
		case strings.HasPrefix(l, "BINARY_PATH_NAME"):
			path = strings.ToLower(strings.TrimSpace(l[strings.Index(l, ":")+1:]))
		}
	}
	if typ == "" || path == "" || !strings.Contains(typ, "WIN32_OWN_PROCESS") || strings.Contains(typ, "DRIVER") {
		return false
	}
	for _, protected := range []string{`\program files`, `\winsxs\`, `\servicing\`, `\drivers\`, `svchost.exe`} {
		if strings.Contains(path, protected) {
			return false
		}
	}
	return true
}

// removeNewService stops and disables a service that appeared during the run and, when it is safe to, deletes it.
// It returns the line to report.
func removeNewService(name string) string {
	snapCmdRun("sc", "stop", name)                         //nolint
	snapCmdRun("sc", "config", name, "start=", "disabled") //nolint
	if out, err := snapCmd("sc", "qc", name); err == nil && serviceRemovable(string(out)) {
		if snapCmdRun("sc", "delete", name) == nil {
			return "service removed: " + name
		}
		return "restore incomplete: service could not be deleted: " + name
	}
	return "service stopped: " + name
}
