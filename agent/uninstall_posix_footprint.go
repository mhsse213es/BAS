package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keepDataEnv is set by an installer that replaces the agent (an upgrade): the service and binary are swapped but
// the enrolment, certificates and configuration must survive.
const keepDataEnv = "BAS_UNINSTALL_KEEP_DATA"

// purgeLogsEnv makes an uninstall remove the agent's diagnostic log (agent.log and its rotations) as well. Without
// it the log is kept: it is the evidence of why an install or an uninstall went wrong.
const purgeLogsEnv = "BAS_UNINSTALL_PURGE_LOGS"

func purgeAgentLogs() bool { return os.Getenv(purgeLogsEnv) == "1" }

func keepAgentData() bool { return os.Getenv(keepDataEnv) == "1" }

// posixFootprint lists, under root, everything the Linux and macOS agent and its installers create: the program, the
// service definition, the configuration (which holds the agent secret) and stored database credentials, the client
// key and certificates and enrolled CA, logs, the event spool and the log folder in Temp. Shared parents are removed
// only if the purge leaves them empty. root is "/" on a real machine and a temporary folder in tests.
func posixFootprint(root, tempDir string, glob func(pattern string) []string) (trees, parents []string) {
	at := func(p string) string { return filepath.Join(root, filepath.FromSlash(p)) }
	trees = []string{
		at("/usr/local/bin/bas-agent"),
		at("/etc/systemd/system/bas-agent.service"),
		at("/etc/systemd/system/bas-agent.service.d"),
		at("/Library/LaunchDaemons/com.audspect.bas-agent.plist"),
		at("/etc/bas-agent"),
		at("/etc/audspect/certs"),
		at("/etc/audspect-agent"),
		at("/var/lib/bas-agent"),
	}
	if glob != nil && !purgeAgentLogs() {
		// the log folder goes, except the diagnostic log and its rotations
		for _, m := range glob(at("/var/log/bas-agent/*")) {
			if !strings.HasPrefix(filepath.Base(m), logFileName) {
				trees = append(trees, m)
			}
		}
	} else {
		trees = append(trees, at("/var/log/bas-agent"))
	}
	if glob != nil {
		trees = append(trees, glob(at("/etc/audspect/certs.replaced-*"))...)
	}
	if tempDir != "" {
		trees = append(trees, filepath.Join(tempDir, "BASAgent"))
	}
	return trees, []string{at("/etc/audspect")}
}

// cleanPosixFootprint removes the footprint and reports the outcome through logf.
func cleanPosixFootprint(root, tempDir string, logf func(format string, a ...any)) purgeReport {
	trees, parents := posixFootprint(root, tempDir, func(p string) []string { m, _ := filepath.Glob(p); return m })
	rep := purgeAgentFiles(trees, parents, osPurgeOps(nil))
	rep.print(logf)
	return rep
}

func printfLog(format string, a ...any) { fmt.Printf(format+"\n", a...) }
