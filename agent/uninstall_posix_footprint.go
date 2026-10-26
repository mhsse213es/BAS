package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// keepDataEnv is set by an installer that replaces the agent (an upgrade): the service and binary are swapped but
// the enrolment, certificates and configuration must survive.
const keepDataEnv = "BAS_UNINSTALL_KEEP_DATA"

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
		at("/var/log/bas-agent"),
		at("/var/lib/bas-agent"),
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
