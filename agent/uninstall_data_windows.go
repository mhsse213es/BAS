//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// cleanAgentFootprint is the last step of an uninstall: it puts back the machine-wide Windows settings the agent
// changed, then removes the data the agent leaves on disk (client key and certificate, enrolled CA, local API
// token, logs, event spool). installDirs are the folders the removed services ran from; the executable itself is
// removed by the MSI (or at the next boot), not here. logf may be nil.
func cleanAgentFootprint(installDirs []string, logf func(format string, a ...any)) purgeReport {
	if logf == nil {
		logf = func(format string, a ...any) { fmt.Printf(format, a...) }
	}
	if restored, failed := restoreSettingsFromBackup(settingsBackupPath(), registryStore{}); restored {
		if len(failed) == 0 {
			logf("[+] Windows settings the agent had changed were put back as they were\n")
		}
		for _, f := range failed {
			logf("[!] Could not restore %s\n", f)
		}
	}

	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	cfgDir, _ := os.UserConfigDir()
	var logDirs []string
	for _, d := range installDirs {
		// Only a folder that really holds the agent's log is taken for an install folder, so an agent started
		// from somewhere like Downloads never causes that folder's own "logs" to be touched.
		if d != "" && fileExists(filepath.Join(d, "logs", logFileName)) {
			logDirs = append(logDirs, d)
		}
	}
	trees, parents := agentDataTargets(programData, logDirs, cfgDir, os.TempDir(), func(p string) []string {
		m, _ := filepath.Glob(p)
		return m
	})
	// The diagnostic log (agent.log under Program Files, in the Audspect folder) is kept unless the operator asks for it to go.
	if purgeAgentLogs() {
		trees = append(trees, agentLogDir())
	}
	rep := purgeAgentFiles(trees, parents, osPurgeOps(scheduleBinaryDeleteOnReboot))
	rep.print(logf)
	return rep
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// platformPurgeLocalData runs after a remote uninstall has been reported to the server. An agent installed from
// the MSI is removed by Windows Installer, whose uninstall runs the agent's own uninstall (and so this cleanup)
// once the service has stopped; only an agent installed some other way is cleaned here.
func platformPurgeLocalData() {
	if _, ok := readMSIProductCode(); ok {
		return
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	cleanAgentFootprint(dirs, func(format string, a ...any) { log.Printf(format, a...) })
}
