//go:build linux || darwin

package main

import "os"

// platformPurgeLocalData removes every file the agent created, after its service has been removed. An installer that
// is only replacing the agent sets BAS_UNINSTALL_KEEP_DATA=1, and nothing is removed.
func platformPurgeLocalData() {
	if keepAgentData() {
		return
	}
	cleanPosixFootprint("/", os.TempDir(), printfLog)
}
