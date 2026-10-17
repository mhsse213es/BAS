package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// installDefaults is the per-deployment config the console's download
// endpoint bundles alongside this installer (see orchestrator's
// buildAgentDefaultsJSON), so the operator never has to copy the Server
// URL/Enrollment Port off the dashboard by hand -- only the Secret.
type installDefaults struct {
	ServerURL  string `json:"serverURL"`
	EnrollPort string `json:"enrollPort"`
}

// loadInstallDefaultsFromDir reads bas-agent-defaults.json out of dir, if
// present. Any problem reading or parsing it (missing, malformed) returns
// the zero value rather than an error: a bare binary run outside its
// downloaded bundle -- e.g. during development -- must fall back to manual
// entry, not fail to start.
func loadInstallDefaultsFromDir(dir string) installDefaults {
	data, err := os.ReadFile(filepath.Join(dir, "bas-agent-defaults.json"))
	if err != nil {
		return installDefaults{}
	}
	var d installDefaults
	if err := json.Unmarshal(data, &d); err != nil {
		return installDefaults{}
	}
	return d
}

// loadInstallDefaults looks next to the running executable itself.
func loadInstallDefaults() installDefaults {
	selfPath, err := os.Executable()
	if err != nil {
		return installDefaults{}
	}
	return loadInstallDefaultsFromDir(filepath.Dir(selfPath))
}
