//go:build windows

package main

import _ "embed"

// agentData holds the embedded bas_agent.exe binary. The agent is a single
// binary: it runs as the service, and `--tray` / `--status-window` provide the
// user-session UI. There is no separate tray executable.
// The file is copied by the build script before compiling the installer.

//go:embed bas_agent.exe
var agentData []byte
