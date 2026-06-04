//go:build windows

package main

import _ "embed"

// agentData holds the embedded bas_agent.exe binary.
// trayData holds the embedded bas_agent_tray.exe binary.
// Both are copied by the build script before compiling the installer.

//go:embed bas_agent.exe
var agentData []byte

//go:embed bas_agent_tray.exe
var trayData []byte
