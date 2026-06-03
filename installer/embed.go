//go:build windows

package main

import _ "embed"

// agentData holds the embedded bas_agent.exe binary.
// The file is copied by the build script before compiling the installer.
//
//go:embed bas_agent.exe
var agentData []byte
