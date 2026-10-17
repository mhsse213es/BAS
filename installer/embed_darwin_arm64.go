//go:build darwin && arm64

package main

import _ "embed"

// bas_agent_darwin_arm64 is copied into place by the build script before
// compiling the installer (see embed.go's Windows counterpart).
//
//go:embed bas_agent_darwin_arm64
var agentData []byte
