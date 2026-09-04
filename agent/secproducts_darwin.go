//go:build darwin

package main

import (
	"context"
	"os/exec"
	"time"
)

// The macOS entry point. Everything this file does is turn "run a command" into
// a real process; the catalogue, the parsers and the whole report assembly live
// in secproducts_mac.go, which carries no build tag and is unit-tested from the
// Windows build host. Keeping this file to a single small function is what
// makes the rest of the inventory verifiable without a Mac.
func enumerateSecurityProducts() (products []string, diag []string) {
	return enumerateDarwinSecurityProducts("/", execMacCommand)
}

// macProbeTimeout bounds one inventory command. Each is a local status query
// that normally returns in milliseconds; the bound exists so a wedged tool
// cannot stall enrollment.
const macProbeTimeout = 10 * time.Second

// execMacCommand runs one probe and returns stdout. stderr is deliberately not
// merged in: csrutil and spctl write advisory notices there on healthy hosts,
// and folding those into the parsed text would turn a clean read into an
// unrecognised one.
func execMacCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), macProbeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}
