package main

import (
	"fmt"
	"os"
	"strings"
)

// stepScriptThreshold is the command length above which a shell step is run
// from a temporary script file instead of being passed as an argument. Windows
// caps a command line near 32,000 characters and Linux caps a single argument
// at 128 KB, while the console accepts uploads up to 256 KB.
const stepScriptThreshold = 8000

// writeStepScript writes content to a new, uniquely named file in dir and
// returns its path and an idempotent cleanup that removes it. The name is
// generated here and never derived from user input; ext only supplies the
// suffix and must not contain a path separator. The file is created owner-only
// (0600). withBOM prefixes a UTF-8 byte-order mark so Windows PowerShell 5.1
// reads non-ASCII text correctly.
func writeStepScript(dir, ext string, content string, withBOM bool) (string, func(), error) {
	if strings.ContainsAny(ext, `/\`) {
		return "", func() {}, fmt.Errorf("invalid script extension %q", ext)
	}
	f, err := os.CreateTemp(dir, "bas-step-*"+ext)
	if err != nil {
		return "", func() {}, err
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	data := []byte(content)
	if withBOM {
		data = append([]byte{0xEF, 0xBB, 0xBF}, data...)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}
