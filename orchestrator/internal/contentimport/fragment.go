// Package contentimport turns detection content (Sigma and YARA rules) into DRAFT test scenarios, and compiles chains of
// reviewed steps into one self-contained step.
//
// The safety rule that runs through all of it: a generated step never runs what the rule describes. It carries the
// rule's strings inertly (echoed as arguments, or written into a file the host's security software can scan), so a
// rule about credential dumping produces a harmless process or file that merely LOOKS like the rule's match. Anything
// that cannot be carried that way is reported as not emulated, not guessed at. Every draft needs a reviewer's approval
// before it can run.
package contentimport

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// fragmentOK admits only characters that mean the same thing in a cmd.exe echo, a POSIX single-quoted word and a file
// name: no quoting, expansion, redirection, chaining or control characters. A rule string with anything else is not
// carried (it is reported), never escaped, because escaping changes the very text a rule matches on.
var fragmentOK = regexp.MustCompile(`^[A-Za-z0-9 _.,:/\\=@#+~\[\]{}-]{1,200}$`)

// SafeFragment reports whether s can be carried inertly.
func SafeFragment(s string) bool {
	return fragmentOK.MatchString(s) && !strings.Contains(s, "..")
}

// Marker is the stable token a generated step puts in its command, derived from what it was generated from, so
// importing the same rule twice yields the same marker. It satisfies scenario.markerPattern.
func Marker(kind string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return "imp-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// Coverage says how faithfully a draft reproduces the rule it came from.
type Coverage struct {
	// Emulable is false when the generated step cannot satisfy the rule; no step is produced then.
	Emulable bool `json:"emulable"`
	// Emulated lists what the step reproduces; NotEmulated lists what it cannot, each with the reason.
	Emulated    []string `json:"emulated"`
	NotEmulated []string `json:"notEmulated"`
	Notes       []string `json:"notes,omitempty"`
}
