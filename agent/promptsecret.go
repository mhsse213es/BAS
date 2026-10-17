package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// promptSecret reads one line from r, used when --install is run with
// neither --secret nor BAS_AGENT_SECRET set. Letting the operator type the
// secret interactively, rather than requiring it as a command-line flag,
// keeps it out of shell history and process listings, and is what makes
// the console's copy-paste install one-liner able to omit it entirely.
func promptSecret(r io.Reader, w io.Writer) (string, error) {
	fmt.Fprint(w, "Agent Secret: ")
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read secret: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("agent secret must not be empty")
	}
	return line, nil
}

// stdinIsTerminal reports whether stdin is an interactive terminal (as
// opposed to a pipe, redirect, or closed fd) -- promptSecret is only
// attempted when it is, so a scripted/non-interactive --install still fails
// fast with a clear error instead of hanging on a read that will never
// complete.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
