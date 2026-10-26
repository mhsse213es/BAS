package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// promptHidden shows label and reads one line from in with terminal echo switched off, so a token or secret
// typed by an operator is not displayed, left in the scrollback, or captured by screen sharing. If echo cannot
// be switched off (stdin is not a terminal) the line is still read. The value is never written to out.
func promptHidden(label string, in *os.File, out io.Writer) (string, error) {
	fmt.Fprint(out, label)
	restore := disableEcho(in)
	line, err := bufio.NewReader(in).ReadString('\n')
	if restore != nil {
		restore()
	}
	fmt.Fprintln(out)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
