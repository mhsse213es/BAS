package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"audspect/agent/preflight"
	"audspect/agent/protocol"
)

// installEnrollError is a failed install-time enrolment, kept distinct from other install failures so the
// installer can tell an operator whether the server refused the credentials or could not be reached.
type installEnrollError struct {
	err             error
	rejected        bool // the server answered and refused the credentials
	alreadyEnrolled bool // the server answered 409: it already has an active identity for this host
}

func (e *installEnrollError) Error() string { return e.err.Error() }
func (e *installEnrollError) Unwrap() error { return e.err }

// classifyEnrollError wraps err and says, in words an operator can act on, which kind of failure it was.
// The server answering 401/403 is an authorization failure (the token is wrong, expired, used, or for a
// different host). Anything else (no connection, TLS failure, 5xx, an unexpected status) is a connection
// problem and says nothing about the token. The token itself never appears in the message.
func classifyEnrollError(err error) error {
	var se *protocol.StatusError
	if errors.As(err, &se) && se.Code == 409 {
		return &installEnrollError{alreadyEnrolled: true, err: errors.New("the server already has an active agent for this host and will not replace it with a new install on the shared secret alone. Ask an administrator to use Force Remove Agent for this host in the console, or to issue an enrolment token for it, then run the install again")}
	}
	if errors.As(err, &se) && (se.Code == 401 || se.Code == 403) {
		return &installEnrollError{rejected: true, err: fmt.Errorf("the server refused the enrolment (HTTP %d): the enrolment token is invalid, expired, already used, or was issued for a different host", se.Code)}
	}
	return &installEnrollError{err: fmt.Errorf("could not complete enrolment because the server could not be reached or did not respond correctly (this is not a token problem): %w", err)}
}

// installExitCode maps an install-time enrolment error to its process exit code.
func installExitCode(err error) int {
	var ie *installEnrollError
	if !errors.As(err, &ie) {
		return 1
	}
	if ie.alreadyEnrolled {
		return preflight.CodeAlreadyEnrolled
	}
	if ie.rejected {
		return preflight.CodeEnrollmentRejected
	}
	return preflight.CodeServerUnreachable
}

const maxTokenBytes = 1024

// readTokenLine reads a single-line token from r with the same strictness as the agent secret: one line,
// printable text, bounded, and never echoed in an error.
func readTokenLine(r io.Reader, source string) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxTokenBytes+512))
	if err != nil {
		return "", fmt.Errorf("could not read the enrolment token from %s", source)
	}
	first, rest, _ := strings.Cut(string(raw), "\n")
	first = strings.TrimSuffix(first, "\r")
	if strings.TrimSpace(rest) != "" {
		return "", fmt.Errorf("%s has more than one line: provide only the enrolment token", source)
	}
	if first == "" {
		return "", fmt.Errorf("no enrolment token was provided on %s", source)
	}
	if len(first) > maxTokenBytes || !utf8.ValidString(first) {
		return "", fmt.Errorf("the enrolment token from %s is not valid", source)
	}
	for _, c := range first {
		if c < 0x20 || c == 0x7f || c == ' ' {
			return "", fmt.Errorf("the enrolment token from %s is not valid", source)
		}
	}
	return first, nil
}

// resolveEnrollmentToken finds the single-use enrolment token for an install. At most one of the file and
// stdin sources may be used, and stdin cannot also carry the agent secret. A token file is deleted once read
// (it is single use and should not stay on disk). With neither, BAS_ENROLLMENT_TOKEN is used and then removed
// from the environment. No source returns "". The token is never accepted as a command-line value.
func resolveEnrollmentToken(file string, fromStdin, secretFromStdin bool, stdin io.Reader) (string, error) {
	if file != "" && fromStdin {
		return "", errors.New("use --enrollment-token-file or --enrollment-token-stdin, not both")
	}
	if fromStdin && secretFromStdin {
		return "", errors.New("--enrollment-token-stdin and --secret-stdin cannot both read stdin: pass the secret another way")
	}
	switch {
	case fromStdin:
		return readTokenLine(stdin, "stdin")
	case file != "":
		info, err := os.Lstat(file)
		if err != nil {
			return "", fmt.Errorf("enrolment token file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("the enrolment token file must be a regular file")
		}
		f, err := os.Open(file)
		if err != nil {
			return "", fmt.Errorf("enrolment token file: %w", err)
		}
		tok, readErr := readTokenLine(f, "the token file")
		f.Close()
		if readErr != nil {
			return "", readErr
		}
		if err := os.Remove(file); err != nil {
			return "", fmt.Errorf("the token was read but the token file could not be removed: %w", err)
		}
		return tok, nil
	}
	tok := strings.TrimSpace(os.Getenv("BAS_ENROLLMENT_TOKEN"))
	os.Unsetenv("BAS_ENROLLMENT_TOKEN")
	return tok, nil
}
