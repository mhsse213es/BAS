package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// maxSecretBytes bounds an agent secret read from stdin. Real secrets are far
// shorter; the cap keeps a stray pipe from being slurped into memory.
const maxSecretBytes = 4096

// readSecretFromStdin reads an agent secret from r, so it never has to appear
// in process arguments or a generated script.
//
// The first line is the secret; a trailing CR or LF is removed and nothing else
// is trimmed (spaces inside a secret are kept). Anything other than blank space
// after the first line is rejected rather than silently dropped, because a
// multi-line input almost certainly means the wrong thing was piped in and a
// guessed secret would fail later with a confusing error. Control characters,
// invalid UTF-8, empty input and over-long input are rejected too. Error
// messages never include any part of the input.
func readSecretFromStdin(r io.Reader) (string, error) {
	// Read a little past the cap so over-long input is detected, but never more.
	raw, err := io.ReadAll(io.LimitReader(r, maxSecretBytes+1024))
	if err != nil {
		return "", fmt.Errorf("could not read the secret from stdin: %w", err)
	}
	s := string(raw)
	first, rest, _ := strings.Cut(s, "\n")
	first = strings.TrimSuffix(first, "\r")

	if strings.TrimSpace(rest) != "" {
		return "", errors.New("stdin has more than one line: pipe only the secret")
	}
	if len(first) > maxSecretBytes {
		return "", fmt.Errorf("the secret is too long (limit %d bytes)", maxSecretBytes)
	}
	if first == "" {
		return "", errors.New("no secret was provided on stdin")
	}
	if !utf8.ValidString(first) {
		return "", errors.New("the secret on stdin is not valid text")
	}
	for _, c := range first {
		if c < 0x20 || c == 0x7f {
			return "", errors.New("the secret on stdin contains a control character")
		}
	}
	return first, nil
}

// secretFromFlags resolves the --secret / --secret-stdin pair. fromStdin is
// true when the secret was read from stdin. When neither flag is set it returns
// ("", false, nil) so the caller keeps its existing fallbacks (environment
// variable, interactive prompt) exactly as before. Supplying both is an error
// and stdin is left unread.
func secretFromFlags(secretFlag string, secretStdin bool, stdin io.Reader) (secret string, fromStdin bool, err error) {
	if secretFlag != "" && secretStdin {
		return "", false, errors.New("use --secret or --secret-stdin, not both")
	}
	if secretStdin {
		s, err := readSecretFromStdin(stdin)
		if err != nil {
			return "", false, err
		}
		return s, true, nil
	}
	return secretFlag, false, nil
}
