package main

import "strings"

// shQuote wraps s in single quotes for safe use as one argument in a POSIX
// shell command string, escaping any embedded single quote by closing the
// quoted section, inserting an escaped literal quote, and reopening it --
// the standard '"'"' trick. Needed by the macOS installer because
// AppleScript's "do shell script" takes the whole command as one string
// handed to /bin/sh -c, so every value placed in it must be quoted exactly
// as if building a shell command by hand.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// appleScriptQuote wraps s in double quotes for safe use as an AppleScript
// string literal, escaping backslash and double-quote (the only two
// characters AppleScript string literals treat specially). Order matters:
// backslashes must be escaped first, or escaping the quotes afterward would
// double-escape the backslashes just inserted.
func appleScriptQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
