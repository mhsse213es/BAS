package main

import "strings"

// Variables the agent reads for its own use and must never hand to a child
// process: dbsim credentials (BAS_DBCRED_*, including the Windows *_ENC form)
// and the dbsim local policy flags (BAS_DBPROBE_*). A shell step that dumps its
// environment would otherwise put them into Stdout and so into the report.
var childEnvStripPrefixes = []string{"BAS_DBCRED_", "BAS_DBPROBE_"}

// childEnvironment returns a copy of base without any variable whose name starts
// with a stripped prefix. Matching is case-insensitive on EVERY platform (a
// superset of Windows semantics; harmless on POSIX). An entry with no '=' is
// treated as a bare name. Entries that do not match are kept verbatim and in
// order, including odd ones such as Windows' "=C:=C:\dir" pseudo variables.
//
// Every place the agent builds an environment for a child process must pass it
// through this function; a nil cmd.Env makes os/exec inherit the full parent
// environment, so callers must set cmd.Env explicitly.
func childEnvironment(base []string) []string {
	out := make([]string, 0, len(base))
	for _, e := range base {
		name := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			name = e[:i]
		}
		strip := false
		for _, p := range childEnvStripPrefixes {
			if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
				strip = true
				break
			}
		}
		if !strip {
			out = append(out, e)
		}
	}
	return out
}
