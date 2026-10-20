package reporting

import (
	"regexp"
	"strings"
	"time"
)

// dlpEventStartRe matches the payload's DLP_EVENT_START line: the step's task
// id, then the UTC time the payload recorded just before its transfer attempt.
var dlpEventStartRe = regexp.MustCompile(`(?m)^DLP_EVENT_START: (\S+) (\S+)\s*$`)

// Reasons ParseDLPEventStart reports when it returns no timestamp.
const (
	DLPEventStartNoMarker    = "no_marker"
	DLPEventStartAmbiguous   = "ambiguous"
	DLPEventStartUnparseable = "unparseable"
)

// ParseDLPEventStart returns the test-event start recorded for taskID. It
// accepts exactly one matching DLP_EVENT_START line. Lines for other task IDs
// are ignored. An empty taskID never matches, so an uncorrelated marker cannot
// be attributed to a step. On failure it returns the zero time and one of the
// DLPEventStart reason constants; a failure is never reported as a time.
func ParseDLPEventStart(raw, taskID string) (time.Time, string) {
	if taskID == "" {
		return time.Time{}, DLPEventStartNoMarker
	}
	var matches []string
	for _, m := range dlpEventStartRe.FindAllStringSubmatch(raw, -1) {
		if m[1] == taskID {
			matches = append(matches, m[2])
		}
	}
	switch len(matches) {
	case 0:
		return time.Time{}, DLPEventStartNoMarker
	case 1:
	default:
		return time.Time{}, DLPEventStartAmbiguous
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(matches[0]))
	if err != nil {
		return time.Time{}, DLPEventStartUnparseable
	}
	return at.UTC(), ""
}
