package pipelinecheck

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
)

// MarkerField and MarkerTag identify a record created by a BAS test run. A record is a cleanup
// candidate only if it carries both, together with the exact run identifier.
const (
	MarkerField = "audspect.test_run"
	MarkerTag   = "audspect-bas-test"
)

var (
	testRunIDPattern = regexp.MustCompile(`^bas-[0-9a-f]{32}$`)
	// indexNamePattern allows one explicit lowercase index name. Wildcards, lists and
	// patterns are not matched, so a preview or cleanup can never widen beyond one index.
	indexNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,254}$`)
)

// NewTestRunID returns a new server-generated test-run identifier. The caller never supplies it.
func NewTestRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("test run id: %w", err)
	}
	return "bas-" + hex.EncodeToString(b[:]), nil
}

// ValidTestRunID reports whether id has the exact server-generated form.
func ValidTestRunID(id string) bool { return testRunIDPattern.MatchString(id) }

// ValidIndexName reports whether name is one explicit index, with no wildcard or list.
func ValidIndexName(name string) bool { return indexNamePattern.MatchString(name) }
