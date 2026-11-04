// Package secretstore holds the values of credential fields outside the rows that reference them. A database row keeps only
// an opaque reference (for example "cred:siem_configs:<id>:token"); the value is resolved at the point of use.
//
// The current backend is PGStore: values are encrypted with pgcrypto under a key held in a root-owned file outside
// PostgreSQL (see keyfile.go). This is an interim. The Store interface is the seam for an external secret manager, and a
// future Vault backend implements the same three methods. No caller depends on the backend.
package secretstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// Store keeps credential values by reference. Values never appear in an error, a log line or a returned reference.
type Store interface {
	// Put stores value under ref, replacing any earlier value. An empty value is refused: an empty field means "not set".
	Put(ctx context.Context, ref, value string) error
	// Get returns the value stored under ref, or ErrNotFound.
	Get(ctx context.Context, ref string) (string, error)
	// Delete removes the value stored under ref. Deleting a missing reference is not an error.
	Delete(ctx context.Context, ref string) error
}

var (
	// ErrNotFound means no value is stored under the reference.
	ErrNotFound = errors.New("secretstore: no value stored for this reference")
	// ErrBadRef means the reference does not match the grammar (see ValidRef).
	ErrBadRef = errors.New("secretstore: malformed reference")
	// ErrEmptyValue means a value to store was empty.
	ErrEmptyValue = errors.New("secretstore: empty value refused")
)

// refRE is the reference grammar: a fixed prefix, the table name, the row identifier and the column name. Only lower-case
// letters, digits, '_' and '-' are allowed, so a reference cannot carry a path, a quote or whitespace.
var refRE = regexp.MustCompile(`^cred:[a-z][a-z_]{0,40}:[A-Za-z0-9_-]{1,80}:[a-z][a-z_]{0,40}$`)

// ValidRef reports whether ref matches the reference grammar.
func ValidRef(ref string) bool {
	return refRE.MatchString(ref)
}

// MakeRef builds the reference for one credential field of one row. It fails if any part is malformed.
func MakeRef(table, rowID, column string) (string, error) {
	ref := fmt.Sprintf("cred:%s:%s:%s", table, rowID, column)
	if !ValidRef(ref) {
		return "", ErrBadRef
	}
	return ref, nil
}
