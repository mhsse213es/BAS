package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Database credential references (dbsim, spec 4.4 / A7).
//
// A dbprobe step carries only an opaque REFERENCE such as "dbcred:lab-pg-ro";
// the secret never travels in a scenario, a signed envelope, a log or a
// report. The agent resolves the reference locally, in this order:
//
//  1. Environment variable BAS_DBCRED_<NAME> holding JSON
//     {"user":"...","password":"..."}. <NAME> is the reference name upper-cased
//     with '-' mapped to '_' (the reference grammar has no '_', so the
//     mapping is injective). A present-but-malformed variable is an error;
//     it never silently falls through to the store.
//  2. An agent-local protected store:
//     - Windows: DPAPI-protected (machine scope) registry value
//     BAS_DBCRED_<NAME>_ENC (hex blob of the same JSON) under the agent
//     service Parameters key, the same mechanism as the proxy credentials.
//     - Linux/macOS: a root-owned regular file <config dir>/dbcred/<name>.json
//     with mode no wider than 0600 (refused otherwise).
//
// An unresolvable reference is a refusal. There is NEVER a fallback to a
// default account.

// dbcredRefRE is the strict reference grammar: lower-case alphanumerics and
// '-', 1..63 chars after the "dbcred:" prefix, first char alphanumeric. No
// path separators, dots, spaces, underscores or control characters.
var dbcredRefRE = regexp.MustCompile(`\Adbcred:([a-z0-9][a-z0-9-]{0,62})\z`)

var (
	errDBCredBadRef     = errors.New("credential reference is malformed")
	errDBCredUnresolved = errors.New("credential reference could not be resolved on this agent")
	errDBCredMalformed  = errors.New("credential material is malformed")
)

// dbCredential is a resolved secret. It only ever lives in a local variable
// that is copied into dbprobe.ConnectionConfig; String/GoString redact it.
type dbCredential struct {
	User     string
	Password string
}

func (c dbCredential) String() string   { return "dbCredential{user=" + c.User + " password=[redacted]}" }
func (c dbCredential) GoString() string { return c.String() }

// dbcredEnvName returns the environment variable name for a reference name
// (the part after "dbcred:").
func dbcredEnvName(name string) string {
	return "BAS_DBCRED_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// readStoredDBCredential reads the raw JSON for name from the platform store.
// found=false with a nil error means "no entry". Indirected so tests can
// supply a store without touching the registry or /etc.
var readStoredDBCredential = readStoredDBCredentialPlatform

// parseDBCredential strictly decodes the credential JSON. The returned error
// never contains any part of the input.
func parseDBCredential(raw []byte) (dbCredential, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := dec.Decode(&v); err != nil {
		return dbCredential{}, errDBCredMalformed
	}
	if dec.More() {
		return dbCredential{}, errDBCredMalformed
	}
	if v.User == "" {
		return dbCredential{}, errDBCredMalformed
	}
	return dbCredential{User: v.User, Password: v.Password}, nil
}

// resolveDBCredential resolves a credential reference. Errors wrap one of
// errDBCredBadRef / errDBCredUnresolved / errDBCredMalformed (or a store error)
// and never contain secret material.
func resolveDBCredential(ref string) (dbCredential, error) {
	m := dbcredRefRE.FindStringSubmatch(ref)
	if m == nil {
		return dbCredential{}, errDBCredBadRef
	}
	name := m[1]
	if v := os.Getenv(dbcredEnvName(name)); v != "" {
		return parseDBCredential([]byte(v))
	}
	raw, found, err := readStoredDBCredential(name)
	if err != nil {
		return dbCredential{}, fmt.Errorf("credential store for %q refused: %w", ref, err)
	}
	if !found {
		return dbCredential{}, errDBCredUnresolved
	}
	return parseDBCredential(raw)
}
