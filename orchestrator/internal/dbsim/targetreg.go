package dbsim

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// ErrTargetInvalid wraps every registration validation failure.
var ErrTargetInvalid = errors.New("dbsim target invalid")

// ErrTargetExists means a target with that id is already registered.
var ErrTargetExists = errors.New("dbsim target already registered")

var (
	reTargetID     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	reHostname     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)
	reDatabaseName = regexp.MustCompile(`^[A-Za-z0-9_.$-]{0,63}$`)
	// reCredentialRef mirrors the agent's resolver (agent/dbcred.go dbcredRefRE).
	reCredentialRef = regexp.MustCompile(`^dbcred:[a-z0-9][a-z0-9-]{0,62}$`)
	rePGIdentity    = regexp.MustCompile(`^[0-9]{1,20}$`)
	reMyIdentity    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// TargetRegistration is what an Admin supplies to register a target. It holds a
// credential REFERENCE only (never a secret) and the identity the server must
// prove (PG system_identifier / MySQL server_uuid, spec R6).
type TargetRegistration struct {
	ID          string
	DisplayName string
	Engine      string
	// Host and Port say where the agent connects. DBServerHost is the database
	// server's own host or IP as the alert source reports it (spec R1: alerts are
	// queried for both this and the agent IP); it defaults to Host.
	Host         string
	Port         int
	DBServerHost string
	Database     string
	TLSMode      string
	// CredentialRef is the opaque "dbcred:<name>" reference resolved on the agent.
	CredentialRef string
	// ExpectedIdentity is supplied at registration for every target (R6). Client
	// mode never trusts the first identity it sees. (Lab discover-then-confirm is
	// not implemented: a lab target also needs its identity up front.)
	ExpectedIdentity string
	// Mode is the one mode this target is eligible for: lab or client.
	Mode ExecMode
	// LabConfirmed is the operator's confirmation that a lab target is a lab
	// (mutation-eligible). It is meaningless, and refused, for a client target.
	LabConfirmed bool
}

// Normalize validates the registration and returns it with defaults applied and
// the identity in canonical form. Every error wraps ErrTargetInvalid.
func (r TargetRegistration) Normalize() (TargetRegistration, error) {
	bad := func(f string, a ...any) (TargetRegistration, error) {
		return TargetRegistration{}, fmt.Errorf("%w: %s", ErrTargetInvalid, fmt.Sprintf(f, a...))
	}
	r.ID = strings.TrimSpace(r.ID)
	if !reTargetID.MatchString(r.ID) {
		return bad("id must be 1-63 characters of a-z 0-9 . _ - starting with a letter or digit")
	}
	r.DisplayName = strings.TrimSpace(r.DisplayName)
	if r.DisplayName == "" {
		r.DisplayName = r.ID
	}
	if len(r.DisplayName) > 100 || strings.IndexFunc(r.DisplayName, unicode.IsControl) >= 0 {
		return bad("display name must be at most 100 characters without control characters")
	}
	if r.Engine != "postgresql" && r.Engine != "mysql" {
		return bad("engine must be postgresql or mysql")
	}
	r.Host = strings.TrimSpace(r.Host)
	if !validHost(r.Host) {
		return bad("host must be a host name or IP address")
	}
	r.DBServerHost = strings.TrimSpace(r.DBServerHost)
	if r.DBServerHost == "" {
		r.DBServerHost = r.Host
	}
	if !validHost(r.DBServerHost) {
		return bad("DB server host must be a host name or IP address")
	}
	if r.Port == 0 {
		r.Port = map[string]int{"postgresql": 5432, "mysql": 3306}[r.Engine]
	}
	if r.Port < 1 || r.Port > 65535 {
		return bad("port must be 1-65535")
	}
	r.Database = strings.TrimSpace(r.Database)
	if !reDatabaseName.MatchString(r.Database) {
		return bad("database name has unsupported characters")
	}
	switch r.TLSMode {
	case "", "verify-full", "insecure-skip-verify", "disable":
	default:
		return bad("tlsMode must be empty, verify-full, insecure-skip-verify or disable")
	}
	if !reCredentialRef.MatchString(r.CredentialRef) {
		return bad(`credentialRef must be a reference of the form "dbcred:<name>" (lower case letters, digits, -); never a password`)
	}
	id := strings.TrimSpace(r.ExpectedIdentity)
	if id == "" {
		return bad("expected identity is required (PostgreSQL system_identifier / MySQL server_uuid): client mode never trusts the first identity it sees")
	}
	switch r.Engine {
	case "postgresql":
		if !rePGIdentity.MatchString(id) {
			return bad("a PostgreSQL expected identity is the numeric system_identifier")
		}
	case "mysql":
		id = strings.ToLower(id)
		if !reMyIdentity.MatchString(id) {
			return bad("a MySQL expected identity is the server_uuid")
		}
	}
	r.ExpectedIdentity = id
	switch r.Mode {
	case ModeLab, ModeClient:
	default:
		return bad("mode must be lab or client")
	}
	if r.Mode == ModeClient && r.LabConfirmed {
		return bad("a client target cannot be lab-confirmed")
	}
	return r, nil
}

func validHost(h string) bool {
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	return reHostname.MatchString(h)
}

// IdentityCheckState is the last read-only identity check of a target.
type IdentityCheckState struct {
	Checked bool // a check has been recorded
	Passed  bool
	At      time.Time
	By      string // actor id that ran it
	Reasons []string
}

// TargetRecord is a registered target as stored.
type TargetRecord struct {
	TargetRegistration
	CreatedBy     string
	CreatedAt     time.Time
	IdentityCheck IdentityCheckState
}

// DefaultIdentityCheckMaxAge is how long a passed read-only identity check
// verifies a target. 24h is a PLACEHOLDER: the validity period is an open user
// decision. A pass at or beyond this age, or dated in the future, verifies
// nothing (fail closed).
const DefaultIdentityCheckMaxAge = 24 * time.Hour

// ErrTargetChanged means the target was deleted, re-registered or edited after
// the record a result was produced for was read; the result is not recorded.
var ErrTargetChanged = errors.New("dbsim target changed since the check started")

// ErrIdentityCheckSuperseded means a newer identity-check result is already
// recorded for the target; an older (slower) result never overwrites it.
var ErrIdentityCheckSuperseded = errors.New("dbsim identity check superseded by a newer result")

// SameConfig reports whether two records describe the same registered target
// version: id, creation time and every field a check result depends on. The
// identity-check state itself is deliberately not compared.
func (r TargetRecord) SameConfig(o TargetRecord) bool {
	return r.ID == o.ID && r.CreatedAt.Equal(o.CreatedAt) && r.Engine == o.Engine && r.Host == o.Host &&
		r.Port == o.Port && r.Database == o.Database && r.TLSMode == o.TLSMode && r.CredentialRef == o.CredentialRef &&
		r.ExpectedIdentity == o.ExpectedIdentity && r.Mode == o.Mode && r.DBServerHost == o.DBServerHost
}

// ToTarget is ToTargetAt with the real clock and DefaultIdentityCheckMaxAge.
func (r TargetRecord) ToTarget() Target { return r.ToTargetAt(time.Now(), DefaultIdentityCheckMaxAge) }

// ToTargetAt converts a stored record to the Target the gates consume. The trust
// flags come only from the stored record: ReadOnlyIdentityVerified needs a
// recorded, passed check on a client target that is younger than maxAge at now
// (exactly maxAge fails; a non-positive maxAge or a timestamp in the future or
// missing never verifies); LabConfirmed needs a lab target.
func (r TargetRecord) ToTargetAt(now time.Time, maxAge time.Duration) Target {
	c := r.IdentityCheck
	fresh := maxAge > 0 && !c.At.IsZero() && !c.At.After(now) && now.Sub(c.At) < maxAge
	return Target{
		ID: r.ID, Engine: r.Engine, Host: r.Host, Port: r.Port, Database: r.Database, TLSMode: r.TLSMode,
		CredentialRef: r.CredentialRef, Mode: r.Mode, ExpectedIdentity: r.ExpectedIdentity,
		ReadOnlyIdentityVerified: r.Mode == ModeClient && c.Checked && c.Passed && fresh,
		LabConfirmed:             r.Mode == ModeLab && r.LabConfirmed,
	}
}

// AuthorizeIdentityCheck is the gate for the read-only identity check itself.
// The check is the step that earns ReadOnlyIdentityVerified, so it cannot
// require it; it also does not require the client mode setting (it only reads
// catalogs and the action is Admin-only). It still needs a registered identity,
// a supported engine, a valid mode, a credential reference and a bounded run.
func AuthorizeIdentityCheck(t Target, now, runExpiry time.Time) error {
	if runExpiry.IsZero() || !now.Before(runExpiry) {
		return fmt.Errorf("dbsim: authorize identity check: run has no valid expiry")
	}
	e, ok := LookupProbeEntry(ProbeCheckReadOnlyIdentity)
	if !ok || e.Class != ClassReadOnly {
		return fmt.Errorf("dbsim: authorize identity check: probe %q is not a registered read_only probe", ProbeCheckReadOnlyIdentity)
	}
	supported := false
	for _, eng := range e.Engines {
		supported = supported || eng == t.Engine
	}
	if !supported {
		return fmt.Errorf("dbsim: authorize identity check: engine %q not supported", t.Engine)
	}
	if t.Mode != ModeLab && t.Mode != ModeClient {
		return fmt.Errorf("dbsim: authorize identity check: invalid mode %q", t.Mode)
	}
	if strings.TrimSpace(t.ExpectedIdentity) == "" {
		return fmt.Errorf("dbsim: authorize identity check: target %q has no pre-registered identity", t.ID)
	}
	if !reCredentialRef.MatchString(t.CredentialRef) {
		return fmt.Errorf("dbsim: authorize identity check: target %q has no valid credential reference", t.ID)
	}
	return nil
}

// ClientModeSettingKey is the dbsim_settings key of the Admin "DB client mode"
// setting.
const ClientModeSettingKey = "client_mode_enabled"

// ClientModeFromSetting interprets a stored setting fail closed: only an
// exactly-"true" value that was found and read without error turns client mode
// on. Missing, unreadable, or any other value means OFF.
func ClientModeFromSetting(value string, found bool, err error) bool {
	return err == nil && found && value == "true"
}

// TargetsSchemaSQL is the DDL for dbsim_targets (executed in order,
// idempotent). It holds credential REFERENCES, never secrets.
var TargetsSchemaSQL = []string{
	`CREATE TABLE IF NOT EXISTS dbsim_targets (
			id                     text        PRIMARY KEY,
			display_name           text        NOT NULL,
			engine                 text        NOT NULL CHECK (engine IN ('postgresql', 'mysql')),
			host                   text        NOT NULL,
			port                   integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
			db_server_host         text        NOT NULL,
			database_name          text        NOT NULL DEFAULT '',
			tls_mode               text        NOT NULL DEFAULT '',
			credential_ref         text        NOT NULL,
			expected_identity      text        NOT NULL CHECK (expected_identity <> ''),
			mode                   text        NOT NULL CHECK (mode IN ('lab', 'client')),
			lab_confirmed          boolean     NOT NULL DEFAULT false,
			created_by             text        NOT NULL,
			created_at             timestamptz NOT NULL DEFAULT NOW(),
			identity_check_passed  boolean     NOT NULL DEFAULT false,
			identity_check_at      timestamptz,
			identity_check_by      text        NOT NULL DEFAULT '',
			identity_check_reasons jsonb       NOT NULL DEFAULT '[]'::jsonb,
			CHECK (NOT (mode = 'client' AND lab_confirmed))
		)`,
}

// SettingsSchemaSQL is the DDL for dbsim_settings (executed in order,
// idempotent): a tiny key/value table for the Admin-controlled switches.
var SettingsSchemaSQL = []string{
	`CREATE TABLE IF NOT EXISTS dbsim_settings (
			key        text        PRIMARY KEY,
			value      text        NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT NOW(),
			updated_by text        NOT NULL DEFAULT ''
		)`,
}
