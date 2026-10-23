package dbprobe

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// Probe ids and fixed fixture addressing of the Task 14 probes.
const (
	ProbeReadClassifiedFixture = "read_classified_fixture"
	ProbeAuthAfterRevoke       = "auth_after_revoke"

	// ClassifiedFixtureKind / ClassifiedFixtureTable are the catalog fixture and
	// table read_classified_fixture addresses (fixtures.KindClassifiedPII and its
	// customers_pii table; a fixtures test pins the equality).
	ClassifiedFixtureKind  = "classified-pii"
	ClassifiedFixtureTable = "customers_pii"
	// RevokeFixtureKind is the (otherwise unused) fixture auth_after_revoke rides
	// on: the smallest catalog fixture, whose id names the throwaway account.
	RevokeFixtureKind = "empty"
)

// Step outcomes of auth_after_revoke, reported in one typed note
// "revoke_steps=create=<v>,baseline=<v>,revoke=<v>,reconnect=<v>". The
// orchestrator parses it with dbsim.Notes.Revocation (same vocabulary).
const (
	RevokeStepsKey = "revoke_steps"

	RevokeStepOK      = "ok"
	RevokeStepFailed  = "failed"
	RevokeStepSkipped = "skipped" // an earlier step failed, so this one was not attempted

	// Reconnect outcomes (after the revoke).
	RevokeReconnectDenied    = "denied"    // authentication refused: the login is revoked
	RevokeReconnectConnected = "connected" // a NEW connection succeeded: the revoke did not hold
	RevokeReconnectError     = "error"     // refused or failed for any other reason (network, TLS, timeout, unknown)
)

// RevokeStepsNote renders the per-step outcome note.
func RevokeStepsNote(create, baseline, revoke, reconnect string) string {
	return RevokeStepsKey + "=create=" + create + ",baseline=" + baseline + ",revoke=" + revoke + ",reconnect=" + reconnect
}

// NewThrowawayPassword returns a fresh random password for the throwaway
// account: 32 random bytes as hex, so it is safe to place in a quoted literal
// (the account statements cannot take bound parameters). It is a local value
// only: never logged, returned, noted or put on the wire.
func NewThrowawayPassword() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("dbprobe: throwaway password generation failed")
	}
	return hex.EncodeToString(b[:]), nil
}

var throwawayID = regexp.MustCompile(`^[a-z0-9_]{1,20}$`)

// ThrowawayAccountName is the login account auth_after_revoke creates:
// dbsim_<fixture id>_acct. The fixture id is normalised the same way as the
// adapters' fixture names and re-validated; the result is at most 31 bytes of
// [a-z0-9_], so it fits both engines' limits and is safe to quote.
func ThrowawayAccountName(fixtureID string) (string, error) {
	id := strings.ReplaceAll(strings.ToLower(fixtureID), "-", "_")
	if !throwawayID.MatchString(id) {
		return "", errors.New("dbprobe: invalid fixture id for the throwaway account")
	}
	return "dbsim_" + id + "_acct", nil
}
