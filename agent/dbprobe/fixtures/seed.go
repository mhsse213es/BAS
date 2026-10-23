package fixtures

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"audspect/agent/dbprobe"
)

// newID generates a fixture id. Production uses crypto/rand: 12 lower-case hex
// characters, accepted by both adapters' fixture-id validation ("dbsim_" + id +
// "_ro" fits MySQL's 32 character user limit). Tests replace it.
var newID = randomID

func randomID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("fixtures: id generation failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// idPat is what Seed accepts from the generator; it is a strict subset of what
// the adapters accept.
var idPat = regexp.MustCompile(`^[a-z0-9]{8,16}$`)

// SchemaName is the dedicated schema a fixture id maps to. It is the only
// schema Seed and Cleanup ever touch.
func SchemaName(id string) string { return "dbsim_" + id }

// Seed creates the synthetic fixture described by spec in a dedicated
// dbsim_<id> schema. Order, all before any DDL/DML:
//
//  1. spec bounds validated (row/column/cell caps, identifier shape)
//  2. adapter must report lab mode (fail closed when it cannot say)
//  3. fresh unique id
//  4. pre-test state of the (new) schema recorded; anything pre-existing refuses
//
// then adapter.Seed runs. On a refusal Seed returns a zero Fixture and nothing
// was sent to the database. When adapter.Seed itself fails the returned Fixture
// has its id set: part of the fixture may exist and the caller must clean up
// (WithFixture does).
func Seed(ctx context.Context, ad dbprobe.Adapter, spec dbprobe.FixtureSpec) (dbprobe.Fixture, error) {
	if spec.Kind == "" {
		return dbprobe.Fixture{}, errors.New("fixtures: fixture spec has no kind")
	}
	if err := dbprobe.ValidateFixtureTables(spec.Tables); err != nil {
		return dbprobe.Fixture{}, err
	}
	mr, ok := ad.(dbprobe.ModeReporter)
	if !ok || mr.Mode() != dbprobe.ModeLab {
		return dbprobe.Fixture{}, errors.New("fixtures: seed refused: fixtures run only against a lab-mode adapter")
	}
	insp, ok := ad.(dbprobe.FixtureInspector)
	if !ok {
		return dbprobe.Fixture{}, errors.New("fixtures: seed refused: adapter cannot inspect fixture state, so cleanup could not be verified")
	}
	id, err := newID()
	if err != nil {
		return dbprobe.Fixture{}, err
	}
	if !idPat.MatchString(id) {
		return dbprobe.Fixture{}, errors.New("fixtures: seed refused: generated fixture id has an unacceptable format")
	}

	fx := dbprobe.Fixture{ID: id, Kind: spec.Kind, Tables: cloneTables(spec.Tables)}
	schema := SchemaName(id)
	fx.Objects = append(fx.Objects, "schema:"+schema)
	for _, t := range spec.Tables {
		fx.Objects = append(fx.Objects, "table:"+schema+"."+t.Name)
	}

	pre, err := insp.InspectFixture(ctx, fx)
	if err != nil {
		return dbprobe.Fixture{}, fmt.Errorf("fixtures: seed refused: pre-test state unreadable: %w", err)
	}
	if len(pre) != 0 {
		sort.Strings(pre)
		return dbprobe.Fixture{}, fmt.Errorf("fixtures: seed refused: schema %s already has objects %v", schema, pre)
	}
	fx.PreState = nil

	if err := ad.Seed(ctx, fx); err != nil {
		if errors.Is(err, dbprobe.ErrFixtureNotCreated) {
			// Nothing of this call exists: return no fixture so the caller
			// issues no Cleanup (and so no DROP) at all.
			return dbprobe.Fixture{}, fmt.Errorf("fixtures: seed failed: %w", err)
		}
		return fx, fmt.Errorf("fixtures: seed failed: %w", err)
	}

	// Runtime visibility check: the schema just created must be visible to the
	// inspection the later VerifyClean relies on. If it is not, "clean" could not
	// be told apart from "cannot see", so fail closed. The fixture is returned
	// (WithFixture still runs the exact-name cleanup) together with errNotVisible.
	seen, verr := insp.InspectFixture(ctx, fx)
	if verr != nil || !contains(seen, "schema:"+schema) {
		return fx, errNotVisible
	}
	return fx, nil
}

// errNotVisible is returned by Seed when the freshly created fixture cannot be
// seen through InspectFixture. WithFixture turns it into a safety incident and
// never runs the probe.
var errNotVisible = errors.New("fixture not visible to inspection; cleanup cannot be verified")

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func cloneTables(in []dbprobe.FixtureTable) []dbprobe.FixtureTable {
	if in == nil {
		return nil
	}
	out := make([]dbprobe.FixtureTable, len(in))
	for i, t := range in {
		out[i] = dbprobe.FixtureTable{Name: t.Name, Columns: append([]dbprobe.FixtureColumn(nil), t.Columns...)}
		for _, r := range t.Rows {
			out[i].Rows = append(out[i].Rows, append([]any(nil), r...))
		}
	}
	return out
}
