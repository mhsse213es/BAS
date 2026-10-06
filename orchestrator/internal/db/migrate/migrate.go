// Package migrate applies the embedded schema migrations and reference-data
// seed (H1). It is the only code that changes the schema; the server checks
// versions at startup and never runs DDL.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strconv"

	gomigrate "github.com/golang-migrate/migrate/v4"
	pgx5 "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/audspect/bas/internal/db/migrations"
	"github.com/audspect/bas/internal/db/schemacheck"
	"github.com/audspect/bas/internal/db/seed"
)

// lockID serialises migrate runs (adoption, schema, seed, role) per database.
const lockID int64 = 7264110001

var (
	ErrDirty        = errors.New("database schema is dirty")
	ErrNewer        = errors.New("database schema is newer than this release")
	ErrUnrecognised = errors.New("database is not an Audspect schema")
)

// Options control Up.
type Options struct {
	AppPassword string    // bas_app password (role step)
	SkipRole    bool      // tests that do not exercise roles
	Out         io.Writer // progress lines; nil discards
	Source      fs.FS     // migration set; nil means migrations.FS
}

// Result describes what Up did.
type Result struct {
	FromVersion, ToVersion uint
	FromSeed, ToSeed       int
	Adopted                bool
	Extra                  []schemacheck.Object // objects outside the baseline found at adoption
	Role                   string
}

// Summary is the one-line operator summary.
func (r Result) Summary() string {
	s := fmt.Sprintf("schema %d→%d, reference data %d→%d", r.FromVersion, r.ToVersion, r.FromSeed, r.ToSeed)
	if r.Adopted {
		s += ", adopted pre-H1 install"
	}
	if r.Role != "" {
		s += ", " + r.Role
	}
	return s
}

func (o Options) source() fs.FS {
	if o.Source == nil {
		return migrations.FS
	}
	return o.Source
}

func (o Options) printf(format string, a ...any) {
	if o.Out != nil {
		fmt.Fprintf(o.Out, format+"\n", a...)
	}
}

// Up brings the database at adminDSN to the newest embedded schema and seed.
func Up(ctx context.Context, adminDSN string, opt Options) (Result, error) {
	var r Result
	if !opt.SkipRole && opt.AppPassword == "" {
		return r, errors.New("bas_app password is empty (BAS_APP_DB_PASSWORD)")
	}
	src := opt.source()
	if err := CheckSet(src); err != nil {
		return r, err
	}
	latest, err := migrations.LatestIn(src)
	if err != nil {
		return r, err
	}
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return r, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return r, fmt.Errorf("advisory lock: %w", err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockID)

	state, version, err := classifyAgainst(ctx, conn, latest)
	if err != nil {
		return r, err
	}
	r.FromVersion = version
	if r.FromSeed, err = seed.Current(ctx, conn); err != nil {
		return r, err
	}
	switch state {
	case Dirty:
		return r, fmt.Errorf("%w: migration %d failed part-way; restore the upgrade snapshot with install.sh --rollback (never repaired automatically)", ErrDirty, version)
	case Newer:
		return r, fmt.Errorf("%w: database is at %d, this release knows %d — run the matching release or install.sh --rollback", ErrNewer, version, latest)
	case Unrecognised:
		return r, fmt.Errorf("%w: public has tables but not the Audspect sentinel set (%v); refusing to touch it", ErrUnrecognised, sentinels)
	case PreH1:
		if r.Extra, err = adopt(ctx, conn, opt); err != nil {
			return r, err
		}
		r.Adopted = true
	}
	opt.printf("migrate: %s, schema version %d", state, r.FromVersion)

	pool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		return r, err
	}
	defer pool.Close()
	m, err := newMigrator(pool, src)
	if err != nil {
		return r, err
	}
	// The migrator's *sql.DB holds pool connections; close it before the pool.
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		return r, fmt.Errorf("migrate up: %w", err)
	}
	v, _, err := m.Version()
	if err != nil {
		return r, err
	}
	r.ToVersion = v
	if r.Adopted {
		if err := finishAdoption(ctx, conn, r.Extra); err != nil {
			return r, err
		}
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(context.Background())
	if err := seed.Apply(ctx, tx); err != nil {
		return r, err
	}
	if err := tx.Commit(ctx); err != nil {
		return r, err
	}
	if r.ToSeed, err = seed.Current(ctx, conn); err != nil {
		return r, err
	}
	if !opt.SkipRole {
		created, err := ensureRole(ctx, conn, opt.AppPassword, adminDSN)
		if err != nil {
			return r, err
		}
		r.Role = AppRole + " ok"
		if created {
			r.Role = AppRole + " created"
		}
	}
	opt.printf("migrate: %s", r.Summary())
	return r, nil
}

// classifyAgainst is Classify with "newer" judged against the source in use.
func classifyAgainst(ctx context.Context, conn *pgx.Conn, latest uint) (State, uint, error) {
	s, v, err := Classify(ctx, conn)
	if err == nil && s == Newer && v <= latest {
		s = Managed
	}
	if err == nil && s == Managed && v > latest {
		s = Newer
	}
	return s, v, err
}

func newMigrator(pool *pgxpool.Pool, src fs.FS) (*gomigrate.Migrate, error) {
	s, err := iofs.New(src, ".")
	if err != nil {
		return nil, err
	}
	drv, err := pgx5.WithInstance(stdlib.OpenDBFromPool(pool), &pgx5.Config{})
	if err != nil {
		return nil, err
	}
	return gomigrate.NewWithInstance("iofs", s, "pgx5", drv)
}

// Status is the read-only view for `migrate status` and the startup check.
type Status struct {
	Version, WantVersion uint
	Dirty                bool
	Seed, WantSeed       int
	Pending              bool
}

// GetStatus reads the recorded versions; it never changes the database.
func GetStatus(ctx context.Context, adminDSN string) (Status, error) {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return Status{}, err
	}
	defer conn.Close(context.Background())
	return readStatus(ctx, conn)
}

func readStatus(ctx context.Context, conn *pgx.Conn) (Status, error) {
	var st Status
	var err error
	if st.WantVersion, err = migrations.Latest(); err != nil {
		return st, err
	}
	if st.WantSeed, err = seed.Version(); err != nil {
		return st, err
	}
	var has bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&has); err != nil {
		return st, err
	}
	if has {
		var v int64
		err := conn.QueryRow(ctx, `SELECT version, dirty FROM public.schema_migrations LIMIT 1`).Scan(&v, &st.Dirty)
		if err != nil && err != pgx.ErrNoRows {
			return st, err
		}
		st.Version = uint(v)
	}
	if st.Seed, err = seed.Current(ctx, conn); err != nil {
		return st, err
	}
	st.Pending = st.Dirty || st.Version != st.WantVersion || st.Seed != st.WantSeed
	return st, nil
}

var setName = regexp.MustCompile(`^(\d{6})_[a-z0-9_]+\.(up|down)\.sql$`)

// CheckSet verifies a migration set: versions 1..N contiguous, one name per
// version, each with .up.sql and .down.sql.
func CheckSet(fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}
	type pair struct {
		name     string
		up, down bool
	}
	got := map[int]*pair{}
	for _, e := range entries {
		if e.IsDir() || !regexp.MustCompile(`\.sql$`).MatchString(e.Name()) {
			continue
		}
		m := setName.FindStringSubmatch(e.Name())
		if m == nil {
			return fmt.Errorf("migration %q: want NNNNNN_name.up.sql / .down.sql", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		base := e.Name()[:len(e.Name())-len(m[2])-5]
		p := got[v]
		if p == nil {
			p = &pair{name: base}
			got[v] = p
		} else if p.name != base {
			return fmt.Errorf("migration version %d used twice (%s, %s)", v, p.name, base)
		}
		if m[2] == "up" {
			p.up = true
		} else {
			p.down = true
		}
	}
	if len(got) == 0 {
		return errors.New("no migrations")
	}
	for v := 1; v <= len(got); v++ {
		p := got[v]
		if p == nil {
			return fmt.Errorf("migration versions not contiguous: %d missing", v)
		}
		if !p.up || !p.down {
			return fmt.Errorf("migration %s needs both .up.sql and .down.sql", p.name)
		}
	}
	return nil
}
