package secretstore

import (
	"context"
	"errors"
	"sort"
)

// Composite is the dual-read store used during migration. Writes go to the primary (customer-controlled) backend only.
// Reads try the primary and fall back to the legacy backend only when the primary has no value for the reference.
//
// The fallback is deliberately narrow. Any other primary error, including a revoked or disabled KEK, is returned
// unchanged. A legacy copy must never answer for a value whose key the customer has withdrawn, or revocation would
// be defeated.
type Composite struct {
	Primary Store
	Legacy  Store
}

// Put writes to the primary backend only. The legacy row is left as it was, and is retired after migration is verified.
func (c *Composite) Put(ctx context.Context, ref, value string) error {
	return c.Primary.Put(ctx, ref, value)
}

// Get returns the primary value. It falls back to the legacy backend only on ErrNotFound.
func (c *Composite) Get(ctx context.Context, ref string) (string, error) {
	v, err := c.Primary.Get(ctx, ref)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	return c.Legacy.Get(ctx, ref)
}

// Delete removes the value from both backends, so a deleted credential cannot come back through the fallback.
func (c *Composite) Delete(ctx context.Context, ref string) error {
	if err := c.Primary.Delete(ctx, ref); err != nil {
		return err
	}
	return c.Legacy.Delete(ctx, ref)
}

// MigrationReport lists the outcome of a migration run. References are reported, never values.
type MigrationReport struct {
	Migrated []string // copied into the primary and read back equal
	Skipped  []string // already present in the primary
	Failed   []string // could not be read from the legacy backend, or did not read back equal; left untouched
}

// Lister is implemented by a backend that can enumerate its references. PGStore implements it.
type Lister interface {
	Refs(ctx context.Context) ([]string, error)
}

// Migrate copies every legacy value into the primary backend, then reads each one back and compares it. A value is
// counted as migrated only when the primary returns exactly the legacy value. Legacy rows are never deleted here.
// Running Migrate again skips what is already in the primary.
func Migrate(ctx context.Context, primary, legacy Store) (MigrationReport, error) {
	var rep MigrationReport
	lister, ok := legacy.(Lister)
	if !ok {
		return rep, errors.New("secretstore: legacy backend cannot list its references")
	}
	refs, err := lister.Refs(ctx)
	if err != nil {
		return rep, errors.New("secretstore: listing legacy references failed")
	}
	sort.Strings(refs)
	for _, ref := range refs {
		if _, err := primary.Get(ctx, ref); err == nil {
			rep.Skipped = append(rep.Skipped, ref)
			continue
		} else if !errors.Is(err, ErrNotFound) {
			rep.Failed = append(rep.Failed, ref)
			continue
		}
		value, err := legacy.Get(ctx, ref)
		if err != nil {
			rep.Failed = append(rep.Failed, ref)
			continue
		}
		if err := primary.Put(ctx, ref, value); err != nil {
			rep.Failed = append(rep.Failed, ref)
			continue
		}
		back, err := primary.Get(ctx, ref)
		if err != nil || back != value {
			rep.Failed = append(rep.Failed, ref)
			continue
		}
		rep.Migrated = append(rep.Migrated, ref)
	}
	return rep, nil
}
