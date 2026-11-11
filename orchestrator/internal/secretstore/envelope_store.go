package secretstore

import (
	"context"
	"errors"

	"github.com/audspect/bas/internal/envelope"
	"github.com/audspect/bas/internal/kms"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// envelopeSchemaSQL holds ciphertext sealed by internal/envelope under a customer-controlled KEK. A row cannot be
// read without the provider, so a database dump alone discloses nothing.
const envelopeSchemaSQL = `CREATE TABLE IF NOT EXISTS credential_secrets_envelope (
	ref        text        PRIMARY KEY,
	blob       bytea       NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT NOW()
)`

// envelopeLabelPrefix binds each envelope to the reference it was written for. Without it, a blob copied from one
// credential field to another would open. The reference is authenticated data, so the copy fails.
const envelopeLabelPrefix = "connector_credentials:"

// EnvelopeStore is the customer-controlled backend. It implements Store. Values are sealed with envelope.Manager and
// the KEK named by keyRef. A revoked or disabled KEK makes every read and write fail with the kms error.
type EnvelopeStore struct {
	pool   *pgxpool.Pool
	mgr    *envelope.Manager
	keyRef kms.KeyRef
}

// NewEnvelopeStore returns a store that seals values under keyRef through mgr.
func NewEnvelopeStore(pool *pgxpool.Pool, mgr *envelope.Manager, keyRef kms.KeyRef) (*EnvelopeStore, error) {
	if pool == nil || mgr == nil || keyRef == "" {
		return nil, errors.New("secretstore: envelope store needs a pool, a manager and a key reference")
	}
	return &EnvelopeStore{pool: pool, mgr: mgr, keyRef: keyRef}, nil
}

func label(ref string) string { return envelopeLabelPrefix + ref }

// Put seals value under ref, replacing any earlier value.
func (s *EnvelopeStore) Put(ctx context.Context, ref, value string) error {
	if !ValidRef(ref) {
		return ErrBadRef
	}
	if value == "" {
		return ErrEmptyValue
	}
	blob, err := s.mgr.Seal(ctx, s.keyRef, label(ref), []byte(value))
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO credential_secrets_envelope (ref, blob, updated_at) VALUES ($1, $2, NOW())
		 ON CONFLICT (ref) DO UPDATE SET blob = EXCLUDED.blob, updated_at = NOW()`, ref, blob)
	if err != nil {
		return errors.New("secretstore: put failed")
	}
	return nil
}

// Get returns the value under ref. ErrNotFound means no envelope row exists; any other error, including a revoked
// key, is returned as is and must not be treated as "not found".
func (s *EnvelopeStore) Get(ctx context.Context, ref string) (string, error) {
	if !ValidRef(ref) {
		return "", ErrBadRef
	}
	var blob []byte
	err := s.pool.QueryRow(ctx, `SELECT blob FROM credential_secrets_envelope WHERE ref = $1`, ref).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", errors.New("secretstore: get failed")
	}
	plain, err := s.mgr.Open(ctx, label(ref), blob)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Delete removes the envelope row for ref.
func (s *EnvelopeStore) Delete(ctx context.Context, ref string) error {
	if !ValidRef(ref) {
		return ErrBadRef
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM credential_secrets_envelope WHERE ref = $1`, ref); err != nil {
		return errors.New("secretstore: delete failed")
	}
	return nil
}
