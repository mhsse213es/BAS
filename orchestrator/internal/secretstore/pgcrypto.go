package secretstore

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SchemaSQL is the DDL for the pgcrypto backend, run in order at startup. The table holds ciphertext only.
var SchemaSQL = []string{
	`CREATE TABLE IF NOT EXISTS credential_secrets (
		ref        text        PRIMARY KEY,
		value_enc  bytea       NOT NULL,
		created_at timestamptz NOT NULL DEFAULT NOW(),
		updated_at timestamptz NOT NULL DEFAULT NOW()
	)`,
}

// PGStore is the interim backend. Each value is encrypted by PostgreSQL with pgcrypto (pgp_sym_encrypt) under the key given
// to NewPGStore. The key is passed to each statement as a parameter and is never written to the database.
type PGStore struct {
	pool *pgxpool.Pool
	key  string
}

// minKeyBytes is the smallest key material accepted: 32 bytes, which is the length LoadKeyFile enforces.
const minKeyBytes = 32

// NewPGStore returns a store that encrypts with key. key is the base64 text of 32 random bytes, as LoadKeyFile returns it.
func NewPGStore(pool *pgxpool.Pool, key string) (*PGStore, error) {
	if pool == nil {
		return nil, errors.New("secretstore: no database pool")
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) < minKeyBytes {
		return nil, errors.New("secretstore: key must be base64 of at least 32 random bytes")
	}
	return &PGStore{pool: pool, key: key}, nil
}

// Put stores value under ref, replacing any earlier value.
func (s *PGStore) Put(ctx context.Context, ref, value string) error {
	if !ValidRef(ref) {
		return ErrBadRef
	}
	if value == "" {
		return ErrEmptyValue
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO credential_secrets (ref, value_enc, updated_at)
		 VALUES ($1, pgp_sym_encrypt($2, $3), NOW())
		 ON CONFLICT (ref) DO UPDATE SET value_enc = EXCLUDED.value_enc, updated_at = NOW()`,
		ref, value, s.key)
	if err != nil {
		// The driver error is not returned: it can name the statement, and the caller must never see a value or the key.
		return errors.New("secretstore: put failed")
	}
	return nil
}

// Get returns the value stored under ref. A wrong key or corrupt ciphertext is an error, never a wrong value.
func (s *PGStore) Get(ctx context.Context, ref string) (string, error) {
	if !ValidRef(ref) {
		return "", ErrBadRef
	}
	var value string
	err := s.pool.QueryRow(ctx,
		`SELECT pgp_sym_decrypt(value_enc, $2) FROM credential_secrets WHERE ref = $1`, ref, s.key,
	).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", errors.New("secretstore: get failed: value could not be decrypted with the configured key")
	}
	return value, nil
}

// Delete removes the value stored under ref.
func (s *PGStore) Delete(ctx context.Context, ref string) error {
	if !ValidRef(ref) {
		return ErrBadRef
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM credential_secrets WHERE ref = $1`, ref); err != nil {
		return errors.New("secretstore: delete failed")
	}
	return nil
}
