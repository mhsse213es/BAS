package cigate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoToken is returned when a presented CI token is unknown, revoked or was never issued.
var ErrNoToken = errors.New("cigate: no active token")

// TokenInfo describes an issued CI token without its secret.
type TokenInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedBy  string     `json:"createdBy"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Store keeps CI tokens. Only the hash of a token is written.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Create issues a token. The plaintext is returned once and is not stored.
func (s *Store) Create(ctx context.Context, name, createdBy string) (token string, info TokenInfo, err error) {
	token, err = NewToken()
	if err != nil {
		return "", TokenInfo{}, err
	}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO ci_tokens (name, token_hash, created_by) VALUES ($1, $2, $3)
		 RETURNING id, name, created_by, created_at`,
		name, HashToken(token), createdBy,
	).Scan(&info.ID, &info.Name, &info.CreatedBy, &info.CreatedAt)
	if err != nil {
		return "", TokenInfo{}, err
	}
	return token, info, nil
}

// List returns every issued token, newest first, without secrets.
func (s *Store) List(ctx context.Context) ([]TokenInfo, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, created_by, created_at, last_used_at, revoked_at
		   FROM ci_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenInfo{}
	for rows.Next() {
		var t TokenInfo
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke disables a token. Revoking an unknown or already revoked token is an error.
func (s *Store) Revoke(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE ci_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoToken
	}
	return nil
}

// Verify checks a presented token and records its use. It returns ErrNoToken for anything not active.
func (s *Store) Verify(ctx context.Context, token string) (TokenInfo, error) {
	var t TokenInfo
	err := s.pool.QueryRow(ctx,
		`UPDATE ci_tokens SET last_used_at = NOW()
		  WHERE token_hash = $1 AND revoked_at IS NULL
		  RETURNING id, name, created_by, created_at, last_used_at, revoked_at`,
		HashToken(token),
	).Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenInfo{}, ErrNoToken
	}
	return t, err
}
