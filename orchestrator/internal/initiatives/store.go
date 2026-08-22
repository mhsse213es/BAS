package initiatives

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const initiativeColumns = `id, name, description, state, created_by, created_at, closed_at, archived_at`

func scanInitiative(row pgx.Row) (Initiative, error) {
	var it Initiative
	err := row.Scan(&it.ID, &it.Name, &it.Description, &it.State, &it.CreatedBy, &it.CreatedAt, &it.ClosedAt, &it.ArchivedAt)
	return it, err
}

// Create makes a new Initiative in StateActive.
func (s *Store) Create(ctx context.Context, name, description, createdBy string) (Initiative, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO initiatives (name, description, state, created_by) VALUES ($1,$2,$3,$4)
		 RETURNING `+initiativeColumns,
		name, description, StateActive, createdBy)
	return scanInitiative(row)
}

func (s *Store) Get(ctx context.Context, id string) (Initiative, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+initiativeColumns+` FROM initiatives WHERE id=$1`, id)
	return scanInitiative(row)
}

// List returns every Initiative, optionally narrowed to one state
// ("" means every state), newest first.
func (s *Store) List(ctx context.Context, state string) ([]Initiative, error) {
	var rows pgx.Rows
	var err error
	if state == "" {
		rows, err = s.pool.Query(ctx, `SELECT `+initiativeColumns+` FROM initiatives ORDER BY created_at DESC`)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT `+initiativeColumns+` FROM initiatives WHERE state=$1 ORDER BY created_at DESC`, state)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Initiative
	for rows.Next() {
		it, err := scanInitiative(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
