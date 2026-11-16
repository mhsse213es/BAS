package cigate

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestStore_IssuedTokenVerifiesAndIsStoredOnlyAsHash(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)

		token, info, err := s.Create(ctx, "release pipeline", "admin-user")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if info.Name != "release pipeline" || info.CreatedBy != "admin-user" || info.ID == "" {
			t.Fatalf("Create returned %+v", info)
		}

		var stored string
		if err := pool.QueryRow(ctx, `SELECT token_hash FROM ci_tokens WHERE id = $1`, info.ID).Scan(&stored); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if stored == token || strings.Contains(stored, token) || stored != HashToken(token) {
			t.Fatalf("the database must hold only the hash, got %q", stored)
		}

		got, err := s.Verify(ctx, token)
		if err != nil {
			t.Fatalf("Verify of a fresh token: %v", err)
		}
		if got.ID != info.ID || got.LastUsedAt == nil {
			t.Fatalf("Verify = %+v, want id %s with last_used_at set", got, info.ID)
		}
	})
}

func TestStore_UnknownAndRevokedTokensAreRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)

		other, _ := NewToken()
		if _, err := s.Verify(ctx, other); !errors.Is(err, ErrNoToken) {
			t.Fatalf("a token never issued: err = %v, want ErrNoToken", err)
		}

		token, info, err := s.Create(ctx, "to revoke", "admin-user")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Revoke(ctx, info.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if _, err := s.Verify(ctx, token); !errors.Is(err, ErrNoToken) {
			t.Fatalf("a revoked token still verified: err = %v", err)
		}
		if err := s.Revoke(ctx, info.ID); !errors.Is(err, ErrNoToken) {
			t.Fatalf("revoking twice: err = %v, want ErrNoToken", err)
		}
		if err := s.Revoke(ctx, "no-such-id"); !errors.Is(err, ErrNoToken) {
			t.Fatalf("revoking an unknown id: err = %v, want ErrNoToken", err)
		}
	})
}

func TestStore_ListNeverCarriesSecretsAndShowsRevocation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)

		keep, kept, _ := s.Create(ctx, "keep", "u")
		_, gone, _ := s.Create(ctx, "gone", "u")
		if err := s.Revoke(ctx, gone.ID); err != nil {
			t.Fatal(err)
		}

		list, err := s.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("List returned %d tokens, want 2", len(list))
		}
		for _, ti := range list {
			switch ti.ID {
			case kept.ID:
				if ti.RevokedAt != nil {
					t.Errorf("active token listed as revoked")
				}
			case gone.ID:
				if ti.RevokedAt == nil {
					t.Errorf("revoked token not marked revoked")
				}
			default:
				t.Errorf("unexpected token %s", ti.ID)
			}
		}
		if strings.Contains(strings.Join(func() []string {
			out := []string{}
			for _, ti := range list {
				out = append(out, ti.Name, ti.CreatedBy, ti.ID)
			}
			return out
		}(), " "), keep) {
			t.Fatal("List exposed a token secret")
		}
	})
}

func TestService_StatusOfUnknownRunIsNotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		svc := NewService(pool, nil, nil, "lab")
		if _, err := svc.Status(context.Background(), "no-such-run"); !errors.Is(err, ErrNoRun) {
			t.Fatalf("Status(unknown) err = %v, want ErrNoRun", err)
		}
	})
}
