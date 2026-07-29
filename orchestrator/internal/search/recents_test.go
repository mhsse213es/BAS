package search

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRecents_FavoritesBeforeRecentsDedupedAndLimited(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "recents-user")

		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "fav1", Title: "Favorited Scenario"},
			{DocType: "scenario", SourceID: "rec1", Title: "Recently Opened Scenario"},
			{DocType: "scenario", SourceID: "both1", Title: "Favorited AND Selected"},
		}); err != nil {
			t.Fatalf("seed search_documents: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,'scenario','fav1'),($1,'scenario','both1')`,
			userID); err != nil {
			t.Fatalf("seed favorites: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','rec1'),($1,'scenario','both1')`,
			userID); err != nil {
			t.Fatalf("seed selections: %v", err)
		}

		out, err := Recents(ctx, pool, userID, 5)
		if err != nil {
			t.Fatalf("Recents: %v", err)
		}

		var sawFav1, sawBoth1, sawRec1 bool
		both1Count := 0
		for _, d := range out {
			switch d.SourceID {
			case "fav1":
				sawFav1 = true
				if !d.Favorited {
					t.Errorf("fav1.Favorited = false, want true")
				}
			case "both1":
				sawBoth1 = true
				both1Count++
				if !d.Favorited {
					t.Errorf("both1.Favorited = false, want true")
				}
			case "rec1":
				sawRec1 = true
				if d.Favorited {
					t.Errorf("rec1.Favorited = true, want false (never favorited)")
				}
			}
		}
		if !sawFav1 || !sawBoth1 || !sawRec1 {
			t.Fatalf("Recents() = %+v, want fav1, both1, and rec1 all present", out)
		}
		if both1Count != 1 {
			t.Fatalf("both1 (favorited AND selected) appeared %d times, want exactly 1 (deduped, not double-listed)", both1Count)
		}
	})
}

func TestRecents_NoHistoryReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "no-recents-user")

		out, err := Recents(ctx, pool, userID, 5)
		if err != nil {
			t.Fatalf("Recents: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("Recents() = %+v, want empty for a user with no favorites/selections", out)
		}
	})
}
