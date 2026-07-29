package search

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedSearchUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, password_hash, role, is_active) VALUES ($1, 'x', 'viewer', true) RETURNING id`,
		username).Scan(&id); err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	return id
}

func TestPersonalize_FavoritesSortFirstInOriginalOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "fav-order-user")
		if _, err := pool.Exec(ctx, `INSERT INTO search_favorites (user_id, doc_type, source_id) VALUES ($1,'scenario','s2')`, userID); err != nil {
			t.Fatalf("seed favorite: %v", err)
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "First (relevance order)"},
			{DocType: "scenario", SourceID: "s2", Title: "Second (relevance order, but favorited)"},
			{DocType: "scenario", SourceID: "s3", Title: "Third (relevance order)"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if len(out) != 3 || out[0].SourceID != "s2" {
			t.Fatalf("Personalize() = %+v, want s2 (favorited) first", out)
		}
		if !out[0].Favorited {
			t.Errorf("out[0].Favorited = false, want true")
		}
		if out[1].SourceID != "s1" || out[2].SourceID != "s3" {
			t.Errorf("non-favorited remainder = [%s, %s], want original relevance order [s1, s3]", out[1].SourceID, out[2].SourceID)
		}
	})
}

func TestPersonalize_PersonalRecencyOutranksNeverOpened(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "recency-user")
		if _, err := pool.Exec(ctx, `INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','s2')`, userID); err != nil {
			t.Fatalf("seed selection: %v", err)
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Never opened"},
			{DocType: "scenario", SourceID: "s2", Title: "Recently opened by this user"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if out[0].SourceID != "s2" {
			t.Fatalf("Personalize() = %+v, want s2 (recently opened) ranked first", out)
		}
	})
}

func TestPersonalize_OrgPopularityAffectsUserWithNoPersonalHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		popularUser := seedSearchUser(t, pool, "popular-selector")
		viewerUser := seedSearchUser(t, pool, "no-history-viewer")
		for i := 0; i < 5; i++ {
			if _, err := pool.Exec(ctx, `INSERT INTO search_selections (user_id, doc_type, source_id) VALUES ($1,'scenario','s2')`, popularUser); err != nil {
				t.Fatalf("seed org selection %d: %v", i, err)
			}
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Unopened by anyone"},
			{DocType: "scenario", SourceID: "s2", Title: "Popular org-wide"},
		}
		out, err := Personalize(ctx, pool, viewerUser, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if out[0].SourceID != "s2" {
			t.Fatalf("Personalize() = %+v, want s2 (org-popular) ranked first even with no personal history", out)
		}
	})
}

func TestPersonalize_SelectionsOlderThan30DaysDontAffectRanking(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "stale-history-user")
		old := time.Now().Add(-45 * 24 * time.Hour)
		if _, err := pool.Exec(ctx,
			`INSERT INTO search_selections (user_id, doc_type, source_id, created_at) VALUES ($1,'scenario','s2',$2)`,
			userID, old); err != nil {
			t.Fatalf("seed stale selection: %v", err)
		}

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "First (relevance order)"},
			{DocType: "scenario", SourceID: "s2", Title: "Selected 45 days ago"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		if out[0].SourceID != "s1" {
			t.Fatalf("Personalize() = %+v, want unmodified relevance order (stale selection outside 30-day window must not affect ranking)", out)
		}
	})
}

func TestPersonalize_NoSignalsReturnsUnmodifiedOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		userID := seedSearchUser(t, pool, "no-signal-user")

		results := []Document{
			{DocType: "scenario", SourceID: "s1", Title: "First"},
			{DocType: "scenario", SourceID: "s2", Title: "Second"},
			{DocType: "scenario", SourceID: "s3", Title: "Third"},
		}
		out, err := Personalize(ctx, pool, userID, results)
		if err != nil {
			t.Fatalf("Personalize: %v", err)
		}
		for i, d := range out {
			if d.SourceID != results[i].SourceID {
				t.Fatalf("Personalize() = %+v, want unmodified order %+v", out, results)
			}
		}
	})
}
