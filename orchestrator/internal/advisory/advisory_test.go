package advisory

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// The owner-supplied CERT-In sample. It is the format this parser was built
// against, not a verified copy of the live feed.
const certInSample = `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>CERT-In Vulnerabilities and Advisories</title>
    <item>
      <title>CIAD-2026-0042: Multiple Vulnerabilities in OpenSSL</title>
      <link>https://www.cert-in.org.in/s2cMain-web?pageid=vulnAdvisories&amp;vulnid=CIAD-2026-0042</link>
      <description>CERT-In has received reports of multiple vulnerabilities in OpenSSL...</description>
      <pubDate>Wed, 11 Nov 2026 08:00:00 +0530</pubDate>
      <guid isPermaLink="false">CIAD-2026-0042</guid>
    </item>
  </channel>
</rss>`

func TestParseCERTInSample(t *testing.T) {
	items, skipped, err := ParseCERTInRSS([]byte(certInSample), "cert-in:vulnAdvisories")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skipped != 0 || len(items) != 1 {
		t.Fatalf("items=%d skipped=%d, want 1 and 0", len(items), skipped)
	}
	it := items[0]
	if it.Source != "cert_in" || it.ExternalID != "CIAD-2026-0042" {
		t.Errorf("source/id = %s/%s", it.Source, it.ExternalID)
	}
	if it.Title != "CIAD-2026-0042: Multiple Vulnerabilities in OpenSSL" {
		t.Errorf("title = %q", it.Title)
	}
	if it.PublishedAt.IsZero() {
		t.Error("pubDate not parsed")
	}
}

func TestParseCERTInFallsBackToLinkIDAndSkipsBadItems(t *testing.T) {
	raw := `<rss version="2.0"><channel>
	<item><title>No guid</title><link>https://x/?vulnid=CIAD-9</link></item>
	<item><title></title><guid>CIAD-10</guid></item>
	</channel></rss>`
	items, skipped, err := ParseCERTInRSS([]byte(raw), "ref")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(items) != 1 || items[0].ExternalID != "CIAD-9" || skipped != 1 {
		t.Fatalf("items=%+v skipped=%d", items, skipped)
	}
}

func TestParseCERTInEmptyFeedIsAnError(t *testing.T) {
	if _, _, err := ParseCERTInRSS([]byte(`<rss version="2.0"><channel></channel></rss>`), "ref"); !errors.Is(err, ErrNoItems) {
		t.Fatalf("empty feed: got %v, want ErrNoItems", err)
	}
}

func TestParseFSISACKeepsOnlyReports(t *testing.T) {
	raw := `{"type":"bundle","id":"bundle--1","objects":[
	  {"type":"indicator","id":"indicator--1","name":"ioc"},
	  {"type":"report","id":"report--1","name":"FS-ISAC advisory A","published":"2026-11-10T09:00:00Z","description":"details"},
	  {"type":"report","id":"","name":"no id"}
	]}`
	items, err := ParseFSISACBundle([]byte(raw), "fsisac:collection-1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(items) != 1 || items[0].ExternalID != "report--1" || items[0].Source != "fs_isac" {
		t.Fatalf("items=%+v, want only report--1", items)
	}
}

func TestParseFSISACRejectsNonBundle(t *testing.T) {
	if _, err := ParseFSISACBundle([]byte(`{"type":"indicator"}`), "ref"); err == nil {
		t.Fatal("non-bundle accepted")
	}
}

func items(src string, n int) []Item {
	var out []Item
	for i := 0; i < n; i++ {
		out = append(out, Item{Source: src, ExternalID: "EXT-" + string(rune('a'+i)), Title: "t", SourceRef: "ref"})
	}
	return out
}

func TestIntakeDedupesOnSourceAndExternalID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		st := NewStore(pool)
		first, err := st.Intake(ctx, items("cert_in", 2))
		if err != nil || first.Inserted != 2 || first.Duplicates != 0 {
			t.Fatalf("first intake = %+v, %v", first, err)
		}
		again, err := st.Intake(ctx, items("cert_in", 2))
		if err != nil || again.Inserted != 0 || again.Duplicates != 2 {
			t.Fatalf("re-poll = %+v, %v; want all duplicates", again, err)
		}
		// Same external ID from a different source is a different advisory.
		other, err := st.Intake(ctx, items("fs_isac", 2))
		if err != nil || other.Inserted != 2 {
			t.Fatalf("other source = %+v, %v", other, err)
		}
	})
}

func TestDecisionRulesAndOneOriginalPerAdvisory(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		st := NewStore(pool)
		if _, err := st.Intake(ctx, []Item{{Source: "cert_in", ExternalID: "RULE-1", Title: "t", SourceRef: "ref"}}); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := pool.QueryRow(ctx, `SELECT id FROM advisory_intake WHERE external_id='RULE-1'`).Scan(&id); err != nil {
			t.Fatal(err)
		}

		if err := st.Decide(ctx, id, "system", "relevant", "", ""); !errors.Is(err, ErrInvalidDecision) {
			t.Errorf("non-user decider: %v", err)
		}
		if err := st.Decide(ctx, id, "user:analyst1", "excluded", "", ""); !errors.Is(err, ErrInvalidDecision) {
			t.Errorf("exclusion without code: %v", err)
		}
		if err := st.Decide(ctx, id, "user:analyst1", "excluded", contentregistry.ExclusionReason("free text"), ""); !errors.Is(err, ErrInvalidDecision) {
			t.Errorf("exclusion with free text: %v", err)
		}
		if err := st.Decide(ctx, id, "user:analyst1", "relevant", contentregistry.ExclusionRelevance, ""); !errors.Is(err, ErrInvalidDecision) {
			t.Errorf("relevant with code: %v", err)
		}

		if err := st.Decide(ctx, id, "user:analyst1", "relevant", "", "in scope"); err != nil {
			t.Fatalf("first decision: %v", err)
		}
		if err := st.Decide(ctx, id, "user:analyst2", "excluded", contentregistry.ExclusionRelevance, ""); !errors.Is(err, ErrAlreadyDecided) {
			t.Errorf("second original decision: %v, want ErrAlreadyDecided", err)
		}
	})
}

func TestReversalKeepsHistoryAndMovesCount(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		st := NewStore(pool)
		if _, err := st.Intake(ctx, []Item{{Source: "fs_isac", ExternalID: "REV-1", Title: "t", SourceRef: "ref"}}); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := pool.QueryRow(ctx, `SELECT id FROM advisory_intake WHERE external_id='REV-1'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := st.Reverse(ctx, id, "user:analyst1", "relevant", "", ""); !errors.Is(err, ErrNoDecision) {
			t.Fatalf("reverse with no decision: %v", err)
		}
		if err := st.Decide(ctx, id, "user:analyst1", "excluded", contentregistry.ExclusionUnsupportedPlatform, ""); err != nil {
			t.Fatal(err)
		}
		if err := st.Reverse(ctx, id, "user:analyst2", "relevant", "", "platform now supported"); err != nil {
			t.Fatalf("reverse: %v", err)
		}
		var rows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_relevance WHERE advisory_id=$1`, id).Scan(&rows); err != nil || rows != 2 {
			t.Fatalf("audit rows = %d, %v; want 2 (old decision kept)", rows, err)
		}
		counts, err := st.Counts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if counts["relevant"] < 1 {
			t.Errorf("current decision not counted as relevant: %v", counts)
		}
	})
}

func TestDatabaseRefusesExcludedWithoutCode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		st := NewStore(pool)
		if _, err := st.Intake(ctx, []Item{{Source: "cert_in", ExternalID: "DB-1", Title: "t", SourceRef: "ref"}}); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := pool.QueryRow(ctx, `SELECT id FROM advisory_intake WHERE external_id='DB-1'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO advisory_relevance (advisory_id, decision, decided_by) VALUES ($1,'excluded','user:x')`, id); err == nil {
			t.Fatal("database accepted an excluded decision with no reason code")
		}
	})
}

func TestLedgerRecordsReceivedAndClassified(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		st := NewStore(pool)
		if _, err := st.Intake(ctx, []Item{{Source: "cert_in", ExternalID: "LED-1", Title: "t", SourceRef: "ref"}}); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := pool.QueryRow(ctx, `SELECT id FROM advisory_intake WHERE external_id='LED-1'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := st.Decide(ctx, id, "user:analyst1", "relevant", "", ""); err != nil {
			t.Fatal(err)
		}
		var got []string
		rows, err := pool.Query(ctx,
			`SELECT event_type FROM tcf_pipeline_events
			  WHERE event_type IN ('advisory_received','advisory_classified')
			    AND (source_pk = $1 OR source_table = 'advisory_relevance')
			  ORDER BY event_type`, id)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var et string
			if err := rows.Scan(&et); err != nil {
				t.Fatal(err)
			}
			got = append(got, et)
		}
		if len(got) < 2 {
			t.Fatalf("ledger events = %v, want advisory_received and advisory_classified", got)
		}
	})
}
