package dbprobe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestEscapeLikeEscapesWildcardsAndEscape(t *testing.T) {
	cases := map[string]string{
		"plain":      "plain",
		"a_b":        `a\_b`,
		"50%":        `50\%`,
		`back\slash`: `back\\slash`,
		"a_b%c\\d":   `a\_b\%c\\d`,
	}
	for in, want := range cases {
		if got := EscapeLike(in); got != want {
			t.Errorf("EscapeLike(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTruncateUTF8OnRuneBoundary(t *testing.T) {
	s := strings.Repeat("a", 510) + "éé" // two 2-byte runes: bytes 510..513
	got := TruncateUTF8(s, 512)
	if len(got) > 512 || !utf8.ValidString(got) {
		t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if len(got) != 512 { // 510 + one full 2-byte rune
		t.Fatalf("expected 512 bytes, got %d", len(got))
	}
	s2 := strings.Repeat("a", 511) + "é" // rune straddles the cut
	got2 := TruncateUTF8(s2, 512)
	if len(got2) != 511 || !utf8.ValidString(got2) {
		t.Fatalf("straddling rune must be dropped whole: len=%d", len(got2))
	}
	if TruncateUTF8("short", 512) != "short" {
		t.Fatal("short strings unchanged")
	}
}

func ev(marker string, sec int, principal string) AuditEvent {
	return AuditEvent{Time: time.Unix(1700000000+int64(sec), 0).UTC(), Principal: principal,
		Statement: "/* dbsim:" + marker + " */ SELECT 1", Source: "src"}
}

func ident(s string) string { return s }

func TestNormalizeAuditKeepsOnlyExactMarkerEvents(t *testing.T) {
	raw := []AuditEvent{
		ev("RUN-1", 0, "u"),
		ev("RUN-2", 1, "u"),                       // other marker
		{Statement: "select 1", Time: time.Now()}, // unmarked
		ev("rUN-1", 2, "u"),                       // case differs: LIKE collation false positive
	}
	got, err := NormalizeAudit(AuditQuery{Marker: "RUN-1"}, raw, ident, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0].Statement, "RUN-1") {
		t.Fatalf("got %+v", got)
	}
}

func TestNormalizeAuditDropsOwnAuditQueries(t *testing.T) {
	own := AuditEvent{Time: time.Now(), Statement: "/* dbsim:dbsim-meta */ SELECT x WHERE m LIKE '%RUN-1%'"}
	got, err := NormalizeAudit(AuditQuery{Marker: "RUN-1"}, []AuditEvent{own, ev("RUN-1", 0, "u")}, ident, false)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestNormalizeAuditPrincipalFilter(t *testing.T) {
	raw := []AuditEvent{ev("M", 0, "alice"), ev("M", 1, "bob"), ev("M", 2, "")}
	got, err := NormalizeAudit(AuditQuery{Marker: "M", Principal: "alice"}, raw, ident, false)
	if err != nil {
		t.Fatal(err)
	}
	// A different known principal is dropped; an unknown principal (thread
	// gone) is kept because the unique marker still ties it to this run.
	if len(got) != 2 || got[0].Principal != "alice" || got[1].Principal != "" {
		t.Fatalf("got %+v", got)
	}
}

func TestNormalizeAuditCapTruncRedact(t *testing.T) {
	var raw []AuditEvent
	for i := 0; i < AuditMaxEvents+1; i++ {
		raw = append(raw, ev("M", i, "u"))
	}
	got, err := NormalizeAudit(AuditQuery{Marker: "M"}, raw, ident, false)
	if len(got) != AuditMaxEvents {
		t.Fatalf("cap: %d", len(got))
	}
	if !errors.Is(err, ErrAuditIncomplete) {
		t.Fatalf("cap hit must be incomplete, got %v", err)
	}
	long := AuditEvent{Time: time.Now(), Statement: "/* dbsim:M */ password=hunter2 " + strings.Repeat("x", 800), Principal: "u"}
	redact := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[redacted]") }
	got, err = NormalizeAudit(AuditQuery{Marker: "M"}, []AuditEvent{long}, redact, false)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", err, got)
	}
	if strings.Contains(got[0].Statement, "hunter2") || len(got[0].Statement) > AuditMaxStatementBytes {
		t.Fatalf("redact/truncate failed: %d", len(got[0].Statement))
	}
	// the source itself reporting truncation (fetched cap+1) is incomplete too
	_, err = NormalizeAudit(AuditQuery{Marker: "M"}, []AuditEvent{ev("M", 0, "u")}, redact, true)
	if !errors.Is(err, ErrAuditIncomplete) {
		t.Fatalf("source overflow must be incomplete: %v", err)
	}
}

func TestAuditStatusOf(t *testing.T) {
	one := []AuditEvent{ev("M", 0, "u")}
	cases := []struct {
		name string
		evs  []AuditEvent
		err  error
		want string
	}{
		{"found", one, nil, "found"},
		{"absent", nil, nil, "absent"},
		{"unsupported", nil, ErrAuditUnsupported, "unsupported"},
		{"incomplete with events", one, &AuditIncompleteError{Reason: "x"}, "incomplete"},
		{"incomplete without events", nil, ErrAuditIncomplete, "incomplete"},
		{"error is never absent", nil, errors.New("boom"), "error"},
		{"error with events", one, errors.New("boom"), "error"},
	}
	for _, c := range cases {
		if got := AuditStatusOf(c.evs, c.err); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestMarkerCommentIsTheSingleSourceOfTruth(t *testing.T) {
	if got := MarkerComment("a b/c"); got != "/* dbsim:a_b_c */" {
		t.Fatalf("got %q", got)
	}
	if MarkerComment("") != "/* dbsim:none */" {
		t.Fatal("empty marker comment")
	}
	if MetaStatementTag != MarkerComment(MetaMarker) {
		t.Fatalf("meta tag %q != MarkerComment(MetaMarker) %q", MetaStatementTag, MarkerComment(MetaMarker))
	}
}

// Positive identification: an event is the probe's own statement only if its
// text BEGINS with the probe's marker comment.
func TestNormalizeAuditPositiveIdentification(t *testing.T) {
	mk := func(s string) AuditEvent { return AuditEvent{Time: time.Now(), Principal: "u", Statement: s} }
	own := MarkerComment("RUN-1")
	cases := []struct {
		name string
		stmt string
		want bool
	}{
		{"probe statement comment-led", own + " SELECT 1", true},
		{"leading whitespace tolerated", "  \n" + own + " SELECT 1", true},
		{"collector lookup with comment stripped (marker substituted into LIKE)", "SELECT UNIX_TIMESTAMP(event_time), user_host, argument FROM mysql.general_log WHERE argument LIKE '%RUN-1%'", false},
		{"marker merely inside a WHERE clause", MarkerComment("OTHER") + " SELECT 1 WHERE x = '" + own + "'", false},
		{"another run's marker comment", MarkerComment("RUN-2") + " SELECT 1", false},
		{"prefix-sharing marker is another run", MarkerComment("RUN-10") + " SELECT 1", false},
		{"meta tagged lookup", MetaStatementTag + " SELECT 1 WHERE m LIKE '%RUN-1%'", false},
		{"probe-led but references general_log", own + " SELECT * FROM mysql.general_log", false},
		{"probe-led but references history_long", own + " SELECT * FROM performance_schema.events_statements_history_long", false},
		{"probe-led but references pg_log", own + " SELECT * FROM x.PG_LOG", false},
		{"probe-led but references dbsim_audit", own + " SELECT to_regclass('dbsim_audit.v')", false},
		{"unmarked", "select 1", false},
	}
	for _, c := range cases {
		got, err := NormalizeAudit(AuditQuery{Marker: "RUN-1"}, []AuditEvent{mk(c.stmt)}, ident, false)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (len(got) == 1) != c.want {
			t.Errorf("%s: counted=%v want %v", c.name, len(got) == 1, c.want)
		}
	}
}

// ---- sync sentinel ----

type syncRig struct {
	now        time.Time
	sleeps     []time.Duration
	fetches    []string
	visibleAt  int // sentinel visible from this sentinel-poll number (1-based); 0 = never
	polls      int
	lookup     []AuditEvent
	covered    bool
	sentinelOK error
	fetchErr   error
	cancel     func()
}

const sentinelMarker = "dbsim-sync:abc"

func (r *syncRig) sync() AuditSync {
	return AuditSync{
		Now: func() time.Time { return r.now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			r.sleeps = append(r.sleeps, d)
			r.now = r.now.Add(d)
			if r.cancel != nil {
				r.cancel()
			}
			return ctx.Err()
		},
	}
}

func (r *syncRig) sentinel(ctx context.Context) (string, error) { return sentinelMarker, r.sentinelOK }

func (r *syncRig) fetch(ctx context.Context, marker string, q AuditQuery) (AuditFetch, error) {
	r.fetches = append(r.fetches, marker)
	if r.fetchErr != nil {
		return AuditFetch{}, r.fetchErr
	}
	if marker == sentinelMarker {
		r.polls++
		if r.visibleAt > 0 && r.polls >= r.visibleAt {
			return AuditFetch{Raw: []AuditEvent{{Time: r.now, Principal: "u", Statement: MarkerComment(sentinelMarker) + " SELECT 1"}}, Covered: true}, nil
		}
		return AuditFetch{Covered: true}, nil
	}
	// the lookup: only sees events once the source caught up
	if r.visibleAt > 0 {
		return AuditFetch{Raw: r.lookup, Covered: r.covered}, nil
	}
	return AuditFetch{Covered: r.covered}, nil
}

func newRig(visibleAt int) *syncRig {
	return &syncRig{now: time.Unix(1700000000, 0), visibleAt: visibleAt, covered: true,
		lookup: []AuditEvent{{Time: time.Unix(1700000000, 0), Principal: "u", Statement: MarkerComment("RUN-1") + " SELECT 1"}}}
}

func TestSyncSentinelVisibleAtOnceNeverSleeps(t *testing.T) {
	r := newRig(1)
	ev, err := CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if err != nil || len(ev) != 1 {
		t.Fatalf("%v %+v", err, ev)
	}
	if len(r.sleeps) != 0 {
		t.Fatalf("a synchronous source must not sleep: %v", r.sleeps)
	}
	if len(r.fetches) != 2 || r.fetches[0] != sentinelMarker || r.fetches[1] != "RUN-1" {
		t.Fatalf("fetch order %v", r.fetches)
	}
}

func TestSyncLagThenCatchUpFindsAndAbsentIsOnlyAfterCatchUp(t *testing.T) {
	r := newRig(4) // visible on the 4th poll
	ev, err := CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if err != nil || len(ev) != 1 {
		t.Fatalf("found after lag: %v %+v", err, ev)
	}
	if len(r.sleeps) != 3 || r.sleeps[0] != 250*time.Millisecond || r.sleeps[1] != 500*time.Millisecond || r.sleeps[2] != time.Second {
		t.Fatalf("poll backoff %v", r.sleeps)
	}
	r2 := newRig(2)
	r2.lookup = nil
	ev, err = CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r2.sentinel, r2.fetch, ident, r2.sync())
	if AuditStatusOf(ev, err) != "absent" {
		t.Fatalf("caught-up empty lookup must be absent: %v %v", ev, err)
	}
}

func TestSyncNeverCatchesUpIsIncompleteNotAbsent(t *testing.T) {
	r := newRig(0)
	r.lookup = nil
	ev, err := CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if got := AuditStatusOf(ev, err); got != "incomplete" {
		t.Fatalf("got %s (%v)", got, err)
	}
	if !strings.Contains(err.Error(), "did not catch up") {
		t.Fatalf("reason: %v", err)
	}
	var total time.Duration
	for _, d := range r.sleeps {
		total += d
	}
	if total < 5*time.Second || total > 6*time.Second || r.polls > 10 {
		t.Fatalf("polling not bounded: total sleep %v polls %d", total, r.polls)
	}
}

func TestSyncFoundButNotCaughtUpIsIncompleteWithEvents(t *testing.T) {
	r := newRig(0)
	fetch := func(ctx context.Context, marker string, q AuditQuery) (AuditFetch, error) {
		if marker == sentinelMarker {
			return AuditFetch{Covered: true}, nil
		}
		return AuditFetch{Raw: r.lookup, Covered: true}, nil
	}
	ev, err := CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, fetch, ident, r.sync())
	if len(ev) != 1 || AuditStatusOf(ev, err) != "incomplete" {
		t.Fatalf("%v %v", ev, err)
	}
}

func TestSyncContextCancelStopsPolling(t *testing.T) {
	r := newRig(0)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	ev, err := CollectWithSync(ctx, AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if AuditStatusOf(ev, err) != "error" || !errors.Is(err, context.Canceled) {
		t.Fatalf("%v %v", ev, err)
	}
	if len(r.sleeps) != 1 || r.polls != 1 {
		t.Fatalf("polling must stop at cancel: sleeps %v polls %d", r.sleeps, r.polls)
	}
}

func TestSyncErrorsAreErrorsNeverAbsent(t *testing.T) {
	r := newRig(1)
	r.sentinelOK = errors.New("sentinel failed")
	ev, err := CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if AuditStatusOf(ev, err) != "error" {
		t.Fatalf("sentinel failure: %v", err)
	}
	r = newRig(1)
	r.fetchErr = errors.New("source unreadable")
	ev, err = CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if AuditStatusOf(ev, err) != "error" {
		t.Fatalf("poll failure: %v", err)
	}
}

func TestSyncUncoveredWindowIsIncompleteAfterCatchUp(t *testing.T) {
	r := newRig(1)
	r.covered = false
	r.lookup = nil
	ev, err := CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if AuditStatusOf(ev, err) != "incomplete" {
		t.Fatalf("%v %v", ev, err)
	}
}

func TestSyncSentinelStatementsAreNeverReturnedAsEvents(t *testing.T) {
	r := newRig(1)
	r.lookup = []AuditEvent{
		{Time: r.now, Principal: "u", Statement: MarkerComment(sentinelMarker) + " SELECT 1"},
		{Time: r.now, Principal: "u", Statement: MarkerComment("RUN-1") + " SELECT 1"},
	}
	ev, err := CollectWithSync(context.Background(), AuditQuery{Marker: "RUN-1"}, r.sentinel, r.fetch, ident, r.sync())
	if err != nil || len(ev) != 1 || strings.Contains(ev[0].Statement, "dbsim-sync") {
		t.Fatalf("%v %+v", err, ev)
	}
}

func TestNewSentinelMarkerIsRandomAndTagged(t *testing.T) {
	a, b := NewSentinelMarker(), NewSentinelMarker()
	if a == b || !strings.HasPrefix(a, SyncMarkerPrefix) || SanitizeMarker(a, 120) != a {
		t.Fatalf("%q %q", a, b)
	}
}

func TestReadAuditConfigInCatalog(t *testing.T) {
	d, ok := LookupProbe("read_audit_config")
	if !ok || d.Class != ClassReadOnly || len(d.ParamSchema) != 0 || len(d.Engines) != 2 {
		t.Fatalf("%+v %v", d, ok)
	}
}
