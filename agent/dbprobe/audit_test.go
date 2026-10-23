package dbprobe

import (
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

func TestReadAuditConfigInCatalog(t *testing.T) {
	d, ok := LookupProbe("read_audit_config")
	if !ok || d.Class != ClassReadOnly || len(d.ParamSchema) != 0 || len(d.Engines) != 2 {
		t.Fatalf("%+v %v", d, ok)
	}
}
