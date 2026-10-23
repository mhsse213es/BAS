package dbsim

import (
	"strings"
	"testing"
)

func TestParseNotesReadsKeyValueAndAuditConfig(t *testing.T) {
	n := ParseNotes([]string{
		"shape=wide_select", "rows_read=25", "bytes_read=1048576", "truncated=true",
		"row_cap_applied=25", "duration_ms=12", "audit_config: covered",
		"free text sentence with = sign inside", "Bad Key=1",
	})
	if v, ok := n.Int("rows_read"); !ok || v != 25 {
		t.Fatalf("rows_read %v %v", v, ok)
	}
	if v, ok := n.Int("bytes_read"); !ok || v != 1048576 {
		t.Fatalf("bytes_read %v %v", v, ok)
	}
	if v, ok := n.Bool("truncated"); !ok || !v {
		t.Fatalf("truncated %v %v", v, ok)
	}
	if v, ok := n.Get("shape"); !ok || v != "wide_select" {
		t.Fatalf("shape %q %v", v, ok)
	}
	if c, ok := n.AuditConfig(); !ok || c != "covered" {
		t.Fatalf("audit_config %q %v", c, ok)
	}
	if _, ok := n.Get("free text sentence with "); ok {
		t.Fatal("free text must not parse as a key")
	}
	if _, ok := n.Get("Bad Key"); ok {
		t.Fatal("invalid key accepted")
	}
}

func TestParseNotesIsBoundedAndTolerant(t *testing.T) {
	if _, ok := ParseNotes(nil).Int("rows_read"); ok {
		t.Fatal("absent key reported present")
	}
	n := ParseNotes([]string{"rows_read=abc", "bytes_read=-5", "truncated=maybe", "audit_config: banana", "rows_read=7"})
	if _, ok := n.Int("rows_read"); ok {
		t.Fatal("first occurrence (non-numeric) must win and be rejected, not fall through to the later value")
	}
	if _, ok := n.Int("bytes_read"); ok {
		t.Fatal("negative count accepted")
	}
	if _, ok := n.Bool("truncated"); ok {
		t.Fatal("non-boolean accepted")
	}
	if _, ok := n.AuditConfig(); ok {
		t.Fatal("unknown audit coverage accepted")
	}
	var many []string
	for i := 0; i < 500; i++ {
		many = append(many, "k"+strings.Repeat("x", 3)+"=1")
	}
	many = append(many, "late_key=1")
	if _, ok := ParseNotes(many).Get("late_key"); ok {
		t.Fatal("notes beyond the cap must be ignored")
	}
	long := "shape=" + strings.Repeat("a", 5000)
	if v, _ := ParseNotes([]string{long}).Get("shape"); len(v) > 256 {
		t.Fatalf("value not bounded: %d", len(v))
	}
}
