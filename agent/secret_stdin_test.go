package main

import (
	"strings"
	"testing"
)

func TestReadSecretFromStdin(t *testing.T) {
	long := strings.Repeat("a", maxSecretBytes)
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr string // substring; empty means success
	}{
		{"plain with LF", "abc123\n", "abc123", ""},
		{"plain with CRLF", "abc123\r\n", "abc123", ""},
		{"no trailing newline", "abc123", "abc123", ""},
		{"spaces inside are kept", "ab c d\n", "ab c d", ""},
		{"trailing blank lines are fine", "abc123\n\n\r\n", "abc123", ""},
		{"max length", long + "\n", long, ""},
		{"empty input", "", "", "no secret"},
		{"only newline", "\n", "", "no secret"},
		{"only CRLF", "\r\n", "", "no secret"},
		{"second line is rejected, not silently dropped", "abc\nsecond\n", "", "more than one line"},
		{"second line after CRLF is rejected", "abc\r\nsecond", "", "more than one line"},
		{"NUL is rejected", "ab\x00cd\n", "", "control character"},
		{"tab is rejected", "ab\tcd\n", "", "control character"},
		{"escape is rejected", "ab\x1bcd\n", "", "control character"},
		{"invalid utf-8 is rejected", "ab\xffcd\n", "", "not valid text"},
		{"over max length", long + "x\n", "", "too long"},
		{"huge input is bounded", strings.Repeat("a", 1<<20), "", "too long"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readSecretFromStdin(strings.NewReader(c.in))
			if c.wantErr == "" {
				if err != nil || got != c.want {
					t.Fatalf("got %q, %v; want %q", got, err, c.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("got %q, %v; want an error containing %q", got, err, c.wantErr)
			}
			if got != "" {
				t.Fatalf("a rejected secret must not be returned, got %q", got)
			}
			// Errors must never echo the input back.
			if in := strings.TrimSpace(c.in); len(in) > 3 && strings.Contains(err.Error(), in) {
				t.Fatalf("error leaks the input: %v", err)
			}
		})
	}
}

func TestSecretFromFlags(t *testing.T) {
	t.Run("neither: caller keeps its existing fallbacks", func(t *testing.T) {
		s, used, err := secretFromFlags("", false, strings.NewReader("ignored\n"))
		if err != nil || used || s != "" {
			t.Fatalf("got %q, %v, %v", s, used, err)
		}
	})
	t.Run("command-line secret is returned unchanged and stdin untouched", func(t *testing.T) {
		r := strings.NewReader("ignored\n")
		s, used, err := secretFromFlags("from-flag", false, r)
		if err != nil || used || s != "from-flag" {
			t.Fatalf("got %q, %v, %v", s, used, err)
		}
		if r.Len() != len("ignored\n") {
			t.Fatal("stdin was consumed when --secret-stdin was not requested")
		}
	})
	t.Run("stdin secret", func(t *testing.T) {
		s, used, err := secretFromFlags("", true, strings.NewReader("from-stdin\r\n"))
		if err != nil || !used || s != "from-stdin" {
			t.Fatalf("got %q, %v, %v", s, used, err)
		}
	})
	t.Run("both is an error and does not read stdin", func(t *testing.T) {
		r := strings.NewReader("x\n")
		_, _, err := secretFromFlags("from-flag", true, r)
		if err == nil || !strings.Contains(err.Error(), "not both") {
			t.Fatalf("got %v, want a not-both error", err)
		}
		if r.Len() != 2 {
			t.Fatal("stdin was consumed despite the conflicting flags")
		}
	})
	t.Run("stdin requested but malformed", func(t *testing.T) {
		if _, _, err := secretFromFlags("", true, strings.NewReader("")); err == nil {
			t.Fatal("empty stdin must be an error")
		}
	})
}
