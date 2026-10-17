package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPromptSecret_ReadsLineWithTrailingNewline(t *testing.T) {
	var out bytes.Buffer
	got, err := promptSecret(strings.NewReader("my-secret\n"), &out)
	if err != nil {
		t.Fatalf("promptSecret: %v", err)
	}
	if got != "my-secret" {
		t.Fatalf("got %q, want %q", got, "my-secret")
	}
	if !strings.Contains(out.String(), "Agent Secret") {
		t.Fatalf("expected a prompt to be written, got %q", out.String())
	}
}

func TestPromptSecret_ReadsLineWithoutTrailingNewline_EOF(t *testing.T) {
	// A piped value with no trailing newline (e.g. printf, not echo) hits
	// EOF instead of a newline -- that must still count as a real read, not
	// an error, since the content itself is valid.
	var out bytes.Buffer
	got, err := promptSecret(strings.NewReader("my-secret"), &out)
	if err != nil {
		t.Fatalf("promptSecret: %v", err)
	}
	if got != "my-secret" {
		t.Fatalf("got %q, want %q", got, "my-secret")
	}
}

func TestPromptSecret_TrimsWhitespace(t *testing.T) {
	var out bytes.Buffer
	got, err := promptSecret(strings.NewReader("  my-secret  \n"), &out)
	if err != nil {
		t.Fatalf("promptSecret: %v", err)
	}
	if got != "my-secret" {
		t.Fatalf("got %q, want %q", got, "my-secret")
	}
}

func TestPromptSecret_EmptyInput_ReturnsError(t *testing.T) {
	var out bytes.Buffer
	if _, err := promptSecret(strings.NewReader("\n"), &out); err == nil {
		t.Fatal("expected an error for an empty secret, got nil")
	}
}

func TestPromptSecret_ImmediateEOF_ReturnsError(t *testing.T) {
	var out bytes.Buffer
	if _, err := promptSecret(strings.NewReader(""), &out); err == nil {
		t.Fatal("expected an error for no input at all, got nil")
	}
}
