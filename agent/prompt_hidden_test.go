package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Without a terminal (a pipe) there is nothing to switch off, but the line is still read, the label is
// shown, and what was read is never written back to the output.
func TestPromptHidden_ReadsALineAndNeverEchoesIt(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w.WriteString("bas_enr_TYPED\r\n")
	w.Close()
	var out bytes.Buffer
	got, err := promptHidden("Enrollment token: ", r, &out)
	if err != nil || got != "bas_enr_TYPED" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if !strings.Contains(out.String(), "Enrollment token: ") {
		t.Error("the prompt label should be shown")
	}
	if strings.Contains(out.String(), "TYPED") {
		t.Error("the typed value must never be written to the output")
	}
}

func TestPromptHidden_EmptyInputIsAllowedForOptionalPrompts(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	w.WriteString("\n")
	w.Close()
	got, err := promptHidden("x: ", r, &bytes.Buffer{})
	if err != nil || got != "" {
		t.Errorf("got=%q err=%v, want an empty line to be returned as empty", got, err)
	}
}
