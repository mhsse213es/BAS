package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/pki"
)

func rotationDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := pki.LoadOrGenerateCA(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A rotation step changes how the whole fleet is trusted, so it needs an explicit --yes (audit F-09).
func TestCARotationCommand_MutatingStepsNeedExplicitConfirmation(t *testing.T) {
	dir := rotationDir(t)
	var out bytes.Buffer
	if code := runCARotation([]string{"start"}, dir, &out); code == 0 {
		t.Errorf("start without --yes must fail, output: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "next-ca-key.pem")); err == nil {
		t.Error("nothing may be created without confirmation")
	}
	out.Reset()
	if code := runCARotation([]string{"start", "--yes"}, dir, &out); code != 0 {
		t.Fatalf("start --yes = %d: %s", code, out.String())
	}
	out.Reset()
	if code := runCARotation([]string{"status"}, dir, &out); code != 0 || !strings.Contains(out.String(), "prepared") {
		t.Errorf("status = %d, output %q, want prepared", code, out.String())
	}
}

func TestCARotationCommand_UnknownStepAndMissingCAFail(t *testing.T) {
	var out bytes.Buffer
	if code := runCARotation([]string{"explode", "--yes"}, rotationDir(t), &out); code == 0 {
		t.Error("an unknown step must fail")
	}
	if code := runCARotation([]string{"start", "--yes"}, t.TempDir(), &out); code == 0 {
		t.Error("a missing CA must never start a rotation")
	}
}
