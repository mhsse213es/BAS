package segprobe

import (
	"context"
	"errors"
	"testing"
)

func TestLookupPack_UnknownIDRejected(t *testing.T) {
	for _, id := range []string{"", "../../etc/passwd", "swift-isolation.yaml", "SWIFT-ISOLATION"} {
		if _, err := LookupPack(id); !errors.Is(err, ErrUnknownPack) {
			t.Errorf("LookupPack(%q): got %v, want ErrUnknownPack", id, err)
		}
	}
}

func TestLookupPack_RegisteredPacksResolve(t *testing.T) {
	for _, p := range Packs() {
		got, err := LookupPack(p.ID)
		if err != nil || got.ScenarioFile == "" || got.RulesFile == "" {
			t.Fatalf("LookupPack(%q) = %+v, %v", p.ID, got, err)
		}
	}
	if len(Packs()) != 3 {
		t.Fatalf("got %d packs, want 3", len(Packs()))
	}
}

func TestApplyRules_RejectsUnregisteredFileWithoutExecuting(t *testing.T) {
	called := false
	p := &DockerProvider{composeFile: "c.yml", run: func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}}
	for _, name := range []string{"../evil.sh", "default.sh", "test-open-corp-db.sh", "", "swift.sh; rm -rf /"} {
		if err := p.ApplyRules(context.Background(), name); err == nil {
			t.Errorf("ApplyRules(%q): want error", name)
		}
	}
	if called {
		t.Fatal("an unregistered rules file reached the container exec")
	}
}

func TestApplyRules_RunsRegisteredFileInFirewallContainer(t *testing.T) {
	var got []string
	p := &DockerProvider{composeFile: "c.yml", run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		got = args
		return nil, nil
	}}
	if err := p.ApplyRules(context.Background(), "swift.sh"); err != nil {
		t.Fatalf("ApplyRules: %v", err)
	}
	want := []string{"compose", "-f", "c.yml", "exec", "-T", "seg-fw", "/rules/apply.sh", "/rules/swift.sh"}
	if len(got) != len(want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args = %v, want %v", got, want)
		}
	}
}
