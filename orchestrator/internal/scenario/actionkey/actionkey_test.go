package actionkey

import "testing"

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Delete Volume Shadow Copies":       "delete_volume_shadow_copies",
		"  Stop & Disable Windows Defender": "stop_disable_windows_defender",
		"T1003.001---LSASS Dump (OS X)":     "t1003_001_lsass_dump_os_x",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeriveActionKeys_NoCollision(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "art", TechniqueID: "T1490", Name: "Delete Shadow Copies", Executor: "psh", Command: "vssadmin delete shadows /all"},
		{Source: "art", TechniqueID: "T1490", Name: "List Shadow Copies", Executor: "psh", Command: "vssadmin list shadows"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 0 {
		t.Fatalf("expected no collisions, got %v", collisions)
	}
	if len(keyed) != 2 {
		t.Fatalf("expected 2 keyed items, got %d", len(keyed))
	}
	if keyed[0].ActionKey == keyed[1].ActionKey {
		t.Errorf("expected distinct action_keys, both got %q", keyed[0].ActionKey)
	}
}

func TestDeriveActionKeys_SameNameDifferentExecutor_Disambiguated(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "caldera", TechniqueID: "T1070", Name: "Clear Logs", Executor: "psh", Command: "wevtutil cl System"},
		{Source: "caldera", TechniqueID: "T1070", Name: "Clear Logs", Executor: "sh", Command: "rm -f /var/log/syslog"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 0 {
		t.Fatalf("expected no collisions, got %v", collisions)
	}
	seen := map[string]bool{}
	for _, k := range keyed {
		if seen[k.ActionKey] {
			t.Fatalf("expected disambiguated keys, got duplicate %q", k.ActionKey)
		}
		seen[k.ActionKey] = true
	}
}

func TestDeriveActionKeys_SameNameSameExecutor_SameCommand_Deduped(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "art", TechniqueID: "T1082", Name: "System Info", Executor: "psh", Command: "systeminfo"},
		{Source: "art", TechniqueID: "T1082", Name: "System Info", Executor: "psh", Command: "systeminfo"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 0 {
		t.Fatalf("expected no collisions for identical real duplicates, got %v", collisions)
	}
	if len(keyed) != 2 {
		t.Fatalf("expected both items kept (same key), got %d", len(keyed))
	}
	if keyed[0].ActionKey != keyed[1].ActionKey {
		t.Errorf("expected identical commands to share one action_key, got %q and %q", keyed[0].ActionKey, keyed[1].ActionKey)
	}
}

func TestDeriveActionKeys_SameNameSameExecutor_DifferentCommand_Unresolved(t *testing.T) {
	items := []DiscoveredItem{
		{Source: "caldera", TechniqueID: "T1490", Name: "Disable Recovery", Executor: "psh", Command: "bcdedit /set recoveryenabled no"},
		{Source: "caldera", TechniqueID: "T1490", Name: "Disable Recovery", Executor: "psh", Command: "wbadmin delete catalog -quiet"},
	}
	keyed, collisions := DeriveActionKeys(items)
	if len(collisions) != 1 {
		t.Fatalf("expected exactly 1 unresolvable collision, got %d: %v", len(collisions), collisions)
	}
	for _, k := range keyed {
		if k.TechniqueID == "T1490" {
			t.Errorf("colliding items must not appear in the keyed output, found %+v", k)
		}
	}
}
