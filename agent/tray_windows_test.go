//go:build windows

package main

import "testing"

func TestTrayShowMenu_ItemOrder(t *testing.T) {
	items := buildTrayMenuItems()
	wantLabels := []string{"Open Status Console", "Settings...", "Troubleshoot...", "", "Export Diagnostic Bundle", "Open Logs Folder"}
	if len(items) != len(wantLabels) {
		t.Fatalf("got %d items, want %d", len(items), len(wantLabels))
	}
	for i, want := range wantLabels {
		if items[i].Label != want {
			t.Errorf("item %d label = %q, want %q", i, items[i].Label, want)
		}
	}
	for _, it := range items {
		if it.ID == tIDM_EXIT {
			t.Fatal("Exit must not appear in the user-facing menu")
		}
	}
}
