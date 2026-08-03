package remediation

import "testing"

func TestNewCatalog_LoadsEmbeddedFile(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.Lookup("windows-firewall-enabled")
	if !ok {
		t.Fatal("expected windows-firewall-enabled to be mapped")
	}
	if entry.ID != "enable_windows_firewall" || entry.Tier != TierSafeAutomatic {
		t.Errorf("entry = %+v, want id=enable_windows_firewall tier=1", entry)
	}
}

func TestCatalogByID_FindsEntry(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.ByID("enable_bitlocker")
	if !ok || entry.Tier != TierManualGuidance {
		t.Errorf("entry = %+v ok=%v, want enable_bitlocker/TierManualGuidance", entry, ok)
	}
	if entry.Command != "" {
		t.Error("expected a Tier 4 entry to have no command")
	}
	if len(entry.ManualSteps) == 0 {
		t.Error("expected a Tier 4 entry to have manual_steps")
	}
}

func TestCatalogLookup_UnknownCheckID_NotOK(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	_, ok := c.Lookup("no-such-check")
	if ok {
		t.Error("expected ok=false for an unmapped check_id")
	}
}

func TestCatalogTier2Entry_HasCommandAndRollback(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.ByID("disable_windows_smbv1")
	if !ok || entry.Tier != TierConfirmRequired {
		t.Fatalf("entry = %+v ok=%v, want disable_windows_smbv1/TierConfirmRequired", entry, ok)
	}
	if entry.Command == "" || !entry.SupportsRollback || entry.RollbackCommand == "" {
		t.Errorf("entry = %+v, want a command and rollback support", entry)
	}
	if !entry.RequiresReboot {
		t.Error("expected disable_windows_smbv1 to declare requires_reboot=true")
	}
}
