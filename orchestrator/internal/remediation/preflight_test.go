package remediation

import "testing"

func TestOSSupported_ExactMatch(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"windows"}}
	if !OSSupported("windows", entry) {
		t.Error("expected windows to match")
	}
}

func TestOSSupported_CaseInsensitive(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"Windows"}}
	if !OSSupported("WINDOWS", entry) {
		t.Error("expected case-insensitive match")
	}
}

func TestOSSupported_Mismatch(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"windows"}}
	if OSSupported("linux", entry) {
		t.Error("expected linux not to match a windows-only entry")
	}
}

func TestOSSupported_EmptyAgentOS(t *testing.T) {
	entry := CatalogEntry{SupportedOS: []string{"windows"}}
	if OSSupported("", entry) {
		t.Error("expected an unknown/empty agent OS not to match")
	}
}
