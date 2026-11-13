package scenario

import (
	"strings"
	"testing"
)

// A veto with no action key must not print an empty "action=" field. The class and source still say why it was
// refused, and the text still says the customer's controls were not tested.
func TestVetoDetail_OmitsEmptyAction(t *testing.T) {
	got := vetoDetail("", "destructive", "catalog")
	if strings.Contains(got, "action=") {
		t.Errorf("veto detail prints an empty action field: %q", got)
	}
	if !strings.Contains(got, "class=destructive") || !strings.Contains(got, "source=catalog") {
		t.Errorf("veto detail lost the class or source: %q", got)
	}
	if !strings.Contains(got, "Customer defensive controls were not tested") {
		t.Errorf("veto detail lost the statement that customer controls were not tested: %q", got)
	}
}

func TestVetoDetail_KeepsActionWhenPresent(t *testing.T) {
	got := vetoDetail("wipe-tmp", "destructive", "catalog")
	if !strings.Contains(got, "action=wipe-tmp") {
		t.Errorf("veto detail dropped a real action: %q", got)
	}
}
