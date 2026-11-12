package api

import (
	"testing"

	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/phishval"
)

// A dispatched run whose observation window is still open must not read as completed: its result is provisional
// and the run stays running, so a later read settles it once the window has closed.
func TestDispatchStatusFor_OpenWindowStaysRunning(t *testing.T) {
	got := dispatchStatusFor(phishval.Outcome{Provisional: true})
	if got != phishingrun.StatusRunning {
		t.Errorf("status with the window still open = %q, want %q", got, phishingrun.StatusRunning)
	}
}

func TestDispatchStatusFor_ClosedWindowCompletes(t *testing.T) {
	got := dispatchStatusFor(phishval.Outcome{})
	if got != phishingrun.StatusCompleted {
		t.Errorf("status after the window closed = %q, want %q", got, phishingrun.StatusCompleted)
	}
}
