package scenario

import (
	"fmt"
	"time"

	"github.com/audspect/bas/internal/models"
)

// terminationEvidence renders a StepTermination as a sentence appended to a
// terminated step's detail line. Returns "" when the agent reported nothing,
// which is the case for every agent predating the field and for pooled steps —
// silence from the agent must read as "not measured", never as "wrote nothing".
//
// The sentence states two measurements and stops there. Output is evidence of
// activity, not proof of progress: a process can print the same line forever,
// and a legitimate silent scan can produce nothing until its final second. So
// the reader is given the numbers and draws the conclusion; the platform draws
// none, and the verdict stays ERROR either way.
//
// The leading space is deliberate — callers concatenate this straight onto a
// sentence that already ends in a period.
func terminationEvidence(t *models.StepTermination) string {
	if t == nil {
		return ""
	}
	if t.OutputBytes == 0 {
		return " It produced no output at any point before it was terminated."
	}
	return fmt.Sprintf(" It produced %s of output, most recently %s before it was terminated.",
		humanBytes(t.OutputBytes),
		(time.Duration(t.SilenceMs) * time.Millisecond).Round(100*time.Millisecond))
}

// humanBytes formats a byte count for a report reader. The exact figure stays
// available in StepTermination.OutputBytes for analysis.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d bytes", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
