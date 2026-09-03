package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/exercise"
)

// The product name must appear on the cover of every report, whether or not a
// logo image is configured.
//
// Regression, 2026-09-03: the cover lockup was written as
// {{if .logoDarkUri}}<img ...>{{else}}<wordmark>{{end}}, so the image replaced
// the WHOLE lockup rather than just the "A" mark tile. Since the logo PNG is
// embedded at build time, .logoDarkUri is set on every normal deployment --
// meaning the branch that renders the name was effectively dead, and the name
// was missing from the cover of every report in both HTML and PDF. An <img>
// carries no extractable text, so the name was absent from the document
// outright, not merely styled away: a text search of a real 45-page PDF found
// no wordmark on the cover.
//
// Asserted in both states, because a test run only in the no-logo state would
// have passed against the broken template.
func TestGenerateHTML_CoverAlwaysShowsProductName(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	prevDark, prevLight := _logoDark, _logoLight
	t.Cleanup(func() { _logoDark, _logoLight = prevDark, prevLight })

	cases := []struct {
		name string
		logo string
	}{
		{"logo image configured (the normal deployment)", "data:image/png;base64,iVBORw0KGgo="},
		{"no logo image configured", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_logoDark = c.logo
			var buf bytes.Buffer
			if err := GenerateHTML(&buf, robustnessReport(now), nil); err != nil {
				t.Fatalf("GenerateHTML: %v", err)
			}
			out := buf.String()

			if !strings.Contains(out, `class="clogo-name"`) {
				t.Error("cover is missing the clogo-name wordmark element")
			}
			// The name is split by a <span> for the two-tone treatment, so assert
			// on the rendered fragments rather than the flat string.
			for _, frag := range []string{"Aud", "spect", "BAS"} {
				if !strings.Contains(out, frag) {
					t.Errorf("cover wordmark missing %q", frag)
				}
			}
			if !strings.Contains(out, "Breach &amp; Attack Simulation Platform") {
				t.Error("cover is missing the product sub-title")
			}
		})
	}
}

// The exercise report is a separate template with its own cover; the name must
// be there too. It already renders unconditionally — this pins that so the two
// templates cannot drift apart.
func TestExerciseReportHTML_CoverShowsProductName(t *testing.T) {
	var buf bytes.Buffer
	// Minimal report: the template dereferences Execution, but the cover
	// branding must not depend on any exercise CONTENT being present.
	rep := &ExerciseReport{
		Execution: &exercise.Execution{ID: "ex-1", Name: "Cyber Crisis Exercise", Status: exercise.ExecStatus("completed")},
		Plan:      &exercise.Plan{ID: "plan-1", Name: "Ransomware Tabletop"},
	}
	if err := ExerciseReportHTML(&buf, rep); err != nil {
		t.Fatalf("ExerciseReportHTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `class="clogo-name"`) {
		t.Error("exercise cover is missing the clogo-name wordmark element")
	}
	if !strings.Contains(out, "Breach &amp; Attack Simulation Platform") {
		t.Error("exercise cover is missing the product sub-title")
	}
}

// The exercise report must render to COMPLETION, not stop partway.
//
// Separate from the branding assertion above because it guards a different
// failure: `lower` was registered as strings.ToLower (a func(string) string),
// but the template calls it on .Execution.Status of type exercise.ExecStatus
// -- a defined string type, which Go does not treat as assignable to a string
// parameter. Execute aborted at that field, so every exercise report was
// truncated there.
//
// It stayed hidden because ExerciseReportHTML streams into the
// http.ResponseWriter: the 200 and the opening markup were already sent before
// the error, so the handler's jsonError could only append JSON to a half-written
// page, and a test asserting "status 200 and contains <html>" still passed.
// Asserting the document is CLOSED is what makes truncation visible.
func TestExerciseReportHTML_RendersToCompletion(t *testing.T) {
	var buf bytes.Buffer
	rep := &ExerciseReport{
		Execution: &exercise.Execution{ID: "ex-1", Name: "Cyber Crisis Exercise", Status: exercise.ExecStatus("completed")},
		Plan:      &exercise.Plan{ID: "plan-1", Name: "Ransomware Tabletop"},
	}
	if err := ExerciseReportHTML(&buf, rep); err != nil {
		t.Fatalf("ExerciseReportHTML: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if !strings.HasSuffix(out, "</html>") {
		tail := out
		if len(tail) > 200 {
			tail = tail[len(tail)-200:]
		}
		t.Errorf("exercise report is truncated — document does not end with </html>.\nlast 200 bytes:\n%s", tail)
	}
}
