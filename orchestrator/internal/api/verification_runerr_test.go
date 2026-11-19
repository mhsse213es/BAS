package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/contentregistry"
)

func TestRunVerificationError(t *testing.T) {
	cases := []struct {
		name   string
		rc     contentregistry.RunContent
		status int
		sub    string
	}{
		{"factory validation run", contentregistry.RunContent{Status: contentregistry.RunSynthetic}, http.StatusConflict, "factory validation"},
		{"unknown run", contentregistry.RunContent{Status: contentregistry.RunUnreadable, NotFound: true}, http.StatusNotFound, "run or scenario not found"},
		{"unreadable content", contentregistry.RunContent{Status: contentregistry.RunUnreadable}, http.StatusNotFound, "run or scenario not found"},
	}
	for _, c := range cases {
		status, msg := runVerificationError(c.rc)
		if status != c.status || !strings.Contains(msg, c.sub) {
			t.Errorf("%s: got %d %q, want %d containing %q", c.name, status, msg, c.status, c.sub)
		}
	}
}
