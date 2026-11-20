package mysqlauditfile

import (
	"errors"
	"testing"
)

func TestCoverageVerdict(t *testing.T) {
	cases := []struct {
		name         string
		pluginActive bool
		readErr      error
		want         string
	}{
		{"plugin active and file readable is covered", true, nil, "covered"},
		{"plugin active but file unreadable is partial", true, errors.New("permission denied"), "partial"},
		{"plugin inactive is none even if a file exists", false, nil, "none"},
		{"plugin inactive and unreadable is none", false, errors.New("no such file"), "none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CoverageVerdict(c.pluginActive, c.readErr); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}
