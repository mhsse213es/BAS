package mysqlaudit

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// fakeQ records every query the harness issues. Any query other than SHOW PLUGINS
// fails the test: the harness never reads general_log or any agent-supplied SQL.
type fakeQ struct {
	rows    [][]string
	err     error
	queries []string
}

func (f *fakeQ) Query(_ context.Context, q string) ([][]string, error) {
	f.queries = append(f.queries, q)
	return f.rows, f.err
}

func openFile(content string, err error) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		if err != nil {
			return nil, err
		}
		return io.NopCloser(strings.NewReader(content)), nil
	}
}

func activePlugins() [][]string { return [][]string{{"audit_log", "ACTIVE"}} }
func noPlugin() [][]string      { return [][]string{{"validate_password", "ACTIVE"}} }

const oneQuery = `{"audit_record":{"name":"Query","timestamp":"2026-11-20T11:00:00Z","sqltext":"SELECT /* dbsim:m1 */ 1","user":"root[root] @ [127.0.0.1]"}}` + "\n"

func TestPluginActiveOnlyForAuditLogACTIVE(t *testing.T) {
	cases := []struct {
		name string
		rows [][]string
		want bool
	}{
		{"audit_log ACTIVE", [][]string{{"audit_log", "ACTIVE"}}, true},
		{"audit_log DISABLED", [][]string{{"audit_log", "DISABLED"}}, false},
		{"no audit_log row", noPlugin(), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PluginActive(c.rows); got != c.want {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestCollectPluginActiveReadableIsCovered(t *testing.T) {
	q := &fakeQ{rows: activePlugins()}
	ev, err := Collect(context.Background(), q, openFile(oneQuery, nil))
	if err != nil || ev.AuditCoverage != "covered" {
		t.Fatalf("ev=%+v err=%v", ev, err)
	}
}

func TestCollectPluginActiveUnreadableIsPartial(t *testing.T) {
	q := &fakeQ{rows: activePlugins()}
	ev, err := Collect(context.Background(), q, openFile("", errors.New("permission denied")))
	if err != nil || ev.AuditCoverage != "partial" {
		t.Fatalf("ev=%+v err=%v", ev, err)
	}
}

func TestCollectNoPluginIsNoneEvenWithAFile(t *testing.T) {
	q := &fakeQ{rows: noPlugin()}
	ev, err := Collect(context.Background(), q, openFile(oneQuery, nil))
	if err != nil || ev.AuditCoverage != "none" {
		t.Fatalf("ev=%+v err=%v", ev, err)
	}
}

func TestCollectQueriesOnlyShowPlugins(t *testing.T) {
	q := &fakeQ{rows: activePlugins()}
	if _, err := Collect(context.Background(), q, openFile(oneQuery, nil)); err != nil {
		t.Fatal(err)
	}
	if len(q.queries) != 1 || q.queries[0] != "SHOW PLUGINS" {
		t.Fatalf("harness must issue exactly SHOW PLUGINS, issued %q", q.queries)
	}
}

func TestCollectFailsClosedOnQueryError(t *testing.T) {
	q := &fakeQ{err: errors.New("access denied")}
	ev, err := Collect(context.Background(), q, openFile(oneQuery, nil))
	if err == nil {
		t.Fatal("a failed SHOW PLUGINS must be an error, not a coverage value")
	}
	if ev.AuditCoverage != "" {
		t.Fatalf("no verdict may be reported when the plugin state is unknown: %q", ev.AuditCoverage)
	}
}
