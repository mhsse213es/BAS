package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"audspect/agent/dbprobe"
)

// connFake answers the connection collector's queries: the sentinel poll and
// the final connection read. rows are returned for the connection pattern;
// sentinelSeen controls whether the sentinel is visible to the poll.
func connFake(rows [][]any, sentinelSeen bool, covered bool) *fakeSession {
	return &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, "clock_timestamp"):
			return [][]any{{time.Unix(1700000000, 0).UTC()}}, nil
		case strings.Contains(sql, sqlAuditCovered):
			return [][]any{{covered}}, nil
		case strings.Contains(sql, sqlAuditEvents):
			pattern, _ := args[2].(string)
			if strings.Contains(pattern, "connection authorized") {
				return rows, nil
			}
			if sentinelSeen {
				return [][]any{{time.Unix(1700000001, 0).UTC(), "bas_probe", "marker"}}, nil
			}
			return nil, nil
		}
		return nil, nil
	}}
}

func TestCollectConnectionsReturnsRoleWindowMatch(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	rows := [][]any{{ts, "bas_probe", "connection authorized: user=bas_probe database=dbsim"}}
	a := &Adapter{s: connFake(rows, true, true), mode: dbprobe.ModeClient, auditSources: []string{"x"}}
	ev, err := a.CollectConnections(context.Background(), dbprobe.AuditQuery{
		Principal: "bas_probe", Since: ts.Add(-time.Second), Until: ts.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("CollectConnections: %v", err)
	}
	if len(ev) != 1 || ev[0].Principal != "bas_probe" || !strings.HasPrefix(ev[0].Statement, "connection authorized") {
		t.Fatalf("events = %+v", ev)
	}
}

func TestCollectConnectionsRefusesWithoutPrincipal(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	a := &Adapter{s: connFake(nil, true, true), mode: dbprobe.ModeClient, auditSources: []string{"x"}}
	if _, err := a.CollectConnections(context.Background(), dbprobe.AuditQuery{Since: ts, Until: ts}); err == nil {
		t.Fatal("a connection query with no role must be refused, not matched on every login")
	}
}

func TestCollectConnectionsIncompleteWhenWindowNotCovered(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	a := &Adapter{s: connFake(nil, true, false), mode: dbprobe.ModeClient, auditSources: []string{"x"}}
	_, err := a.CollectConnections(context.Background(), dbprobe.AuditQuery{
		Principal: "bas_probe", Since: ts, Until: ts.Add(time.Second),
	})
	var inc *dbprobe.AuditIncompleteError
	if err == nil || !errors.As(err, &inc) {
		t.Fatalf("uncovered window must be AuditIncompleteError, got %v", err)
	}
}

// DB-04-04: a refused password is matched by its own log line, under the
// throwaway account's name, never as a successful connection.
func TestCollectConnectionsFailedLoginUsesRefusalPattern(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	var pattern string
	f := &fakeSession{queryFn: func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, "clock_timestamp"):
			return [][]any{{ts}}, nil
		case strings.Contains(sql, sqlAuditCovered):
			return [][]any{{true}}, nil
		case strings.Contains(sql, sqlAuditEvents):
			p, _ := args[2].(string)
			if strings.Contains(p, "password authentication failed") {
				pattern = p
				return [][]any{{ts, "dbsim_abc_acct", `password authentication failed for user "dbsim_abc_acct"`}}, nil
			}
			return [][]any{{ts, "dbsim", "sentinel"}}, nil
		}
		return nil, nil
	}}
	a := &Adapter{s: f, mode: dbprobe.ModeLab, auditSources: []string{"x"}}
	ev, err := a.CollectConnections(context.Background(), dbprobe.AuditQuery{
		Principal: "dbsim_abc_acct", Event: dbprobe.EventFailedLogin, Since: ts.Add(-time.Second), Until: ts.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("CollectConnections: %v", err)
	}
	// LIKE wildcards in the name are escaped, so "_" matches only itself.
	if !strings.Contains(pattern, `password authentication failed for user "dbsim\_abc\_acct"`) {
		t.Fatalf("refusal pattern not used: %q", pattern)
	}
	if len(ev) != 1 || ev[0].Principal != "dbsim_abc_acct" {
		t.Fatalf("events = %+v", ev)
	}
}

