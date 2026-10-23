//go:build dbsim_e2e

package dbrun

import "testing"

func TestE2EDecision(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	all := map[string]string{}
	for _, v := range commonVars {
		all[v] = "x"
	}
	for _, v := range engineVars {
		all["DBSIM_E2E_PG_"+v] = "x"
	}
	cases := []struct {
		name string
		kv   map[string]string
		want string
	}{
		{"nothing set", map[string]string{}, "skip"},
		{"only a common var (typo guard)", map[string]string{"DBSIM_E2E_AGENT_BIN": "x"}, "fail"},
		{"common var + mistyped engine prefix", map[string]string{"DBSIM_E2E_AGENT_IP": "x", "DBSIM_E2E_PGG_HOST": "x"}, "fail"},
		{"fully configured pg", all, "run"},
		{"pg partial", map[string]string{"DBSIM_E2E_PG_HOST": "x"}, "fail"},
	}
	for _, c := range cases {
		if got, msg := e2eDecision(env(c.kv), "DBSIM_E2E_PG", "DBSIM_E2E_MYSQL"); got != c.want {
			t.Errorf("%s: got %s want %s (%s)", c.name, got, c.want, msg)
		}
	}
	// the other engine configured: this engine merely skips
	if got, _ := e2eDecision(env(all), "DBSIM_E2E_MYSQL", "DBSIM_E2E_PG"); got != "skip" {
		t.Errorf("unconfigured engine next to a configured one: %s, want skip", got)
	}
}
