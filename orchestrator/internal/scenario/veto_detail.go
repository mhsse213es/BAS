package scenario

import "fmt"

// vetoDetail is the report line for a step Audspect's own destructive-action policy refused. The action is named
// only when the step carries one; an empty action is left out rather than printed as "action=".
func vetoDetail(actionKey, class, source string) string {
	where := fmt.Sprintf("class=%s, source=%s", class, source)
	if actionKey != "" {
		where = fmt.Sprintf("action=%s, %s", actionKey, where)
	}
	return fmt.Sprintf("VETOED — Audspect prevented execution under its local destructive-action policy (%s). Customer defensive controls were not tested by this step.", where)
}
