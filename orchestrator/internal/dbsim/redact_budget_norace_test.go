//go:build !race

package dbsim

import "time"

// redactBudget is how long redact may take on the adversarial inputs: about five times what a normal build needs, so a
// linear-time redactor passes and a superlinear one does not. Under -race the budget is wider (redact_budget_race_test.go).
const redactBudget = time.Second
